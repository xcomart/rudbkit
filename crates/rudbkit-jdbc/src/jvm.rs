//! JVM bootstrap and the one JNI call this crate makes (architecture document,
//! §4.1 and §4.3).
//!
//! # One JVM per process
//!
//! JNI cannot create a second VM after the first, so [`Jvm::start`] is
//! idempotent: the first call builds the VM and every later call — including
//! from another thread — hands back the same one, configuration and all.
//!
//! **`DestroyJavaVM` is never called.** It is unreliable in the presence of
//! attached threads, it can block forever, and process exit does the same job
//! for free.
//!
//! # Why a dedicated thread creates it
//!
//! `JNI_CreateJavaVM` attributes special significance to the thread that calls
//! it and that thread has to stay alive, so the VM is created on a thread of
//! this crate's own that then parks forever. On macOS the alternative would be
//! the main thread, and gpui owns that one.
//!
//! # The options are not negotiable
//!
//! Everything in [`JvmConfig::options`] is fixed except the heap, the locale and
//! the caller's extra arguments. `-Xrs` in particular: without it the JVM
//! installs its own SIGINT/SIGTERM handlers and swallows Ctrl-C and the window
//! close, and the symptom — a window that will not close — points nowhere near
//! the JVM.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc;

use jni::objects::{JByteArray, JClass, JStaticMethodID};
use jni::refs::Global;
use jni::signature::ReturnType;
use jni::sys::{jint, jvalue};
use jni::{Env, InitArgsBuilder, JNIVersion, JavaVM, jni_sig, jni_str};
use parking_lot::Mutex;

use crate::error::{Error, Result};

/// Application names supplied to the shared runtime.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeIdentity {
    /// Application name, also used for the bootstrap thread.
    pub name: &'static str,
    /// JNI class with slash-separated packages.
    pub bridge_class: &'static str,
    /// Environment override for the runtime location.
    pub java_home_env: &'static str,
}

/// The process-wide VM, once started.
static JVM: OnceLock<Jvm> = OnceLock::new();

/// Serialises start-up so two threads racing into [`Jvm::start`] cannot both
/// try to create a VM. `OnceLock::get_or_init` cannot do this on its own
/// because building the VM is fallible and a failure must not poison the slot.
static STARTING: Mutex<()> = Mutex::new(());

/// How the JVM is started.
///
/// Only the first call to [`Jvm::start`] in a process uses one of these; see
/// that method.
#[derive(Clone, Debug)]
pub struct JvmConfig {
    identity: RuntimeIdentity,
    bridge_jar: PathBuf,
    java_home: Option<PathBuf>,
    heap_mb: u32,
    extra_args: Vec<String>,
    language: Option<String>,
    script: Option<String>,
    country: Option<String>,
}

impl JvmConfig {
    /// A configuration with the default heap and no extra arguments.
    pub fn new(bridge_jar: impl Into<PathBuf>, identity: RuntimeIdentity) -> Self {
        JvmConfig {
            identity,
            bridge_jar: bridge_jar.into(),
            java_home: None,
            heap_mb: 1024,
            extra_args: Vec::new(),
            language: None,
            script: None,
            country: None,
        }
    }

    /// Sets the Java locale from a BCP 47 language tag.
    ///
    /// Only the parts Java's start-up locale is built from are kept — language,
    /// script and region — and `_` is accepted in place of `-`, so
    /// `zh-Hans-CN`, `zh_TW`, `sr-Latn-RS` and `es-419` all come out right. A tag whose language subtag is malformed sets nothing, leaving
    /// the JVM on the OS locale rather than on a half-understood one. `None`
    /// leaves any earlier setting alone.
    pub fn with_locale(mut self, tag: Option<&str>) -> Self {
        if let Some(tag) = tag {
            let locale = parse_locale(tag);
            self.language = locale.language;
            self.script = locale.script;
            self.country = locale.region;
        }
        self
    }

    /// Overrides the Java runtime location, ahead of every other candidate.
    pub fn with_java_home(mut self, java_home: impl Into<PathBuf>) -> Self {
        self.java_home = Some(java_home.into());
        self
    }

    /// Sets the maximum heap in megabytes (`-Xmx`).
    pub fn with_heap_mb(mut self, heap_mb: u32) -> Self {
        self.heap_mb = heap_mb;
        self
    }

    /// Appends extra JVM arguments, after the ones this crate sets.
    pub fn with_extra_args(mut self, args: impl IntoIterator<Item = String>) -> Self {
        self.extra_args.extend(args);
        self
    }

    /// The bridge JAR this configuration will put on the class path.
    pub fn bridge_jar(&self) -> &Path {
        &self.bridge_jar
    }

    /// The full option list, in the order the JVM will see it.
    ///
    /// Public so that a start-up failure can be logged with the exact arguments
    /// that produced it.
    pub fn options(&self) -> Vec<String> {
        let mut options = vec![
            format!("-Djava.class.path={}", self.bridge_jar.display()),
            // Nothing here ever draws: a driver that reaches for AWT on a
            // headless box would fail with an unrelated-looking error.
            "-Djava.awt.headless=true".to_string(),
            // Keep the JVM's hands off SIGINT/SIGTERM (appendix A).
            "-Xrs".to_string(),
            // Some drivers — Oracle's above all — recurse deeply.
            "-Xss2m".to_string(),
            // A desktop tool's heap is small; parallel GC threads cost more
            // than they save.
            "-XX:+UseSerialGC".to_string(),
            format!("-Xmx{}m", self.heap_mb),
        ];
        // Matching the app locale is what makes a driver's error messages come
        // back in the language the rest of the window is in.
        if let Some(language) = &self.language {
            options.push(format!("-Duser.language={language}"));
        }
        // `user.script` has been read by `Locale`'s start-up default since
        // Java 7, and the runtime floor is 17.
        if let Some(script) = &self.script {
            options.push(format!("-Duser.script={script}"));
        }
        if let Some(country) = &self.country {
            options.push(format!("-Duser.country={country}"));
        }
        options.extend(self.extra_args.iter().cloned());
        options
    }

    /// Picks the Java runtime, in the order of architecture document §4.1.
    ///
    /// `None` means none of the candidates looked like a runtime, in which case
    /// start-up falls back on whatever `java` on `PATH` resolves to.
    fn resolve_java_home(&self) -> Option<PathBuf> {
        // An explicit setting wins: a caller that already resolved a runtime
        // (a test, or an installer) should not be second-guessed.
        let explicit = self.java_home.clone();
        explicit
            .into_iter()
            .chain(bundled_runtime())
            .chain(std::env::var_os(self.identity.java_home_env).map(PathBuf::from))
            .chain(std::env::var_os("JAVA_HOME").map(PathBuf::from))
            .find(|candidate| is_java_home(candidate))
    }
}

/// The parts of a language tag that Java's start-up locale is built from.
#[derive(Debug, Default, PartialEq, Eq)]
struct LocaleParts {
    /// ISO 639 language, lowercase (`user.language`).
    language: Option<String>,
    /// ISO 15924 script, title case (`user.script`).
    script: Option<String>,
    /// ISO 3166 alpha-2 region, uppercase, or a UN M.49 numeric region such
    /// as `419` (`user.country`).
    region: Option<String>,
}

/// Splits a BCP 47 tag — loosely: `_` separators, any casing, and a POSIX
/// `.codeset`/`@modifier` tail are tolerated — into language, script and
/// region.
///
/// The grammar is RFC 5646's `language [-extlang] [-script] [-region]`, read
/// left to right with each optional subtag recognised by its shape: a script is
/// four letters, a region two letters or three digits. Extended language
/// subtags, variants, extensions and private use are dropped — Java's
/// `user.variant` takes its own non-BCP 47 syntax, and none of them changes
/// which language a driver answers in. A first subtag that is not two to eight
/// letters (`x-private`, `i-klingon`, an empty string, digits) makes the whole
/// tag unusable and yields nothing at all.
fn parse_locale(tag: &str) -> LocaleParts {
    let tag = tag.split(['.', '@']).next().unwrap_or_default().trim();
    let mut subtags = tag.split(['-', '_']).peekable();
    let is_alpha = |part: &str, lengths: std::ops::RangeInclusive<usize>| {
        lengths.contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphabetic())
    };
    let Some(language) = subtags.next().filter(|part| is_alpha(part, 2..=8)) else {
        return LocaleParts::default();
    };
    // Up to three extlang subtags (`zh-yue`), only after a short language.
    if language.len() <= 3 {
        for _ in 0..3 {
            if subtags.next_if(|part| is_alpha(part, 3..=3)).is_none() {
                break;
            }
        }
    }
    let script = subtags.next_if(|part| is_alpha(part, 4..=4)).map(|part| {
        let mut script = part.to_ascii_lowercase();
        script[..1].make_ascii_uppercase();
        script
    });
    let region = subtags
        .next_if(|part| {
            is_alpha(part, 2..=2)
                || (part.len() == 3 && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .map(str::to_ascii_uppercase);
    LocaleParts {
        language: Some(language.to_ascii_lowercase()),
        script,
        region,
    }
}

/// The bundled runtime beside the executable, in the order of architecture
/// document §4.1: `<exe_dir>/runtime` — the flat archive Windows and Linux
/// ship — then `<exe_dir>/../runtime`, which on macOS is
/// `<bundle>/Contents/runtime`.
fn bundled_runtime() -> Vec<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| runtime_candidates(&exe))
        .unwrap_or_default()
}

/// The places a runtime bundled with the executable at `exe` could be.
fn runtime_candidates(exe: &Path) -> Option<Vec<PathBuf>> {
    let dir = exe.parent()?;
    let mut candidates = vec![dir.join("runtime")];
    if let Some(above) = dir.parent() {
        candidates.push(above.join("runtime"));
    }
    Some(candidates)
}

/// Whether a directory holds a JVM shared library where java-locator will look.
fn is_java_home(path: &Path) -> bool {
    jvm_library(path).is_some()
}

fn jvm_library(path: &Path) -> Option<PathBuf> {
    const LIBRARIES: [&str; 4] = [
        "lib/server/libjvm.so",
        "lib/server/libjvm.dylib",
        "lib/libjvm.dylib",
        "bin/server/jvm.dll",
    ];
    LIBRARIES
        .iter()
        .map(|library| path.join(library))
        .find(|library| library.is_file())
}

/// Resolves an app's bridge JAR from its override, bundle or build output.
pub fn default_bridge_jar(env: &str, jar_name: &str, fallback: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os(env) {
        return PathBuf::from(path);
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(path) = bridge_jar_candidates(&exe, jar_name)
            .into_iter()
            .find(|p| p.is_file())
    {
        return path;
    }
    fallback.to_path_buf()
}
fn bridge_jar_candidates(exe: &Path, jar_name: &str) -> Vec<PathBuf> {
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let mut candidates = vec![dir.join("lib").join(jar_name), dir.join(jar_name)];
    if let Some(above) = dir.parent() {
        candidates.push(above.join("lib").join(jar_name));
    }
    candidates
}

/// The running JVM and the one method handle this crate caches.
///
/// Cheap to pass around: [`Jvm::start`] hands out a `&'static Jvm`, since the
/// VM outlives everything anyway.
pub struct Jvm {
    vm: JavaVM,
    /// A global reference, not a local one: a method ID is only valid while its
    /// class stays loaded, and this reference is what keeps it loaded.
    bridge_class: Global<JClass<'static>>,
    /// `Bridge.call`. **The only cached method ID in the crate** — having a
    /// single entry point is precisely what makes that possible.
    call_method: JStaticMethodID,
}

impl std::fmt::Debug for Jvm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jvm").finish_non_exhaustive()
    }
}

impl Jvm {
    /// Starts the process-wide JVM, or returns the one already running.
    ///
    /// **The configuration only applies to the first call.** JNI allows exactly
    /// one VM per process and offers no way to reconfigure it, so a later call
    /// with a different [`JvmConfig`] returns the running VM and ignores the
    /// difference. Callers that need different options must change them and
    /// restart the process, which is what the settings dialog tells the user.
    pub fn start(config: &JvmConfig) -> Result<&'static Jvm> {
        if let Some(jvm) = JVM.get() {
            return Ok(jvm);
        }
        let _guard = STARTING.lock();
        // Someone may have won the race between the check above and the lock.
        if let Some(jvm) = JVM.get() {
            return Ok(jvm);
        }
        let jvm = boot(config)?;
        Ok(JVM.get_or_init(|| jvm))
    }

    /// The running JVM, if one has been started.
    pub fn get() -> Option<&'static Jvm> {
        JVM.get()
    }

    /// The underlying VM handle, for attaching threads.
    pub fn vm(&self) -> &JavaVM {
        &self.vm
    }

    /// Invokes `Bridge.call` on a thread that is already attached.
    ///
    /// Returns the raw response envelope; see
    /// the application protocol decoder.
    ///
    /// The bridge catches every `Throwable` and answers with an ERROR envelope,
    /// so an exception crossing this boundary is either a bridge bug or a fatal
    /// case the bridge cannot catch (an `OutOfMemoryError` while building the
    /// response, say). Such an exception is **caught and cleared here** and comes
    /// back as [`Error::Jni`] naming its class and message. Left pending, it
    /// would make every later JNI call on this thread — which, for a session
    /// worker, is every later call of the session — fail with nothing more than
    /// "Java exception was thrown".
    pub fn call_attached(
        &self,
        env: &mut Env<'_>,
        op: i32,
        handle: i64,
        arg: i64,
        request: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // A frame per call: the worker thread stays attached for the life of
        // the session, and without this the request and response arrays would
        // pile up in the attachment's frame until the session closed.
        env.with_local_frame(4, |env| {
            let result = self.call_in_frame(env, op, handle, arg, request);
            // Checked on success too: it costs nothing, and a call that reports
            // success over a pending exception must not hand it on either.
            if env.exception_check() {
                return Err(take_exception(env));
            }
            result
        })
    }

    /// The body of [`call_attached`](Self::call_attached), inside its frame.
    fn call_in_frame(
        &self,
        env: &mut Env<'_>,
        op: i32,
        handle: i64,
        arg: i64,
        request: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let request = match request {
            Some(bytes) => env.byte_array_from_slice(bytes)?,
            None => JByteArray::null(),
        };

        // `jvalue` is a raw union; writing one is safe, reading it is what
        // the JNI call below does under the `unsafe`.
        let args = [
            jvalue { i: op as jint },
            jvalue { j: handle },
            jvalue { j: arg },
            jvalue {
                l: request.as_raw(),
            },
        ];

        // SAFETY: `call_method` was looked up on `bridge_class` with the
        // signature `(IJJ[B)[B`, and the four arguments above are int,
        // long, long and a byte array in that order.
        let returned = unsafe {
            env.call_static_method_unchecked(
                &self.bridge_class,
                self.call_method,
                ReturnType::Array,
                &args,
            )?
        };

        let object = returned.l()?;
        if object.is_null() {
            return Err(Error::Protocol(
                "Bridge.call returned null, which it documents it never does".into(),
            ));
        }
        // SAFETY: the method's return type is `[B`, and `into_raw` gives up
        // the only owning wrapper for that reference.
        let array = unsafe { JByteArray::from_raw(env, object.into_raw()) };
        Ok(env.convert_byte_array(&array)?)
    }

    /// Invokes `Bridge.call` from a thread that may not be attached, attaching
    /// and detaching around it.
    ///
    /// Only `CANCEL` takes this path. It has to run while the session worker is
    /// blocked inside the very statement it is cancelling, so it cannot be
    /// queued behind it, and it is rare enough that the cost of an attach does
    /// not matter (architecture document, §4.2).
    pub fn call_detached(
        &self,
        op: i32,
        handle: i64,
        arg: i64,
        request: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.vm.attach_current_thread_for_scope(|env| {
            self.call_attached(env, op, handle, arg, request)
        })
    }
}

/// Catches and clears the pending Java exception, describing it as an error.
///
/// Called only when `ExceptionCheck` says one is pending. The clear is repeated
/// unconditionally at the end because `exception_catch` can fail before it gets
/// as far as clearing — when the frame it needs cannot be pushed, say — and the
/// whole point is that the thread leaves here with nothing pending.
fn take_exception(env: &Env<'_>) -> Error {
    let error = match env.exception_catch() {
        Err(jni::errors::Error::CaughtJavaException { name, msg, .. }) => {
            Error::Jni(describe_exception(&name, &msg))
        }
        Err(other) => Error::Jni(format!("a Java exception was thrown: {other}")),
        Ok(()) => Error::Jni("a Java exception was thrown and vanished before it was read".into()),
    };
    env.exception_clear();
    error
}

/// Renders a caught exception the way `Throwable.toString` does: the class,
/// then the message when there is one.
///
/// `jni-rs` renders a null message as `<NULL>`, and many exceptions have
/// none (`NullPointerException` without helpful messages, a bare
/// `StackOverflowError`), so that placeholder is dropped rather than shown.
fn describe_exception(class: &str, message: &str) -> String {
    match message.trim() {
        "" | "<NULL>" => class.to_string(),
        message => format!("{class}: {message}"),
    }
}

/// Creates the VM on a thread of our own and waits for the result.
fn boot(config: &JvmConfig) -> Result<Jvm> {
    if !config.bridge_jar.is_file() {
        return Err(Error::JvmStart(format!(
            "the bridge JAR is missing: {} (build it with `cd bridge && ./gradlew jar`)",
            config.bridge_jar.display()
        )));
    }

    let options = config.options();
    let java_home = config.resolve_java_home();
    let jar = config.bridge_jar.clone();
    let identity = config.identity;
    log::debug!(
        "starting the JVM with JAVA_HOME={:?} and options {:?}",
        java_home,
        options
    );

    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name(format!("{}-jvm", identity.name))
        .spawn(move || {
            let result = create(options, java_home, &jar, identity);
            let started = result.is_ok();
            if tx.send(result).is_err() {
                return;
            }
            // The creating thread is special to the JVM and has to outlive it,
            // and the JVM outlives everything. Parking costs one idle thread.
            if started {
                loop {
                    std::thread::park();
                }
            }
        })
        .map_err(|source| Error::JvmStart(format!("cannot spawn the JVM thread: {source}")))?;

    rx.recv()
        .map_err(|_| Error::JvmStart("the JVM bootstrap thread died silently".into()))?
}

/// Runs on the bootstrap thread: loads the selected runtime, creates the VM, resolves
/// `Bridge.call`.
fn create(
    options: Vec<String>,
    java_home: Option<PathBuf>,
    jar: &Path,
    identity: RuntimeIdentity,
) -> Result<Jvm> {
    let mut builder = InitArgsBuilder::new().version(JNIVersion::V1_8);
    for option in options {
        builder = builder.option(option);
    }
    let args = builder
        .build()
        .map_err(|source| Error::JvmStart(format!("invalid JVM options: {source}")))?;

    // Resolve the selected library without changing process-global JAVA_HOME.
    let library = java_home.as_ref().and_then(|home| jvm_library(home));
    #[cfg(windows)]
    if let (Some(home), Some(_)) = (&java_home, &library) {
        add_runtime_bin_to_dll_search(&home.join("bin"));
    }
    let vm = match library {
        Some(path) => JavaVM::with_libjvm(args, || Ok(path)),
        None => JavaVM::new(args),
    }
    .map_err(|source| {
        Error::JvmStart(format!(
            "{source} (set {} to point at a Java 17 runtime; JAVA_HOME={})",
            identity.java_home_env,
            java_home
                .as_deref()
                .map(|home| home.display().to_string())
                .unwrap_or_else(|| "<unset>".to_string()),
        ))
    })?;

    let bridge_name = identity.bridge_class;
    vm.attach_current_thread(|env| {
        let class = env
            .find_class(jni::strings::JNIString::new(bridge_name))
            .map_err(|source| {
                Error::JvmStart(format!(
                    "the bridge class {bridge_name} is not in {}: {source}",
                    jar.display()
                ))
            })?;
        let bridge_class = env.new_global_ref(class)?;
        let call_method = env
            .get_static_method_id(&bridge_class, jni_str!("call"), jni_sig!("(IJJ[B)[B"))
            .map_err(|source| {
                Error::JvmStart(format!(
                    "{bridge_name}.call(int,long,long,byte[]): {source}"
                ))
            })?;
        Ok(Jvm {
            vm: vm.clone(),
            bridge_class,
            call_method,
        })
    })
}

/// Puts the runtime's `bin` directory on the DLL search path, which `java.exe`
/// gets for free by living in it.
///
/// The JDK loads some of its own DLLs by bare name. The one that bites is
/// `zip.dll`: jimage.dll fetches its inflater with `LoadLibrary("zip.dll")` to
/// read the classes of a `--compress=2` jlink image, which is what the apps
/// bundle. From an executable outside `bin` that lookup fails, jimage keeps a
/// null inflater and calls it anyway, and the VM dies with an access violation
/// at pc 0 while loading its first classes, taking the process with it before
/// any error can be reported. The same search also finds the MSVC runtime the
/// JDK ships in `bin` for `jvm.dll`'s own imports. jpackage's Windows launcher
/// does the same.
///
/// Process-wide and never undone: the VM lives as long as the process does.
#[cfg(windows)]
fn add_runtime_bin_to_dll_search(bin: &Path) {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetDllDirectoryW(path: *const u16) -> i32;
    }

    let wide: Vec<u16> = bin.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call,
    // and the function copies it.
    if unsafe { SetDllDirectoryW(wide.as_ptr()) } == 0 {
        log::warn!(
            "cannot add {} to the DLL search path: {}",
            bin.display(),
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: RuntimeIdentity = RuntimeIdentity {
        name: "test",
        bridge_class: "test/Bridge",
        java_home_env: "RUDBKIT_TEST_JAVA_HOME",
    };
    #[test]
    fn runtime_options_preserve_locale_and_override_order() {
        let options = JvmConfig::new("bridge.jar", ID)
            .with_heap_mb(512)
            .with_locale(Some("zh-CN"))
            .with_extra_args(["-Xmx768m".into()])
            .options();
        for option in [
            "-Xrs",
            "-Duser.language=zh",
            "-Duser.country=CN",
            "-Xmx512m",
        ] {
            assert!(options.contains(&option.into()));
        }
        assert_eq!(options.last().unwrap(), "-Xmx768m");
    }
    #[test]
    fn language_tags_map_onto_java_locale_properties() {
        let parts = |tag| {
            let locale = parse_locale(tag);
            (locale.language, locale.script, locale.region)
        };
        let some = |value: &str| Some(value.to_string());
        assert_eq!(parts("zh-Hans-CN"), (some("zh"), some("Hans"), some("CN")));
        assert_eq!(parts("zh_TW"), (some("zh"), None, some("TW")));
        assert_eq!(parts("sr-Latn-RS"), (some("sr"), some("Latn"), some("RS")));
        assert_eq!(parts("en"), (some("en"), None, None));
        assert_eq!(parts("pt-BR"), (some("pt"), None, some("BR")));
        assert_eq!(parts("es-419"), (some("es"), None, some("419")));
        // Odd casing, POSIX tails, extlang, variants and extensions.
        assert_eq!(parts("ZH_hant_tw"), (some("zh"), some("Hant"), some("TW")));
        assert_eq!(parts("de_DE.UTF-8"), (some("de"), None, some("DE")));
        assert_eq!(parts("zh-yue-HK"), (some("zh"), None, some("HK")));
        assert_eq!(
            parts("de-CH-1901-u-co-phonebk"),
            (some("de"), None, some("CH"))
        );
        assert_eq!(parts("en-u-ca-gregory"), (some("en"), None, None));
        // Garbage sets nothing.
        for tag in ["", "-", "x-private", "1234", "e", "en!", "toolonglanguage"] {
            assert_eq!(parse_locale(tag), LocaleParts::default(), "{tag:?}");
        }
        // A region must be two letters or three digits; anything else is not
        // promoted to one.
        assert_eq!(parts("en-12"), (some("en"), None, None));
        assert_eq!(parts("en-USA"), (some("en"), None, None));
    }
    #[test]
    fn locale_options_carry_script_and_skip_garbage() {
        let options = JvmConfig::new("bridge.jar", ID)
            .with_locale(Some("zh-Hans-CN"))
            .options();
        for option in [
            "-Duser.language=zh",
            "-Duser.script=Hans",
            "-Duser.country=CN",
        ] {
            assert!(options.contains(&option.into()), "{option}");
        }
        assert!(!options.iter().any(|option| option == "-Duser.country=HANS"));
        let options = JvmConfig::new("bridge.jar", ID)
            .with_locale(Some("zh-CN"))
            .with_locale(Some("garbage!"))
            .options();
        assert!(!options.iter().any(|option| option.starts_with("-Duser.")));
    }
    #[test]
    fn a_caught_exception_names_its_class_and_message() {
        assert_eq!(
            describe_exception("java.lang.OutOfMemoryError", "Java heap space"),
            "java.lang.OutOfMemoryError: Java heap space"
        );
        // No message: the class alone, never jni-rs's `<NULL>` placeholder.
        assert_eq!(
            describe_exception("java.lang.StackOverflowError", "<NULL>"),
            "java.lang.StackOverflowError"
        );
        assert_eq!(
            describe_exception("java.lang.NullPointerException", ""),
            "java.lang.NullPointerException"
        );
        assert_eq!(
            Error::Jni(describe_exception(
                "java.lang.IllegalStateException",
                "boom"
            ))
            .to_string(),
            "JNI call failed: java.lang.IllegalStateException: boom"
        );
    }
    #[test]
    fn runtime_and_bridge_candidates_follow_bundle_layouts() {
        let exe = Path::new("/opt/app/bin/app");
        assert_eq!(
            runtime_candidates(exe).unwrap(),
            [
                PathBuf::from("/opt/app/bin/runtime"),
                PathBuf::from("/opt/app/runtime")
            ]
        );
        assert_eq!(
            bridge_jar_candidates(exe, "bridge.jar"),
            [
                PathBuf::from("/opt/app/bin/lib/bridge.jar"),
                PathBuf::from("/opt/app/bin/bridge.jar"),
                PathBuf::from("/opt/app/lib/bridge.jar")
            ]
        );
        assert!(!is_java_home(Path::new("/definitely/missing/runtime")));
    }
    #[cfg(windows)]
    #[test]
    fn the_runtime_bin_joins_the_dll_search_path() {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetDllDirectoryW(length: u32, buffer: *mut u16) -> u32;
            fn SetDllDirectoryW(path: *const u16) -> i32;
        }
        let bin = Path::new(r"C:\rudbkit-test\runtime\bin");
        add_runtime_bin_to_dll_search(bin);
        let mut buffer = [0u16; 260];
        // SAFETY: the length passed is the buffer's own.
        let length = unsafe { GetDllDirectoryW(buffer.len() as u32, buffer.as_mut_ptr()) };
        // SAFETY: null restores the default search order.
        unsafe { SetDllDirectoryW(std::ptr::null()) };
        assert_eq!(
            String::from_utf16_lossy(&buffer[..length as usize]),
            r"C:\rudbkit-test\runtime\bin"
        );
    }
}
