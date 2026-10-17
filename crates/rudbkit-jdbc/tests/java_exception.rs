//! A Java exception crossing the JNI boundary, against a real JVM.
//!
//! The bridge catches every `Throwable` and answers with an ERROR envelope, so
//! the only way to get an exception through [`Jvm::call_attached`] is a bridge
//! that does not. This test compiles one — `ThrowingBridge`, with the same
//! `call(int, long, long, byte[])` entry point — into a JAR with the local JDK,
//! starts the VM on it, and checks that a thrown exception comes back named and
//! *cleared*: before that was done, it stayed pending, and every later call on
//! the same attached thread failed with a bare "Java exception was thrown".
//!
//! Needs `javac` and `jar` from a JDK 17 or later. Without one the test says so
//! on stderr and passes, since this repository cannot provide a JDK; point
//! `RUDBKIT_TEST_JAVA_HOME` or `JAVA_HOME` at one to make sure it runs.
//!
//! One test function only: JNI allows one VM per process, and this binary is
//! that process.

use std::path::{Path, PathBuf};
use std::process::Command;

use rudbkit_jdbc::{Error, Jvm, JvmConfig, RuntimeIdentity};

const IDENTITY: RuntimeIdentity = RuntimeIdentity {
    name: "rudbkit-jdbc-test",
    bridge_class: "ThrowingBridge",
    java_home_env: "RUDBKIT_TEST_JAVA_HOME",
};

/// `op` 1 throws with a message, 2 throws without one, anything else echoes
/// the request (or answers `[42]` when there is none).
const BRIDGE_SOURCE: &str = r#"
public final class ThrowingBridge {
    private ThrowingBridge() {}

    public static byte[] call(int op, long handle, long arg, byte[] request) {
        if (op == 1) {
            throw new IllegalStateException("bridge exploded");
        }
        if (op == 2) {
            throw new NullPointerException();
        }
        return request == null ? new byte[] {42} : request;
    }
}
"#;

/// The JDK to build and run with, if one can be found.
fn java_home() -> Option<PathBuf> {
    let from_env = ["RUDBKIT_TEST_JAVA_HOME", "JAVA_HOME"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from);
    // Otherwise the JDK `javac` on `PATH` belongs to: `<home>/bin/javac`.
    let from_path = Command::new("which")
        .arg("javac")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let path = String::from_utf8(output.stdout).ok()?;
            let javac = std::fs::canonicalize(path.trim()).ok()?;
            Some(javac.parent()?.parent()?.to_path_buf())
        });
    from_env
        .chain(from_path)
        .find(|home| home.join("bin/javac").is_file() && home.join("bin/jar").is_file())
}

/// Compiles [`BRIDGE_SOURCE`] into a JAR under `dir` and returns its path.
fn build_bridge(home: &Path, dir: &Path) -> PathBuf {
    let classes = dir.join("classes");
    std::fs::create_dir_all(&classes).expect("creating the class directory");
    let source = dir.join("ThrowingBridge.java");
    std::fs::write(&source, BRIDGE_SOURCE).expect("writing the bridge source");

    let status = Command::new(home.join("bin/javac"))
        .args(["--release", "17", "-d"])
        .arg(&classes)
        .arg(&source)
        .status()
        .expect("running javac");
    assert!(status.success(), "javac failed");

    let jar = dir.join("throwing-bridge.jar");
    let status = Command::new(home.join("bin/jar"))
        .arg("--create")
        .arg("--file")
        .arg(&jar)
        .arg("-C")
        .arg(&classes)
        .arg(".")
        .status()
        .expect("running jar");
    assert!(status.success(), "jar failed");
    jar
}

/// The message of an [`Error::Jni`], failing the test on anything else.
fn jni_message(result: rudbkit_jdbc::Result<Vec<u8>>) -> String {
    match result {
        Err(Error::Jni(message)) => message,
        other => panic!("expected a JNI error, got {other:?}"),
    }
}

#[test]
fn a_java_exception_is_named_and_cleared_so_the_thread_keeps_working() {
    let Some(home) = java_home() else {
        eprintln!(
            "skipped: no JDK with javac and jar found (set RUDBKIT_TEST_JAVA_HOME or JAVA_HOME)"
        );
        return;
    };
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("java-exception");
    let jar = build_bridge(&home, &dir);
    let config = JvmConfig::new(&jar, IDENTITY).with_java_home(&home);
    let jvm = Jvm::start(&config).expect("the JVM starts");

    jvm.vm()
        .attach_current_thread(|env| -> rudbkit_jdbc::Result<()> {
            assert_eq!(jvm.call_attached(env, 0, 0, 0, Some(b"ping"))?, b"ping");

            let message = jni_message(jvm.call_attached(env, 1, 0, 0, None));
            assert!(
                message.contains("java.lang.IllegalStateException: bridge exploded"),
                "the error must name the exception and its message: {message}"
            );
            assert!(!env.exception_check(), "the exception is still pending");

            // The regression: with the exception left pending, this call — and
            // every one after it on this thread — failed at its first JNI step.
            assert_eq!(jvm.call_attached(env, 0, 0, 0, Some(b"again"))?, b"again");

            // An exception without a message is named by its class alone.
            assert_eq!(
                jni_message(jvm.call_attached(env, 2, 0, 0, None)),
                "java.lang.NullPointerException"
            );
            assert_eq!(jvm.call_attached(env, 0, 0, 0, None)?, [42]);
            Ok(())
        })
        .expect("the attached calls succeed");

    // The detaching path goes through the same frame, so it clears too.
    std::thread::spawn(move || {
        let message = jni_message(jvm.call_detached(1, 0, 0, None));
        assert!(message.contains("IllegalStateException"), "{message}");
        assert_eq!(
            jvm.call_detached(0, 0, 0, Some(b"detached"))
                .expect("a detached call after an exception succeeds"),
            b"detached"
        );
    })
    .join()
    .expect("the detached thread did not panic");
}
