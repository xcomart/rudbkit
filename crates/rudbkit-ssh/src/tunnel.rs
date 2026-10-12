//! The tunnel driver.
//!
//! [`SshTunnel::open`] moves every blocking or `async` operation onto a
//! dedicated OS thread that owns its own Tokio runtime, so a GUI thread can hold
//! an [`SshTunnel`] and never block on it. All communication happens through
//! channels: a single command flows in, [`TunnelEvent`]s flow out.
//!
//! The connect path here is deliberately *not* the one an interactive client
//! uses. No session channel is opened, no pty is requested and no shell is
//! started: forwarding needs none of them, and bastion accounts are routinely
//! configured with `/usr/sbin/nologin` and nothing but `direct-tcpip` allowed.
//! Asking for a shell on such an account fails a tunnel that would otherwise
//! have worked.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use russh::client::{self, AuthResult, Handle};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{Disconnect, keys};
use tokio::net::{TcpListener, TcpStream};

use crate::config::{SshAuth, TunnelSpec};
use crate::event::{SshErrorKind, TunnelEvent};
use crate::forward::forward;
use crate::verify::{HostKeyVerifier, algorithm_name, fingerprint};

/// Host key has not been examined yet.
const KEY_UNCHECKED: u8 = 0;
/// Host key was accepted by the verifier.
const KEY_ACCEPTED: u8 = 1;
/// Host key was rejected by the verifier.
const KEY_REJECTED: u8 = 2;

/// How long the teardown handshake may take before the worker gives up and lets
/// the thread exit anyway.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How often a running tunnel checks that somebody is still reading its events
/// and that the transport is still up. Independent of the keepalive, which the
/// specification can disable.
const LIVENESS_INTERVAL: Duration = Duration::from_secs(5);

/// How many `accept` calls may fail back to back before the tunnel gives up.
///
/// A single failure is normal — a client that connects and vanishes before the
/// accept completes shows up as `ECONNABORTED`, and a process at its descriptor
/// limit as `EMFILE`. A listener that fails *every* time cannot recover, and
/// looping on it would spin a core, so the streak is capped.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 16;

/// A request sent from the owning thread to the tunnel worker.
#[derive(Debug)]
enum Command {
    /// Take the tunnel down.
    Close,
}

/// A live (or recently closed) SSH tunnel running on its own thread.
///
/// The handle is `Send` and `Sync` and every method is non-blocking. Dropping it
/// closes the tunnel and lets the worker thread wind down.
///
/// Sharing one tunnel between several database sessions is the *application's*
/// job: this type deliberately has no reference count and no `Clone`, so the
/// question of when the last user has gone is answered where the sessions are
/// known (architecture document, §9.3).
pub struct SshTunnel {
    /// Command channel to the worker thread.
    commands: UnboundedSender<Command>,
    /// The port that was actually bound, or `0` if binding failed.
    local_port: u16,
    /// `true` between [`TunnelEvent::Ready`] and the terminal event.
    alive: Arc<AtomicBool>,
}

impl SshTunnel {
    /// Binds the local port, starts connecting on a background thread, and
    /// returns immediately.
    ///
    /// The returned receiver yields every [`TunnelEvent`] the tunnel produces,
    /// in order, starting with [`TunnelEvent::Connecting`] and ending with
    /// either [`TunnelEvent::Disconnected`] or [`TunnelEvent::Error`]. Nothing
    /// here waits on the network, so this is safe to call from a GUI thread.
    ///
    /// The listening socket is bound on the *calling* thread, before the worker
    /// starts. Binding is a syscall rather than a wait, so it costs the caller
    /// nothing, and doing it here is what lets [`local_port`](Self::local_port)
    /// be answered the instant this returns — which is what a caller needs in
    /// order to substitute the port into a JDBC URL. A bind that fails leaves
    /// the port at `0` and puts a [`SshErrorKind::LocalBind`] error on the
    /// stream.
    ///
    /// Dropping the receiver closes the tunnel: a running tunnel notices within
    /// the liveness-check interval even when no traffic is flowing.
    pub fn open(
        spec: TunnelSpec,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> (SshTunnel, UnboundedReceiver<TunnelEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let alive = Arc::new(AtomicBool::new(false));

        let listener = match bind(&spec) {
            Ok(listener) => listener,
            Err(message) => {
                emit(
                    &event_tx,
                    TunnelEvent::Error(SshErrorKind::LocalBind, message),
                );
                // Dropping the sender ends the stream right after that error, so
                // a caller collecting the events sees a complete, terminated
                // sequence rather than hanging on a tunnel that never started.
                return (
                    SshTunnel {
                        commands: command_tx,
                        local_port: 0,
                        alive,
                    },
                    event_rx,
                );
            }
        };
        // Read back rather than echoed from the specification: with
        // `local_port: 0` the two differ, and the bound one is the only one that
        // is true.
        let local_port = match listener.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                emit(
                    &event_tx,
                    TunnelEvent::Error(
                        SshErrorKind::LocalBind,
                        format!("the local port could not be read back: {error}"),
                    ),
                );
                return (
                    SshTunnel {
                        commands: command_tx,
                        local_port: 0,
                        alive,
                    },
                    event_rx,
                );
            }
        };

        let tunnel = SshTunnel {
            commands: command_tx,
            local_port,
            alive: Arc::clone(&alive),
        };

        let thread_name = format!("rudbkit-ssh-{}-{}", spec.host, spec.port);
        let failure_tx = event_tx.clone();
        let spawned = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                worker(
                    spec, verifier, listener, local_port, event_tx, command_rx, &alive,
                );
            });

        if let Err(error) = spawned {
            emit(
                &failure_tx,
                TunnelEvent::Error(
                    SshErrorKind::Io,
                    format!("could not start the SSH tunnel worker thread: {error}"),
                ),
            );
        }

        (tunnel, event_rx)
    }

    /// The local port the tunnel is listening on, or `0` if binding failed.
    ///
    /// This is the port to substitute into a connection URL. When the
    /// specification asked for `0` — the default — it is whatever the OS chose,
    /// and it is already known when [`open`](Self::open) returns, well before
    /// [`TunnelEvent::Ready`] says anything may be sent through it.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Reports whether the tunnel is forwarding, i.e. whether
    /// [`TunnelEvent::Ready`] has been emitted and no terminal event has
    /// followed it.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Takes the tunnel down in an orderly fashion.
    ///
    /// Returns without waiting for the worker to finish; the final
    /// [`TunnelEvent::Disconnected`] still arrives on the event receiver, and
    /// the local port is closed before it does. Safe to call any number of
    /// times.
    pub fn close(&self) {
        let _ = self.commands.unbounded_send(Command::Close);
        self.commands.close_channel();
    }
}

impl fmt::Debug for SshTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshTunnel")
            .field("local_port", &self.local_port)
            .field("alive", &self.is_alive())
            .finish()
    }
}

impl Drop for SshTunnel {
    /// Signals the worker thread to stop. Closing the command channel also
    /// unblocks the worker if it is still connecting, so no thread outlives its
    /// tunnel.
    fn drop(&mut self) {
        self.close();
    }
}

/// Binds the listening socket described by `spec`.
///
/// Uses the blocking `std` listener because binding never waits; the worker
/// hands it to Tokio once its runtime exists. Returned errors are strings rather
/// than [`io::Error`] so the caller can put them straight on the event stream.
fn bind(spec: &TunnelSpec) -> Result<std::net::TcpListener, String> {
    let listener =
        std::net::TcpListener::bind((spec.bind_address, spec.local_port)).map_err(|error| {
            match spec.local_port {
                0 => format!(
                    "could not bind a local port on {}: {error}",
                    spec.bind_address
                ),
                port => format!(
                    "could not bind {}:{port}: {error} — leave `local_port` at 0 to let the \
                 operating system pick a free one",
                    spec.bind_address
                ),
            }
        })?;
    listener.set_nonblocking(true).map_err(|error| {
        format!("could not put the local listener in non-blocking mode: {error}")
    })?;
    Ok(listener)
}

/// A fatal problem raised while establishing the tunnel.
struct Failure {
    /// Classification handed to the UI.
    kind: SshErrorKind,
    /// Human-readable description; never contains credentials.
    message: String,
}

impl Failure {
    /// Builds a failure of the given kind.
    fn new(kind: SshErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// How the accept loop ended.
enum Ending {
    /// The tunnel finished; the payload explains why.
    Closed(String),
    /// The tunnel broke down.
    Failed(SshErrorKind, String),
}

/// Credentials resolved into the form russh wants, with any private key already
/// parsed and decrypted.
enum Credentials {
    /// A password to send verbatim.
    Password(String),
    /// A parsed private key.
    Key(Arc<PrivateKey>),
    /// Signing is delegated to the platform's SSH agent.
    Agent,
}

/// Bridges russh's transport callbacks to the verifier and the event stream.
pub(crate) struct ClientHandler {
    /// Policy consulted for the bastion's host key.
    verifier: Arc<dyn HostKeyVerifier>,
    /// Where [`TunnelEvent::HostKey`] is published.
    events: UnboundedSender<TunnelEvent>,
    /// Host being connected to, for the verifier's benefit.
    host: String,
    /// Port being connected to, for the verifier's benefit.
    port: u16,
    /// Records the verdict so a handshake error can be attributed correctly.
    key_state: Arc<AtomicU8>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let algorithm = algorithm_name(server_public_key);
        let fingerprint = fingerprint(server_public_key);
        let accepted = self
            .verifier
            .verify(&self.host, self.port, server_public_key)
            .await;

        self.key_state.store(
            if accepted { KEY_ACCEPTED } else { KEY_REJECTED },
            Ordering::SeqCst,
        );
        log::debug!(
            "host key for {}:{} ({algorithm} {fingerprint}) accepted={accepted}",
            self.host,
            self.port
        );
        emit(
            &self.events,
            TunnelEvent::HostKey {
                algorithm,
                fingerprint,
                accepted,
            },
        );
        Ok(accepted)
    }
}

/// Publishes an event, reporting whether anyone is still listening.
pub(crate) fn emit(events: &UnboundedSender<TunnelEvent>, event: TunnelEvent) -> bool {
    match events.unbounded_send(event) {
        Ok(()) => true,
        Err(_) => {
            log::debug!("tunnel event receiver is gone");
            false
        }
    }
}

/// Entry point of the worker thread: owns the runtime for one tunnel.
#[allow(clippy::too_many_arguments)]
fn worker(
    spec: TunnelSpec,
    verifier: Arc<dyn HostKeyVerifier>,
    listener: std::net::TcpListener,
    local_port: u16,
    events: UnboundedSender<TunnelEvent>,
    commands: UnboundedReceiver<Command>,
    alive: &AtomicBool,
) {
    // One thread per tunnel, single-threaded inside. Forwarding is pure I/O and
    // every byte of it is encrypted by russh's own session task, which is a
    // single task either way; extra worker threads would add context switches
    // without adding parallelism.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            emit(
                &events,
                TunnelEvent::Error(
                    SshErrorKind::Io,
                    format!("could not start the SSH tunnel runtime: {error}"),
                ),
            );
            return;
        }
    };

    runtime.block_on(run(
        spec, verifier, listener, local_port, &events, commands, alive,
    ));
    alive.store(false, Ordering::SeqCst);
    log::debug!("ssh tunnel worker thread finished");
}

/// Drives one tunnel from first connect to final event.
#[allow(clippy::too_many_arguments)]
async fn run(
    spec: TunnelSpec,
    verifier: Arc<dyn HostKeyVerifier>,
    listener: std::net::TcpListener,
    local_port: u16,
    events: &UnboundedSender<TunnelEvent>,
    mut commands: UnboundedReceiver<Command>,
    alive: &AtomicBool,
) {
    if !emit(events, TunnelEvent::Connecting) {
        return;
    }

    // Registering with the reactor has to happen on the runtime, which is why
    // the socket arrives here as a `std` one.
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            emit(
                events,
                TunnelEvent::Error(
                    SshErrorKind::Io,
                    format!("could not hand the local listener to the runtime: {error}"),
                ),
            );
            return;
        }
    };

    // Racing setup against the command channel keeps a dropped `SshTunnel` from
    // leaving this thread stuck in a long connect.
    let outcome = tokio::select! {
        result = connect(&spec, &verifier, events) => Some(result),
        () = wait_for_close(&mut commands) => None,
    };

    let handle = match outcome {
        None => {
            drop(listener);
            emit(
                events,
                TunnelEvent::Disconnected {
                    reason: "closed before the tunnel was ready".to_owned(),
                },
            );
            return;
        }
        Some(Err(failure)) => {
            drop(listener);
            log::warn!("ssh tunnel failed: {} ({})", failure.message, failure.kind);
            emit(events, TunnelEvent::Error(failure.kind, failure.message));
            return;
        }
        Some(Ok(handle)) => handle,
    };

    // Shared with every forwarding task: each opens its own channel on this one
    // transport, and `Handle`'s methods all take `&self`, so they never contend.
    let handle = Arc::new(handle);

    alive.store(true, Ordering::SeqCst);
    if !emit(events, TunnelEvent::Ready { local_port }) {
        alive.store(false, Ordering::SeqCst);
        drop(listener);
        shutdown(&handle).await;
        return;
    }

    // `accept_loop` consumes the listener, so the local port is closed by the
    // time it returns — which is before the terminal event below. A caller that
    // waits for `Disconnected` can therefore rebind the port immediately.
    let ending = accept_loop(&spec, &handle, listener, &mut commands, events).await;
    alive.store(false, Ordering::SeqCst);
    shutdown(&handle).await;

    match ending {
        Ending::Closed(reason) => {
            log::debug!("ssh tunnel closed: {reason}");
            emit(events, TunnelEvent::Disconnected { reason });
        }
        Ending::Failed(kind, message) => {
            log::warn!("ssh tunnel failed: {message} ({kind})");
            emit(events, TunnelEvent::Error(kind, message));
        }
    }
}

/// Resolves as soon as a close is requested or the command channel is dropped.
async fn wait_for_close(commands: &mut UnboundedReceiver<Command>) {
    match commands.next().await {
        Some(Command::Close) | None => (),
    }
}

/// Loads credentials, connects to the bastion and authenticates.
///
/// Stops there on purpose: a tunnel needs no session channel, no pty and no
/// shell, and asking for any of them would break on a bastion account whose
/// login shell is `nologin`.
async fn connect(
    spec: &TunnelSpec,
    verifier: &Arc<dyn HostKeyVerifier>,
    events: &UnboundedSender<TunnelEvent>,
) -> Result<Handle<ClientHandler>, Failure> {
    // Done first so a bad key path fails fast, before touching the network.
    let credentials = load_credentials(&spec.auth)?;

    let stream = tcp_connect(spec).await?;
    let key_state = Arc::new(AtomicU8::new(KEY_UNCHECKED));
    let handler = ClientHandler {
        verifier: Arc::clone(verifier),
        events: events.clone(),
        host: spec.host.clone(),
        port: spec.port,
        key_state: Arc::clone(&key_state),
    };

    let client_config = client::Config {
        // Keepalives are driven by the accept loop instead, so that russh and
        // this crate never both ping the bastion.
        inactivity_timeout: None,
        keepalive_interval: None,
        ..client::Config::default()
    };

    let mut handle = client::connect_stream(Arc::new(client_config), stream, handler)
        .await
        .map_err(|error| {
            if key_state.load(Ordering::SeqCst) == KEY_REJECTED {
                Failure::new(
                    SshErrorKind::HostKeyRejected,
                    format!(
                        "the host key presented by {}:{} was rejected",
                        spec.host, spec.port
                    ),
                )
            } else {
                Failure::new(
                    SshErrorKind::Connect,
                    format!("SSH handshake with {} failed: {error}", spec.host),
                )
            }
        })?;

    authenticate(&mut handle, spec, credentials).await?;
    Ok(handle)
}

/// Reads and decrypts the private key, or hands back the password unchanged.
fn load_credentials(auth: &SshAuth) -> Result<Credentials, Failure> {
    match auth {
        SshAuth::Password(password) => Ok(Credentials::Password(password.clone())),
        SshAuth::Agent => Ok(Credentials::Agent),
        SshAuth::PrivateKeyFile { path, passphrase } => {
            // russh's error messages describe the failure only, never the
            // passphrase, so they are safe to surface and to log.
            keys::load_secret_key(path, passphrase.as_deref())
                .map(|key| Credentials::Key(Arc::new(key)))
                .map_err(|error| {
                    Failure::new(
                        SshErrorKind::KeyLoad,
                        format!(
                            "could not load the private key at {}: {error}",
                            path.display()
                        ),
                    )
                })
        }
        SshAuth::PrivateKeyData { pem, passphrase } => {
            keys::decode_secret_key(pem, passphrase.as_deref())
                .map(|key| Credentials::Key(Arc::new(key)))
                .map_err(|error| {
                    Failure::new(
                        SshErrorKind::KeyLoad,
                        format!("could not decode the supplied private key: {error}"),
                    )
                })
        }
    }
}

/// Opens the TCP connection to the bastion, honouring the connect timeout.
async fn tcp_connect(spec: &TunnelSpec) -> Result<TcpStream, Failure> {
    let address = (spec.host.as_str(), spec.port);
    let attempt = TcpStream::connect(address);

    let connected = if spec.connect_timeout_secs == 0 {
        attempt.await.map_err(|error| {
            Failure::new(
                SshErrorKind::Connect,
                format!("could not connect to {}:{}: {error}", spec.host, spec.port),
            )
        })?
    } else {
        let limit = Duration::from_secs(spec.connect_timeout_secs);
        match tokio::time::timeout(limit, attempt).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return Err(Failure::new(
                    SshErrorKind::Connect,
                    format!("could not connect to {}:{}: {error}", spec.host, spec.port),
                ));
            }
            Err(_) => {
                return Err(Failure::new(
                    SshErrorKind::Connect,
                    format!(
                        "connecting to {}:{} timed out after {}s",
                        spec.host, spec.port, spec.connect_timeout_secs
                    ),
                ));
            }
        }
    };

    if let Err(error) = connected.set_nodelay(true) {
        log::debug!("could not disable Nagle's algorithm: {error}");
    }
    Ok(connected)
}

/// Runs exactly the one authentication method the specification asks for.
async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    spec: &TunnelSpec,
    credentials: Credentials,
) -> Result<(), Failure> {
    let result = match credentials {
        Credentials::Password(password) => {
            handle
                .authenticate_password(spec.username.as_str(), password)
                .await
        }
        Credentials::Key(key) => {
            let hash_alg = best_rsa_hash(handle).await?;
            handle
                .authenticate_publickey(
                    spec.username.as_str(),
                    PrivateKeyWithHashAlg::new(key, hash_alg),
                )
                .await
        }
        Credentials::Agent => return authenticate_with_agent(handle, spec).await,
    };

    match result {
        Ok(outcome) if outcome.success() => Ok(()),
        Ok(_) => Err(rejected(spec)),
        // A transport-level break during authentication is not a rejection, so
        // it must not be reported as one.
        Err(error) => Err(Failure::new(
            SshErrorKind::Io,
            format!("the connection broke during authentication: {error}"),
        )),
    }
}

/// The failure reported when the bastion turns our credentials down.
///
/// Names the user and nothing else — never the method's secret, and never the
/// secret's length or shape.
fn rejected(spec: &TunnelSpec) -> Failure {
    Failure::new(
        SshErrorKind::Auth,
        format!(
            "the bastion {} rejected the credentials for user {}",
            spec.host, spec.username
        ),
    )
}

/// Negotiates the signature hash to use for RSA keys, if any.
async fn best_rsa_hash(handle: &Handle<ClientHandler>) -> Result<Option<HashAlg>, Failure> {
    handle
        .best_supported_rsa_hash()
        .await
        .map(Option::flatten)
        .map_err(|error| {
            Failure::new(
                SshErrorKind::Io,
                format!("could not negotiate a signature algorithm: {error}"),
            )
        })
}

/// Offers every identity the platform's SSH agent holds, in the agent's order.
///
/// Unlike the other methods this one *is* a chain, because an agent is a set of
/// keys rather than a single credential and there is no way to know in advance
/// which one the bastion trusts. It is still one method: a run that exhausts the
/// agent reports an authentication failure, not a fallback to anything else.
async fn authenticate_with_agent(
    handle: &mut Handle<ClientHandler>,
    spec: &TunnelSpec,
) -> Result<(), Failure> {
    let mut agent = connect_agent().await?;
    let identities = agent.request_identities().await.map_err(|error| {
        Failure::new(
            SshErrorKind::KeyLoad,
            format!("the SSH agent would not list its identities: {error}"),
        )
    })?;
    if identities.is_empty() {
        return Err(Failure::new(
            SshErrorKind::KeyLoad,
            "the SSH agent holds no identities",
        ));
    }

    let rsa_hash = best_rsa_hash(handle).await?;
    let mut offered = 0usize;
    for identity in identities {
        let keys::agent::AgentIdentity::PublicKey { key, comment } = identity else {
            // OpenSSH certificates would need `authenticate_certificate_with`
            // and a CA the bastion trusts; skipping one is not a failure.
            log::debug!("skipping a certificate identity offered by the SSH agent");
            continue;
        };
        // A hash algorithm is only meaningful for RSA; offering one alongside an
        // ed25519 key would name a signature format that does not exist.
        let hash_alg = match key.algorithm() {
            Algorithm::Rsa { .. } => rsa_hash,
            _ => None,
        };
        log::debug!("offering agent identity {comment:?} to {}", spec.host);
        offered += 1;

        match handle
            .authenticate_publickey_with(spec.username.as_str(), key, hash_alg, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(()),
            Ok(AuthResult::Failure { .. }) => (),
            Err(error) => {
                return Err(Failure::new(
                    SshErrorKind::Io,
                    format!("the SSH agent could not sign for {}: {error}", spec.host),
                ));
            }
        }
    }

    if offered == 0 {
        return Err(Failure::new(
            SshErrorKind::KeyLoad,
            "the SSH agent offered only certificates, which are not supported",
        ));
    }
    Err(rejected(spec))
}

/// Connects to the platform's SSH agent.
#[cfg(unix)]
async fn connect_agent() -> Result<keys::agent::client::AgentClient<tokio::net::UnixStream>, Failure>
{
    keys::agent::client::AgentClient::connect_env()
        .await
        .map_err(|error| {
            Failure::new(
                SshErrorKind::KeyLoad,
                format!("could not reach the SSH agent on $SSH_AUTH_SOCK: {error}"),
            )
        })
}

/// Connects to the platform's SSH agent.
///
/// Windows has two: the pipe OpenSSH's `ssh-agent` service listens on, and
/// Pageant. OpenSSH is tried first because it is the one shipped with the OS.
#[cfg(windows)]
async fn connect_agent() -> Result<
    keys::agent::client::AgentClient<Box<dyn keys::agent::client::AgentStream + Send + Unpin>>,
    Failure,
> {
    const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

    match keys::agent::client::AgentClient::connect_named_pipe(OPENSSH_PIPE).await {
        Ok(agent) => return Ok(agent.dynamic()),
        Err(error) => log::debug!("no OpenSSH agent on {OPENSSH_PIPE}: {error}"),
    }
    keys::agent::client::AgentClient::connect_pageant()
        .await
        .map(keys::agent::client::AgentClient::dynamic)
        .map_err(|error| {
            Failure::new(
                SshErrorKind::KeyLoad,
                format!("could not reach an SSH agent (OpenSSH or Pageant): {error}"),
            )
        })
}

/// One iteration's worth of work picked up by the accept loop.
enum Step {
    /// A local client connected, or the listener refused to answer.
    Accepted(io::Result<(TcpStream, SocketAddr)>),
    /// A command arrived from the owning thread.
    Command(Option<Command>),
    /// The keepalive timer fired.
    Keepalive,
    /// The liveness timer fired.
    Liveness,
}

/// Accepts local connections and forwards each one until the tunnel ends.
///
/// Takes the listener by value so that returning from here closes the local
/// port, whatever the reason for returning was.
async fn accept_loop(
    spec: &TunnelSpec,
    handle: &Arc<Handle<ClientHandler>>,
    listener: TcpListener,
    commands: &mut UnboundedReceiver<Command>,
    events: &UnboundedSender<TunnelEvent>,
) -> Ending {
    let mut keepalive = keepalive_timer(spec.keepalive_secs);
    let mut liveness = repeating_timer(LIVENESS_INTERVAL);
    let mut connections = 0u64;
    let mut accept_errors = 0u32;

    loop {
        let step = tokio::select! {
            accepted = listener.accept() => Step::Accepted(accepted),
            command = commands.next() => Step::Command(command),
            () = tick(&mut keepalive) => Step::Keepalive,
            _ = liveness.tick() => Step::Liveness,
        };

        match step {
            Step::Accepted(Ok((socket, origin))) => {
                accept_errors = 0;
                connections += 1;
                if !emit(
                    events,
                    TunnelEvent::Accepted {
                        connection: connections,
                    },
                ) {
                    return Ending::Closed("nobody is reading the tunnel".to_owned());
                }

                // Every forwarded socket gets its own task and its own SSH
                // channel. That is what lets a connection pool hold several
                // sockets open at once, and it is why one of them being closed —
                // or refused by the bastion — cannot disturb the others: the
                // task owns the whole lifetime of exactly one channel.
                tokio::spawn(forward(
                    Arc::clone(handle),
                    spec.remote_host.clone(),
                    spec.remote_port,
                    socket,
                    origin,
                    connections,
                    events.clone(),
                ));
            }
            Step::Accepted(Err(error)) => {
                accept_errors += 1;
                log::warn!("could not accept a local connection: {error}");
                if accept_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return Ending::Failed(
                        SshErrorKind::Io,
                        format!(
                            "the local listener failed {accept_errors} times in a row: {error}"
                        ),
                    );
                }
            }
            Step::Command(Some(Command::Close)) => {
                return Ending::Closed("closed locally".to_owned());
            }
            Step::Command(None) => {
                return Ending::Closed("the tunnel handle was dropped".to_owned());
            }
            Step::Keepalive => {
                if handle.is_closed() {
                    return Ending::Failed(
                        SshErrorKind::Io,
                        "the connection to the bastion was lost".to_owned(),
                    );
                }
                if let Err(error) = handle.send_keepalive(true).await {
                    return Ending::Failed(
                        SshErrorKind::Io,
                        format!("the keepalive to the bastion failed: {error}"),
                    );
                }
            }
            Step::Liveness => {
                // The only way to notice a dropped receiver while the tunnel is
                // idle, and therefore the only thing that makes "dropping the
                // receiver closes the tunnel" true.
                if events.is_closed() {
                    return Ending::Closed("nobody is reading the tunnel".to_owned());
                }
                // A tunnel that dies under a live session is an error, never a
                // quiet reconnect: a transaction may have been open on it, and
                // the user has to be told (architecture document, §9.3).
                if handle.is_closed() {
                    return Ending::Failed(
                        SshErrorKind::Io,
                        "the connection to the bastion was lost".to_owned(),
                    );
                }
            }
        }
    }
}

/// Builds the keepalive timer, or `None` when keepalives are disabled.
fn keepalive_timer(keepalive_secs: u64) -> Option<tokio::time::Interval> {
    if keepalive_secs == 0 {
        return None;
    }
    Some(repeating_timer(Duration::from_secs(keepalive_secs)))
}

/// Builds a timer that fires every `period`.
///
/// The first tick is deliberately pushed out by one full period so that a tunnel
/// does nothing at all the instant it becomes ready, and ticks missed under load
/// are delayed rather than fired back to back.
fn repeating_timer(period: Duration) -> tokio::time::Interval {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// Waits for the next keepalive tick, or forever when there is no timer.
async fn tick(timer: &mut Option<tokio::time::Interval>) {
    match timer {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Closes the transport, giving up after [`SHUTDOWN_GRACE`] so an unresponsive
/// bastion cannot keep the worker thread alive.
///
/// Takes the handle by reference because the forwarding tasks share it; the last
/// reference goes away with the runtime a moment later, which is what actually
/// stops russh's own session task and every forwarding task still in flight.
async fn shutdown(handle: &Handle<ClientHandler>) {
    let teardown = handle.disconnect(Disconnect::ByApplication, "", "en-US");
    if tokio::time::timeout(SHUTDOWN_GRACE, teardown)
        .await
        .is_err()
    {
        log::debug!("timed out while closing the ssh tunnel");
    }
}
