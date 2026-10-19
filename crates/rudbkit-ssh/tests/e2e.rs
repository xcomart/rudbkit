//! End-to-end tests for the tunnel.
//!
//! Unlike `tunnel.rs`, which only exercises paths that fail before a handshake
//! can happen, every test here stands up a real SSH server *inside the test
//! process* using russh's server side, plus a plain TCP echo server standing in
//! for the database, and drives the production [`SshTunnel`] between the two.
//! That makes the success path — authentication, `direct-tcpip`, the accept
//! loop, channel multiplexing and teardown — observable for the first time.
//!
//! Design notes:
//!
//! * Each test owns its own [`Bastion`]: a fresh ephemeral port for the SSH
//!   server, a fresh ephemeral port for the echo server, and a fresh Tokio
//!   runtime. Nothing is shared between tests, so the default parallel
//!   `cargo test` run is safe.
//! * The host key is a checked-in throwaway rather than a generated one, which
//!   keeps a random number generator out of the dependency tree. It is a test
//!   fixture and guards nothing.
//! * Nothing here sleeps to synchronise. Progress is observed by waiting for
//!   events, and every wait is bounded by [`EVENT_TIMEOUT`]; on expiry the panic
//!   message lists every event seen so far.
//! * The tunnel runs on its own thread with its own runtime (see
//!   [`SshTunnel::open`]), so the test thread only ever blocks on the *server's*
//!   runtime. The two never nest.
//!
//! # The test against a real server
//!
//! [`a_real_bastion_forwards_a_real_port`] is `#[ignore]`d because it needs an
//! sshd this repository cannot provide, and credentials it must not contain.
//! Point it at one and run it explicitly:
//!
//! ```text
//! export RUDBKIT_SSH_TEST_HOST=bastion.example.com   # required
//! export RUDBKIT_SSH_TEST_PORT=22                    # optional, defaults to 22
//! export RUDBKIT_SSH_TEST_USER=ops                   # optional, defaults to $USER
//! export RUDBKIT_SSH_TEST_PASSWORD=...               # one of these two; without
//! export RUDBKIT_SSH_TEST_KEY=~/.ssh/id_ed25519      # either, the agent is used
//! export RUDBKIT_SSH_TEST_KEY_PASSPHRASE=...         # optional, for an encrypted key
//! export RUDBKIT_SSH_TEST_REMOTE_HOST=db.internal    # optional, defaults to 127.0.0.1
//! export RUDBKIT_SSH_TEST_REMOTE_PORT=22             # optional, defaults to 22
//!
//! cargo test -p rudbkit-ssh --test e2e -- --ignored --nocapture
//! ```
//!
//! The default target is the bastion's own SSH port, because that is the one
//! service a bastion is guaranteed to be running: the test asserts that the
//! forwarded port answers with an `SSH-2.0` banner. Set the remote host and port
//! to point it at a database instead.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use rudbkit_ssh::{
    AcceptAllVerifier, RejectAllVerifier, SshAuth, SshErrorKind, SshTunnel, TunnelEvent, TunnelSpec,
};
use russh::server::{Auth, ChannelOpenHandle, Handler as ServerHandler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener as AsyncListener, TcpStream as AsyncStream};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

/// Upper bound on any single wait for an expected event.
///
/// Generous enough to survive a loaded CI machine, small enough that a genuine
/// hang fails the run instead of wedging it.
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a blocking read or write made through the forwarded port.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// The only account the in-process bastion accepts.
const TEST_USER: &str = "ops";

/// The only password the in-process bastion accepts.
///
/// Also the canary for the masking tests: it must never appear in an event, a
/// message or a `Debug` rendering.
const TEST_PASSWORD: &str = "hunter2";

/// Host key of the in-process bastion.
///
/// A throwaway generated once with `ssh-keygen -t ed25519`, checked in so that
/// the tests need no random number generator. It protects nothing.
const HOST_KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzUnaPNkCU1v9bqZdayLHMnhlQTsXGrhyB8ZwUpkjaOwAAAKC3iCkJt4gp\n\
CQAAAAtzc2gtZWQyNTUxOQAAACCzUnaPNkCU1v9bqZdayLHMnhlQTsXGrhyB8ZwUpkjaOw\n\
AAAEB3+1F9nbg00InkS4YZ41xdxygI3NYNg1+WF2r5xHUZ87NSdo82QJTW/1upl1rIscye\n\
GVBOxcauHIHxnBSmSNo7AAAAGXJ1ZGJtYW4tc3NoIHRlc3QgaG9zdCBrZXkBAgME\n\
-----END OPENSSH PRIVATE KEY-----\n";

// ---------------------------------------------------------------------------
// Test bastion
// ---------------------------------------------------------------------------

/// What the bastion does with a `direct-tcpip` request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Forwarding {
    /// Connect onwards for real and pump bytes both ways.
    Allow,
    /// Answer `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`, the way an sshd with
    /// `AllowTcpForwarding no` does.
    Prohibited,
    /// Answer `SSH_OPEN_CONNECT_FAILED`, the way a bastion that cannot reach the
    /// target does.
    ConnectFailed,
}

/// Everything one bastion records or needs while serving a connection.
struct ServerState {
    /// Forwarding policy this bastion enforces.
    forwarding: Forwarding,
    /// Number of `direct-tcpip` requests seen.
    forwards: AtomicUsize,
    /// Number of `session` channels seen. A tunnel must never open one.
    sessions: AtomicUsize,
    /// Number of `pty-req` requests seen. A tunnel must never send one.
    ptys: AtomicUsize,
    /// Number of `shell` requests seen. A tunnel must never send one.
    shells: AtomicUsize,
    /// Number of password authentications that were rejected.
    rejections: AtomicUsize,
}

/// One connection's server-side handler.
struct TestHandler {
    /// Shared recording/policy state of the owning [`Bastion`].
    state: Arc<ServerState>,
}

impl ServerHandler for TestHandler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == TEST_USER && password == TEST_PASSWORD {
            return Ok(Auth::Accept);
        }
        self.state.rejections.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Counted, not refused: the assertion that a tunnel never opens one has
        // to be able to tell "did not ask" from "asked and was turned down".
        self.state.sessions.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.ptys.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.shells.fetch_add(1, Ordering::SeqCst);
        session.channel_success(channel)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.state.forwards.fetch_add(1, Ordering::SeqCst);

        match self.state.forwarding {
            Forwarding::Prohibited => {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
            Forwarding::ConnectFailed => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
            Forwarding::Allow => (),
        }

        let target = match AsyncStream::connect((host_to_connect, port_to_connect as u16)).await {
            Ok(target) => target,
            Err(_) => {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;

        // One task per forwarded channel on this side too, so that the server
        // cannot be the reason two connections interfere.
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            let mut target = target;
            let _ = tokio::io::copy_bidirectional(&mut channel, &mut target).await;
        });
        Ok(())
    }
}

/// An SSH server and an echo server running inside the test process, plus the
/// runtimes driving them.
struct Bastion {
    /// Runtime the listeners and the sessions run on.
    ///
    /// Owned rather than shared, and taken away by [`Bastion::kill`], because
    /// killing a bastion convincingly means dropping the runtime: russh owns the
    /// accepted socket inside a task of its own, so aborting the task this test
    /// spawned would leave the connection up.
    servers: Mutex<Option<Runtime>>,
    /// Runtime the tests' bounded waits use. Separate from `servers` so that a
    /// killed bastion still leaves the test able to wait for events.
    clock: Arc<Runtime>,
    /// Accept loops and session tasks, aborted on drop or by
    /// [`Bastion::kill`].
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Ephemeral port the SSH listener got.
    port: u16,
    /// Ephemeral port the echo server got. Stands in for the database.
    echo_port: u16,
    /// Recording/policy state shared with every connection handler.
    state: Arc<ServerState>,
}

impl Bastion {
    /// Starts a bastion with the given forwarding policy.
    fn start(forwarding: Forwarding) -> Self {
        let host_key =
            russh::keys::decode_secret_key(HOST_KEY_PEM, None).expect("the test host key parses");

        let config = russh::server::Config {
            // Rejections are not rate-limited here: the tests assert on the
            // rejection itself, and a constant-time delay would only make the
            // suite slower.
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            inactivity_timeout: Some(Duration::from_secs(60)),
            nodelay: true,
            ..russh::server::Config::default()
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("building the server runtime must succeed");
        let clock = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("building the test runtime must succeed"),
        );

        let state = Arc::new(ServerState {
            forwarding,
            forwards: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            ptys: AtomicUsize::new(0),
            shells: AtomicUsize::new(0),
            rejections: AtomicUsize::new(0),
        });

        // Both sockets are bound before their accept loops start, so no test
        // ever races a not-yet-listening port.
        let ssh = runtime
            .block_on(AsyncListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding the ssh port must succeed");
        let port = ssh.local_addr().expect("ssh listener address").port();
        let echo = runtime
            .block_on(AsyncListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding the echo port must succeed");
        let echo_port = echo.local_addr().expect("echo listener address").port();

        let tasks = Arc::new(Mutex::new(Vec::new()));
        let accept = runtime.spawn(accept_loop(
            ssh,
            Arc::new(config),
            Arc::clone(&state),
            Arc::clone(&tasks),
        ));
        let echo_task = runtime.spawn(echo_loop(echo));
        tasks
            .lock()
            .expect("the task list is never poisoned")
            .extend([accept, echo_task]);

        Self {
            servers: Mutex::new(Some(runtime)),
            clock,
            tasks,
            port,
            echo_port,
            state,
        }
    }

    /// A specification pointed at this bastion, forwarding to its echo server.
    fn spec(&self) -> TunnelSpec {
        TunnelSpec::new(
            "127.0.0.1",
            self.port,
            TEST_USER,
            SshAuth::Password(TEST_PASSWORD.to_owned()),
            "127.0.0.1",
            self.echo_port,
        )
    }

    /// Opens a tunnel to this bastion and waits for it to be ready.
    fn open(&self) -> (SshTunnel, Events) {
        self.open_with(self.spec())
    }

    /// Opens a tunnel described by `spec`, trusting the host key, and waits for
    /// [`TunnelEvent::Ready`].
    fn open_with(&self, spec: TunnelSpec) -> (SshTunnel, Events) {
        let (tunnel, receiver) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
        let mut events = Events::new(receiver, Arc::clone(&self.clock));
        let ready = events.wait_for(|event| matches!(event, TunnelEvent::Ready { .. }));
        let TunnelEvent::Ready { local_port } = ready else {
            unreachable!("the predicate matched Ready");
        };
        assert_eq!(
            local_port,
            tunnel.local_port(),
            "the event and the handle must agree on the bound port"
        );
        assert!(tunnel.is_alive());
        (tunnel, events)
    }

    /// Starts a TCP relay in front of this bastion that [`Relay::silence`] can
    /// make go quiet.
    ///
    /// Runs on the bastion's own runtime, so [`Bastion::kill`] takes it down
    /// too.
    fn relay(&self) -> Relay {
        let servers = self
            .servers
            .lock()
            .expect("the runtime slot is never poisoned");
        let runtime = servers.as_ref().expect("the bastion is still running");
        let listener = runtime
            .block_on(AsyncListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding the relay port must succeed");
        let port = listener
            .local_addr()
            .expect("relay listener address")
            .port();
        let silent = Arc::new(AtomicBool::new(false));
        let task = runtime.spawn(relay_loop(listener, self.port, Arc::clone(&silent)));
        self.tasks
            .lock()
            .expect("the task list is never poisoned")
            .push(task);
        Relay { port, silent }
    }

    /// Kills the bastion outright, the way a bastion that loses power dies.
    ///
    /// Aborts the accept loops and then discards the whole runtime, which drops
    /// every task on it — russh's session task included — and with them the
    /// accepted sockets. The client therefore sees its transport disappear
    /// rather than being told about it, which is the case that matters: a
    /// bastion that says goodbye is the easy one.
    fn kill(&self) {
        for task in self
            .tasks
            .lock()
            .expect("the task list is never poisoned")
            .drain(..)
        {
            task.abort();
        }
        if let Some(runtime) = self
            .servers
            .lock()
            .expect("the runtime slot is never poisoned")
            .take()
        {
            runtime.shutdown_background();
        }
    }
}

impl Drop for Bastion {
    /// Stops accepting immediately; dropping the runtime afterwards discards any
    /// session task still in flight, so no thread or port leaks into the next
    /// test.
    fn drop(&mut self) {
        self.kill();
    }
}

/// Serves SSH connections until the task is aborted.
async fn accept_loop(
    listener: AsyncListener,
    config: Arc<russh::server::Config>,
    state: Arc<ServerState>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };

        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let session = tokio::spawn(async move {
            let handler = TestHandler { state };
            if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                let _ = session.await;
            }
        });
        tasks
            .lock()
            .expect("the task list is never poisoned")
            .push(session);
    }
}

/// A relay between the tunnel and a [`Bastion`], standing in for the network.
struct Relay {
    /// Ephemeral port the relay listens on; point the tunnel here.
    port: u16,
    /// Once set, every byte is swallowed in both directions.
    silent: Arc<AtomicBool>,
}

impl Relay {
    /// Makes the link go quiet without closing it: what a bastion that lost
    /// power, or a NAT entry that expired, looks like from the client. Both
    /// sockets stay open, so nothing short of an unanswered keepalive can tell
    /// the tunnel anything is wrong.
    fn silence(&self) {
        self.silent.store(true, Ordering::SeqCst);
    }
}

/// Relays each accepted connection to `target` on loopback until aborted.
async fn relay_loop(listener: AsyncListener, target: u16, silent: Arc<AtomicBool>) {
    loop {
        let Ok((client, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(server) = AsyncStream::connect((Ipv4Addr::LOCALHOST, target)).await else {
            return;
        };
        let (client_read, client_write) = client.into_split();
        let (server_read, server_write) = server.into_split();
        tokio::spawn(pump(client_read, server_write, Arc::clone(&silent)));
        tokio::spawn(pump(server_read, client_write, Arc::clone(&silent)));
    }
}

/// Copies one direction of a relayed connection, until the relay is silenced.
async fn pump(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, silent: Arc<AtomicBool>) {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let Ok(read) = from.read(&mut buffer).await else {
            return;
        };
        if read == 0 {
            return;
        }
        if silent.load(Ordering::SeqCst) {
            // Hold both halves open and never write again: the far end sees a
            // connection that is up and says nothing.
            std::future::pending::<()>().await;
        }
        if to.write_all(&buffer[..read]).await.is_err() {
            return;
        }
    }
}

/// Echoes every byte back, one task per connection, until the task is aborted.
async fn echo_loop(listener: AsyncListener) {
    loop {
        let Ok((mut socket, _peer)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let (mut reader, mut writer) = socket.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Event stream helpers
// ---------------------------------------------------------------------------

/// A tunnel's event receiver plus a log of everything already taken from it.
///
/// Every wait is bounded, and every failure message includes the events seen so
/// far so a broken expectation can be diagnosed from the test output alone.
struct Events {
    /// The receiver handed out by [`SshTunnel::open`].
    receiver: UnboundedReceiver<TunnelEvent>,
    /// Every event pulled off `receiver`, in arrival order.
    seen: Vec<TunnelEvent>,
    /// Runtime used purely to drive the timeout; the tunnel has its own.
    runtime: Arc<Runtime>,
}

impl Events {
    /// Wraps a receiver.
    fn new(receiver: UnboundedReceiver<TunnelEvent>, runtime: Arc<Runtime>) -> Self {
        Self {
            receiver,
            seen: Vec::new(),
            runtime,
        }
    }

    /// Waits for the next event, failing the test if none arrives in time.
    fn next(&mut self) -> TunnelEvent {
        // The timeout is built *inside* the runtime: a `Sleep` registers with
        // the timer driver when it is created, not when it is first polled.
        let runtime = Arc::clone(&self.runtime);
        let receiver = &mut self.receiver;
        let event = runtime
            .block_on(async move { tokio::time::timeout(EVENT_TIMEOUT, receiver.next()).await });
        match event {
            Ok(Some(event)) => {
                self.seen.push(event.clone());
                event
            }
            Ok(None) => panic!("the event stream ended; saw {:?}", self.seen),
            Err(_) => panic!("no event within {EVENT_TIMEOUT:?}; saw {:?}", self.seen),
        }
    }

    /// Waits until an event matching `predicate` arrives and returns it.
    fn wait_for(&mut self, predicate: impl Fn(&TunnelEvent) -> bool) -> TunnelEvent {
        loop {
            let event = self.next();
            if predicate(&event) {
                return event;
            }
        }
    }

    /// Waits for the tunnel's terminal event and returns it.
    fn wait_for_end(&mut self) -> TunnelEvent {
        self.wait_for(|event| {
            matches!(
                event,
                TunnelEvent::Disconnected { .. } | TunnelEvent::Error(..)
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Forwarded-socket helpers
// ---------------------------------------------------------------------------

/// A blocking client of the forwarded port.
struct Forwarded(std::net::TcpStream);

impl Forwarded {
    /// Connects to `port` on loopback with timeouts on every operation.
    fn connect(port: u16) -> std::io::Result<Self> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let socket = std::net::TcpStream::connect_timeout(&address, SOCKET_TIMEOUT)?;
        socket.set_read_timeout(Some(SOCKET_TIMEOUT))?;
        socket.set_write_timeout(Some(SOCKET_TIMEOUT))?;
        Ok(Self(socket))
    }

    /// Sends `payload` and reads exactly as many bytes back.
    fn round_trip(&mut self, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        self.0.write_all(payload)?;
        self.0.flush()?;
        let mut echoed = vec![0u8; payload.len()];
        self.0.read_exact(&mut echoed)?;
        Ok(echoed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn a_round_trip_reaches_the_echo_server_through_the_tunnel() {
    let bastion = Bastion::start(Forwarding::Allow);
    let (tunnel, mut events) = bastion.open();

    // The port is the OS's choice, not the one the specification asked for.
    assert_ne!(tunnel.local_port(), 0);
    assert_ne!(tunnel.local_port(), bastion.echo_port);

    let mut socket = Forwarded::connect(tunnel.local_port()).expect("the forwarded port answers");
    assert_eq!(
        socket.round_trip(b"SELECT 1").expect("the echo comes back"),
        b"SELECT 1"
    );

    events.wait_for(|event| matches!(event, TunnelEvent::Accepted { connection: 1 }));
    assert_eq!(bastion.state.forwards.load(Ordering::SeqCst), 1);
}

#[test]
fn the_tunnel_never_asks_for_a_session_a_pty_or_a_shell() {
    let bastion = Bastion::start(Forwarding::Allow);
    let (tunnel, _events) = bastion.open();

    let mut socket = Forwarded::connect(tunnel.local_port()).expect("the forwarded port answers");
    assert_eq!(
        socket.round_trip(b"ping").expect("the echo comes back"),
        b"ping"
    );

    // A bastion account with `nologin` as its shell answers all three of these
    // with a failure. Asking for any of them would break a tunnel that has no
    // use for them.
    assert_eq!(
        bastion.state.sessions.load(Ordering::SeqCst),
        0,
        "a tunnel must not open a session channel"
    );
    assert_eq!(
        bastion.state.ptys.load(Ordering::SeqCst),
        0,
        "a tunnel must not request a pty"
    );
    assert_eq!(
        bastion.state.shells.load(Ordering::SeqCst),
        0,
        "a tunnel must not request a shell"
    );
}

#[test]
fn several_forwarded_sockets_are_independent() {
    let bastion = Bastion::start(Forwarding::Allow);
    let (tunnel, mut events) = bastion.open();
    let port = tunnel.local_port();

    let mut first = Forwarded::connect(port).expect("the first socket connects");
    let mut second = Forwarded::connect(port).expect("the second socket connects");
    let mut third = Forwarded::connect(port).expect("the third socket connects");

    // Interleaved on purpose: three live channels at once is what a connection
    // pool looks like.
    assert_eq!(first.round_trip(b"one").expect("echo"), b"one");
    assert_eq!(second.round_trip(b"two").expect("echo"), b"two");
    assert_eq!(third.round_trip(b"three").expect("echo"), b"three");

    // Closing the middle one must reach the bastion and stop there.
    drop(second);
    events.wait_for(|event| matches!(event, TunnelEvent::ConnectionClosed { .. }));

    assert_eq!(
        first.round_trip(b"still here").expect("echo"),
        b"still here"
    );
    assert_eq!(third.round_trip(b"me too").expect("echo"), b"me too");
    assert!(tunnel.is_alive());
    assert_eq!(bastion.state.forwards.load(Ordering::SeqCst), 3);
}

#[test]
fn a_bastion_that_forbids_forwarding_says_so_without_failing_the_tunnel() {
    let bastion = Bastion::start(Forwarding::Prohibited);
    let (tunnel, mut events) = bastion.open();

    // The refusal happens after the connection is accepted locally, so the
    // socket connects and then dies — which is exactly what a driver sees.
    let mut socket = Forwarded::connect(tunnel.local_port()).expect("the local port answers");
    let _ = socket.round_trip(b"SELECT 1");

    let event = events.wait_for(|event| matches!(event, TunnelEvent::ForwardRejected { .. }));
    let TunnelEvent::ForwardRejected { reason, .. } = &event else {
        unreachable!("the predicate matched ForwardRejected");
    };
    assert!(
        reason.contains("AllowTcpForwarding"),
        "the message must point at the bastion's forwarding policy: {reason}"
    );

    // Crucially *not* an error, and crucially not fatal: the bastion is up and
    // the login worked, so telling the user to check their credentials would
    // send them to the wrong place.
    assert!(
        tunnel.is_alive(),
        "a refused forward must not take the tunnel down"
    );
    assert!(
        !events
            .seen
            .iter()
            .any(|event| matches!(event, TunnelEvent::Error(..))),
        "a refused forward is not a tunnel error: {:?}",
        events.seen
    );
}

#[test]
fn a_bastion_that_cannot_reach_the_target_says_so() {
    let bastion = Bastion::start(Forwarding::ConnectFailed);
    let (tunnel, mut events) = bastion.open();

    let mut socket = Forwarded::connect(tunnel.local_port()).expect("the local port answers");
    let _ = socket.round_trip(b"SELECT 1");

    let event = events.wait_for(|event| matches!(event, TunnelEvent::ForwardRejected { .. }));
    let TunnelEvent::ForwardRejected { reason, .. } = &event else {
        unreachable!("the predicate matched ForwardRejected");
    };
    // A different fix from the one above: the target, not the bastion's policy.
    assert!(
        reason.contains("could not reach"),
        "the message must point at the target: {reason}"
    );
    assert!(reason.contains(&bastion.echo_port.to_string()));
    assert!(tunnel.is_alive());
}

#[test]
fn closing_the_tunnel_releases_the_local_port() {
    let bastion = Bastion::start(Forwarding::Allow);
    let (tunnel, mut events) = bastion.open();
    let port = tunnel.local_port();

    let mut socket = Forwarded::connect(port).expect("the forwarded port answers");
    assert_eq!(socket.round_trip(b"before").expect("echo"), b"before");

    tunnel.close();
    let ending = events.wait_for_end();
    assert!(
        matches!(ending, TunnelEvent::Disconnected { .. }),
        "a local close is not an error: {ending:?}"
    );
    assert!(!tunnel.is_alive());

    // The terminal event is published only after the listener has gone, so the
    // port is bindable again the moment the caller learns the tunnel is down.
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn a_rejected_host_key_is_reported_as_a_host_key_rejection() {
    let bastion = Bastion::start(Forwarding::Allow);
    let (tunnel, receiver) = SshTunnel::open(bastion.spec(), Arc::new(RejectAllVerifier));
    let mut events = Events::new(receiver, Arc::clone(&bastion.clock));

    let announced = events.wait_for(|event| matches!(event, TunnelEvent::HostKey { .. }));
    let TunnelEvent::HostKey {
        algorithm,
        fingerprint,
        accepted,
    } = &announced
    else {
        unreachable!("the predicate matched HostKey");
    };
    // Announced even though it was refused: the UI has to be able to show the
    // fingerprint it is asking the user about.
    assert_eq!(algorithm, "ssh-ed25519");
    assert!(fingerprint.starts_with("SHA256:"));
    assert!(!accepted);

    let ending = events.wait_for_end();
    assert!(
        matches!(ending, TunnelEvent::Error(SshErrorKind::HostKeyRejected, _)),
        "expected a host key rejection, got {ending:?}"
    );
    assert!(!tunnel.is_alive());
    assert_eq!(bastion.state.forwards.load(Ordering::SeqCst), 0);
}

#[test]
fn wrong_credentials_report_an_auth_error() {
    let bastion = Bastion::start(Forwarding::Allow);
    let mut spec = bastion.spec();
    spec.auth = SshAuth::Password("swordfish".to_owned());
    let (tunnel, receiver) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
    let mut events = Events::new(receiver, Arc::clone(&bastion.clock));

    let ending = events.wait_for_end();
    assert!(
        matches!(ending, TunnelEvent::Error(SshErrorKind::Auth, _)),
        "expected an auth failure, got {ending:?}"
    );
    assert!(!tunnel.is_alive());
    assert_eq!(bastion.state.rejections.load(Ordering::SeqCst), 1);

    // Not even the rejected password may appear in what the user is shown.
    let rendered = format!("{:?}", events.seen);
    assert!(
        !rendered.contains("swordfish"),
        "the attempted password leaked: {rendered}"
    );
}

#[test]
fn losing_the_bastion_is_reported_as_an_error_and_not_repaired() {
    let bastion = Bastion::start(Forwarding::Allow);
    let mut spec = bastion.spec();
    // Shortened so the loss is noticed in about a second rather than in the
    // production interval; the mechanism under test is the same.
    spec.keepalive_secs = 1;
    let (tunnel, mut events) = bastion.open_with(spec);
    let port = tunnel.local_port();

    let mut socket = Forwarded::connect(port).expect("the forwarded port answers");
    assert_eq!(socket.round_trip(b"before").expect("echo"), b"before");

    bastion.kill();

    let ending = events.wait_for_end();
    assert!(
        matches!(ending, TunnelEvent::Error(SshErrorKind::Io, _)),
        "a tunnel that dies under a live session must report an error, got {ending:?}"
    );
    // Never silently reconnected: a transaction may have been open on it
    // (architecture document, §9.3).
    assert!(!tunnel.is_alive());
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn a_bastion_that_goes_silent_is_given_up_after_unanswered_keepalives() {
    let bastion = Bastion::start(Forwarding::Allow);
    let relay = bastion.relay();
    let mut spec = bastion.spec();
    spec.port = relay.port;
    // Shortened so the loss is noticed in about three seconds rather than in
    // the production two minutes; the mechanism under test is the same.
    spec.keepalive_secs = 1;
    spec.keepalive_max = 2;
    let (tunnel, mut events) = bastion.open_with(spec);
    let port = tunnel.local_port();

    let mut socket = Forwarded::connect(port).expect("the forwarded port answers");
    assert_eq!(socket.round_trip(b"before").expect("echo"), b"before");

    // Half-dead TCP: no FIN, no RST, just silence. Keepalives that are only
    // *sent* would go into the socket buffer without complaint for minutes.
    relay.silence();

    let ending = events.wait_for_end();
    let TunnelEvent::Error(SshErrorKind::Timeout, message) = &ending else {
        panic!("a bastion that stops answering must time out, got {ending:?}");
    };
    assert!(
        message.contains("keepalive"),
        "the message must say what went unanswered: {message}"
    );
    assert!(!tunnel.is_alive());
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

// ---------------------------------------------------------------------------
// Against a real server
// ---------------------------------------------------------------------------

/// Forwards a port through an sshd that is not part of this test process.
///
/// Ignored by default; see the module documentation for the environment
/// variables it reads and how to run it.
#[test]
#[ignore = "needs a real SSH server; see the module docs for RUDBKIT_SSH_TEST_*"]
fn a_real_bastion_forwards_a_real_port() {
    let Ok(host) = std::env::var("RUDBKIT_SSH_TEST_HOST") else {
        panic!("set RUDBKIT_SSH_TEST_HOST; see the module docs");
    };
    let port = env_u16("RUDBKIT_SSH_TEST_PORT", 22);
    let username = std::env::var("RUDBKIT_SSH_TEST_USER")
        .or_else(|_| std::env::var("USER"))
        .expect("set RUDBKIT_SSH_TEST_USER");
    let auth = match (
        std::env::var("RUDBKIT_SSH_TEST_PASSWORD"),
        std::env::var("RUDBKIT_SSH_TEST_KEY"),
    ) {
        (Ok(password), _) => SshAuth::Password(password),
        (_, Ok(path)) => SshAuth::PrivateKeyFile {
            path: path.into(),
            passphrase: std::env::var("RUDBKIT_SSH_TEST_KEY_PASSPHRASE").ok(),
        },
        _ => SshAuth::Agent,
    };
    let remote_host =
        std::env::var("RUDBKIT_SSH_TEST_REMOTE_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let remote_port = env_u16("RUDBKIT_SSH_TEST_REMOTE_PORT", 22);

    let spec = TunnelSpec::new(host, port, username, auth, remote_host, remote_port);
    // `AcceptAllVerifier` is the right call here and nowhere else: this test
    // knows nothing about the operator's `known_hosts`.
    let (tunnel, receiver) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));

    // No bastion runtime to borrow, so this one drives its own.
    let runtime = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building a runtime must succeed"),
    );
    let mut events = Events::new(receiver, runtime);

    let ready = events.wait_for(|event| {
        matches!(
            event,
            TunnelEvent::Ready { .. } | TunnelEvent::Error(..) | TunnelEvent::Disconnected { .. }
        )
    });
    let TunnelEvent::Ready { local_port } = ready else {
        panic!("the tunnel did not come up: {ready:?}");
    };
    assert_eq!(local_port, tunnel.local_port());
    println!("forwarding 127.0.0.1:{local_port}");

    let mut socket = Forwarded::connect(local_port).expect("the forwarded port answers");
    let mut banner = [0u8; 8];
    socket
        .0
        .read_exact(&mut banner)
        .expect("the remote service answers");
    // Only meaningful when the target really is an sshd, which is the default.
    if remote_port == 22 {
        assert_eq!(
            &banner, b"SSH-2.0-",
            "expected an SSH banner, got {banner:?}"
        );
    }

    tunnel.close();
    let ending = events.wait_for_end();
    assert!(
        matches!(ending, TunnelEvent::Disconnected { .. }),
        "expected an orderly close, got {ending:?}"
    );
}

/// Reads a `u16` from the environment, falling back to `default`.
fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
