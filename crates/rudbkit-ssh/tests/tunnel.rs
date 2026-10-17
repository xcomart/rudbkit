//! Hermetic tests for the tunnel transport.
//!
//! Nothing here needs a server: every path exercised ends before, or instead of,
//! a successful handshake. The paths that need a bastion live in `e2e.rs`, which
//! stands one up inside the test process.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt;
use futures::executor::block_on;
use rudbkit_core::{TunnelAuth, TunnelConfig};
use rudbkit_ssh::{
    AcceptAllVerifier, DEFAULT_BIND_ADDRESS, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_KEEPALIVE_MAX,
    DEFAULT_KEEPALIVE_SECS, DEFAULT_SETUP_TIMEOUT_SECS, HostKeyVerifier, RejectAllVerifier,
    SshAuth, SshErrorKind, SshTunnel, TunnelEvent, TunnelSpec, algorithm_name, fingerprint,
};

/// A throwaway ed25519 public key, together with the fingerprint OpenSSH prints
/// for it (`ssh-keygen -lf`).
const TEST_PUBLIC_KEY: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAICwcrJDrM1CScr55jykgFg/NV6C1q2zpz7EXpIsVNOlL";
const TEST_FINGERPRINT: &str = "SHA256:CCHPElk8HNQIXrhrTE8g8WpybVXvNVuP8YlkUi6gFXY";

/// A port that is closed on every sane machine, so connecting to it fails fast.
const CLOSED_PORT: u16 = 9;

/// Builds a specification aimed at a bastion that is not listening.
fn unreachable_spec(auth: SshAuth) -> TunnelSpec {
    TunnelSpec::new(
        "127.0.0.1",
        CLOSED_PORT,
        "nobody",
        auth,
        "db.internal",
        5432,
    )
}

/// A socket that is bound but never accepted from.
///
/// A tunnel pointed at it completes its TCP connect and then waits forever for
/// an SSH banner, which is how the tests below get a tunnel that is reliably
/// *stuck in setup* rather than one racing to fail. The listener has to be kept
/// alive by the caller; dropping it closes the port.
fn stalled_bastion() -> (TcpListener, TunnelSpec) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding must succeed");
    let port = listener
        .local_addr()
        .expect("the listener must have an address")
        .port();
    let spec = TunnelSpec::new(
        "127.0.0.1",
        port,
        "nobody",
        SshAuth::Password("pw".into()),
        "db.internal",
        5432,
    );
    (listener, spec)
}

/// Runs a tunnel to completion and returns every event it produced.
///
/// A watchdog closes the tunnel once `limit` elapses, so the test can never
/// hang: the worker thread honours a close even while it is still connecting.
fn run_tunnel(spec: TunnelSpec, limit: Duration) -> (u16, Vec<TunnelEvent>) {
    let (tunnel, events) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
    let local_port = tunnel.local_port();
    let tunnel = Arc::new(tunnel);
    let done = Arc::new(AtomicBool::new(false));

    let watchdog = {
        let tunnel = Arc::clone(&tunnel);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let deadline = Instant::now() + limit;
            while !done.load(Ordering::SeqCst) {
                if Instant::now() >= deadline {
                    tunnel.close();
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })
    };

    // The stream ends when the worker thread drops its event sender.
    let collected = block_on(events.collect::<Vec<_>>());
    done.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    (local_port, collected)
}

/// Returns the kind of the first `Error` event, if any.
fn first_error(events: &[TunnelEvent]) -> Option<SshErrorKind> {
    events.iter().find_map(|event| match event {
        TunnelEvent::Error(kind, _) => Some(*kind),
        _ => None,
    })
}

#[test]
fn new_spec_fills_in_the_documented_defaults() {
    let spec = TunnelSpec::new(
        "bastion.example.com",
        2222,
        "ops",
        SshAuth::Agent,
        "db.internal",
        5432,
    );

    assert_eq!(spec.host, "bastion.example.com");
    assert_eq!(spec.port, 2222);
    assert_eq!(spec.username, "ops");
    assert_eq!(spec.remote_host, "db.internal");
    assert_eq!(spec.remote_port, 5432);
    // The default that matters: a fixed port is what makes two profiles collide.
    assert_eq!(spec.local_port, 0);
    assert_eq!(spec.bind_address, DEFAULT_BIND_ADDRESS);
    assert_eq!(spec.bind_address, Ipv4Addr::LOCALHOST);
    assert_eq!(spec.keepalive_secs, DEFAULT_KEEPALIVE_SECS);
    assert_eq!(spec.keepalive_max, DEFAULT_KEEPALIVE_MAX);
    assert_eq!(spec.connect_timeout_secs, DEFAULT_CONNECT_TIMEOUT_SECS);
    // Setup is bounded by default: a caller blocking on `Ready` must never be
    // able to wait for ever.
    assert_eq!(spec.setup_timeout_secs, DEFAULT_SETUP_TIMEOUT_SECS);
    assert!(spec.setup_timeout_secs > 0);
}

#[test]
fn a_profiles_tunnel_block_converts_field_for_field() {
    let config = TunnelConfig {
        host: "bastion.example.com".to_owned(),
        port: 2222,
        username: "ops".to_owned(),
        auth: TunnelAuth::Key {
            path: PathBuf::from("/home/ops/.ssh/id_ed25519"),
        },
        remote_host: "db.internal".to_owned(),
        remote_port: 5432,
        local_port: 0,
    };
    let spec = TunnelSpec::from_config(&config, Some("correct horse".to_owned()));

    assert_eq!(spec.host, config.host);
    assert_eq!(spec.port, config.port);
    assert_eq!(spec.username, config.username);
    assert_eq!(spec.remote_host, config.remote_host);
    assert_eq!(spec.remote_port, config.remote_port);
    assert_eq!(spec.local_port, config.local_port);
    assert_eq!(spec.keepalive_max, DEFAULT_KEEPALIVE_MAX);
    assert_eq!(spec.setup_timeout_secs, DEFAULT_SETUP_TIMEOUT_SECS);
    assert!(matches!(
        spec.auth,
        SshAuth::PrivateKeyFile { ref path, ref passphrase }
            if path.ends_with("id_ed25519") && passphrase.as_deref() == Some("correct horse")
    ));

    // The keychain's secret must not surface anywhere in the rendered spec.
    let rendered = format!("{spec:?}");
    assert!(
        !rendered.contains("correct horse"),
        "passphrase leaked: {rendered}"
    );
}

#[test]
fn a_profiles_tunnel_block_maps_every_auth_method() {
    let mut config = TunnelConfig {
        host: "bastion".to_owned(),
        ..TunnelConfig::default()
    };

    config.auth = TunnelAuth::Agent;
    assert!(matches!(
        TunnelSpec::from_config(&config, None).auth,
        SshAuth::Agent
    ));

    config.auth = TunnelAuth::Password;
    assert!(matches!(
        TunnelSpec::from_config(&config, Some("hunter2".to_owned())).auth,
        SshAuth::Password(ref password) if password == "hunter2"
    ));

    // A password nobody stored must still be attempted as a password, so that
    // the bastion's rejection is what the user is told about.
    assert!(matches!(
        TunnelSpec::from_config(&config, None).auth,
        SshAuth::Password(ref password) if password.is_empty()
    ));
}

#[test]
fn debug_output_never_contains_a_password() {
    let auth = SshAuth::Password("hunter2".into());
    let rendered = format!("{auth:?}");

    assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
    assert_eq!(rendered, "Password(<redacted>)");

    let spec = TunnelSpec::new("bastion", 22, "ops", auth, "db.internal", 5432);
    let rendered = format!("{spec:?}");
    assert!(!rendered.contains("hunter2"), "password leaked: {rendered}");
    assert!(rendered.contains("<redacted>"));
    // Non-secret fields stay visible so the output is still useful.
    assert!(rendered.contains("bastion"));
    assert!(rendered.contains("ops"));
    assert!(rendered.contains("db.internal"));
}

#[test]
fn debug_output_never_contains_a_passphrase_or_key_material() {
    let from_file = SshAuth::PrivateKeyFile {
        path: "/home/ops/.ssh/id_ed25519".into(),
        passphrase: Some("correct horse".into()),
    };
    let rendered = format!("{from_file:?}");
    assert!(
        !rendered.contains("correct horse"),
        "passphrase leaked: {rendered}"
    );
    assert!(rendered.contains("Some(<redacted>)"));
    // The path is not a secret and is needed to diagnose failures.
    assert!(rendered.contains("id_ed25519"));

    let from_memory = SshAuth::PrivateKeyData {
        pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nsecretkeybytes\n".into(),
        passphrase: None,
    };
    let rendered = format!("{from_memory:?}");
    assert!(
        !rendered.contains("secretkeybytes"),
        "key material leaked: {rendered}"
    );
    assert!(rendered.contains("pem: <redacted>"));
    assert!(rendered.contains("passphrase: None"));
}

#[test]
fn tunnel_handle_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SshTunnel>();
    assert_send_sync::<TunnelEvent>();
    assert_send_sync::<TunnelSpec>();
}

#[test]
fn opening_binds_an_ephemeral_port_before_it_returns() {
    let (_bastion, spec) = stalled_bastion();
    let (tunnel, _events) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));

    let port = tunnel.local_port();
    assert_ne!(port, 0, "the OS must have picked a port");
    // Bound already, even though the bastion is unreachable and no event has
    // been read yet: that is what makes the port substitutable straight away.
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} should already be listening"
    );
    // Loopback only. A tunnel bound to the wildcard address would republish a
    // database that is behind a bastion precisely because it is private.
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err(),
        "port {port} should be taken on loopback"
    );
}

#[test]
fn the_local_port_is_released_once_the_tunnel_ends() {
    let (port, events) = run_tunnel(
        unreachable_spec(SshAuth::Password("pw".into())),
        Duration::from_secs(10),
    );

    assert_ne!(port, 0);
    assert!(
        matches!(events.last(), Some(TunnelEvent::Error(..))),
        "expected the stream to end with an error, got {events:?}"
    );
    // The terminal event is published only after the listener has been dropped,
    // so by the time the stream has ended the port is free again.
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn a_local_port_that_is_already_taken_is_reported_as_such() {
    let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binding must succeed");
    let taken = squatter
        .local_addr()
        .expect("the listener must have an address")
        .port();

    let mut spec = unreachable_spec(SshAuth::Password("pw".into()));
    spec.local_port = taken;
    let (port, events) = run_tunnel(spec, Duration::from_secs(10));

    assert_eq!(port, 0, "a tunnel that could not bind has no port");
    assert_eq!(
        first_error(&events),
        Some(SshErrorKind::LocalBind),
        "expected a bind failure, got {events:?}"
    );
    // A bind failure must be distinguishable from a bastion failure: nothing
    // was ever sent to the network.
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TunnelEvent::Connecting)),
        "the tunnel must not have tried to connect: {events:?}"
    );
    // The advice in the message is the actionable part.
    assert!(
        matches!(events.first(), Some(TunnelEvent::Error(_, message)) if message.contains("local_port")),
        "the message should point at `local_port`: {events:?}"
    );
}

#[test]
fn connecting_to_a_closed_port_reports_a_connect_error() {
    let (_port, events) = run_tunnel(
        unreachable_spec(SshAuth::Password("pw".into())),
        Duration::from_secs(10),
    );

    assert!(
        matches!(events.first(), Some(TunnelEvent::Connecting)),
        "expected the stream to open with Connecting, got {events:?}"
    );
    let terminal = events.last().expect("the tunnel produced no events");
    assert!(
        matches!(
            terminal,
            TunnelEvent::Error(SshErrorKind::Connect, _) | TunnelEvent::Disconnected { .. }
        ),
        "expected a connect failure, got {terminal:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TunnelEvent::Ready { .. })),
        "the tunnel must not become ready: {events:?}"
    );
}

#[test]
fn a_missing_private_key_reports_a_key_load_error() {
    let (_port, events) = run_tunnel(
        unreachable_spec(SshAuth::PrivateKeyFile {
            path: "this-key-does-not-exist.pem".into(),
            passphrase: Some("hunter2".into()),
        }),
        Duration::from_secs(10),
    );

    assert_eq!(
        first_error(&events),
        Some(SshErrorKind::KeyLoad),
        "expected a key load failure, got {events:?}"
    );
    // The failure must not disclose the passphrase, not even in its message.
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("hunter2"),
        "passphrase leaked: {rendered}"
    );
}

#[test]
fn an_undecodable_private_key_reports_a_key_load_error() {
    let (_port, events) = run_tunnel(
        unreachable_spec(SshAuth::PrivateKeyData {
            pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nnot actually a key\n".into(),
            passphrase: None,
        }),
        Duration::from_secs(10),
    );

    assert_eq!(
        first_error(&events),
        Some(SshErrorKind::KeyLoad),
        "expected a key load failure, got {events:?}"
    );
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("not actually a key"),
        "key material leaked: {rendered}"
    );
}

#[test]
fn a_bastion_that_never_sends_a_banner_times_out() {
    // TCP connects — the kernel completes it from the listen backlog — and then
    // nothing: no banner, no key exchange. Without a limit on setup the tunnel
    // would sit here for ever, and so would anyone waiting for `Ready` (the
    // applications hold a per-bastion lock while they wait).
    let (_bastion, mut spec) = stalled_bastion();
    spec.setup_timeout_secs = 1;

    let started = Instant::now();
    // The watchdog is far beyond the limit, so a close by it would show up as
    // a `Disconnected` instead of the error asserted below.
    let (port, events) = run_tunnel(spec, Duration::from_secs(20));
    let elapsed = started.elapsed();

    let error = events.iter().find_map(|event| match event {
        TunnelEvent::Error(kind, message) => Some((*kind, message.clone())),
        _ => None,
    });
    let Some((kind, message)) = error else {
        panic!("expected a timeout error, got {events:?}");
    };
    assert_eq!(kind, SshErrorKind::Timeout, "{message}");
    assert!(
        message.contains("handshake"),
        "the message must say where setup stalled: {message}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the timeout took {elapsed:?}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TunnelEvent::Ready { .. })),
        "the tunnel must not become ready: {events:?}"
    );
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn a_tunnel_can_be_closed_before_it_is_ready() {
    // A bastion that never answers: without the close below, this tunnel would
    // sit in its handshake indefinitely.
    let (_bastion, spec) = stalled_bastion();
    let (tunnel, events) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
    let port = tunnel.local_port();
    tunnel.close();
    // Calling it twice must be harmless.
    tunnel.close();

    let collected = block_on(events.collect::<Vec<_>>());
    assert!(!tunnel.is_alive());
    assert!(
        !collected
            .iter()
            .any(|event| matches!(event, TunnelEvent::Ready { .. })),
        "the tunnel must not become ready: {collected:?}"
    );
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn dropping_the_handle_releases_the_port() {
    let (_bastion, spec) = stalled_bastion();
    let (tunnel, events) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
    let port = tunnel.local_port();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    drop(tunnel);

    let _ = block_on(events.collect::<Vec<_>>());
    assert!(
        TcpListener::bind(address).is_ok(),
        "port {port} was not released"
    );
}

#[test]
fn fingerprints_match_openssh() {
    let key = russh::keys::parse_public_key_base64(TEST_PUBLIC_KEY).expect("test key must parse");

    assert_eq!(fingerprint(&key), TEST_FINGERPRINT);
    assert_eq!(algorithm_name(&key), "ssh-ed25519");
}

#[test]
fn the_bundled_verifiers_apply_their_policy() {
    let key = russh::keys::parse_public_key_base64(TEST_PUBLIC_KEY).expect("test key must parse");

    assert!(block_on(AcceptAllVerifier.verify("bastion", 22, &key)));
    assert!(!block_on(RejectAllVerifier.verify("bastion", 22, &key)));
}
