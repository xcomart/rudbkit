//! Tunnels shared between the sessions that need them.
//!
//! Two connections to databases behind the same bastion — two tabs of one
//! profile, or two profiles naming the same target — need one tunnel between
//! them, not two. [`TunnelLease::acquire`] hands out a claim on the tunnel a
//! profile's `tunnel` block describes, opening one only when none is up, and
//! the last claim to be dropped closes it.
//!
//! Each tunnel is a *generation*: one that ended is never handed out again, and
//! a replacement is a new tunnel that the leases on the old one know nothing
//! about. Releasing an old lease therefore cannot close a replacement.
//!
//! A tunnel that breaks is never repaired silently. Every lease carries a
//! [`TunnelLease::watch`] channel that fires once with the reason, and what
//! happens to the session above it is the application's to decide.

use std::fmt;
use std::hash::BuildHasher;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use futures::StreamExt;
use futures::channel::oneshot;
use futures::executor::block_on;
use parking_lot::Mutex;
use rudbkit_core::{TunnelAuth, TunnelConfig};

use crate::config::{TunnelSecrets, TunnelSpec};
use crate::event::{SshErrorKind, TunnelEvent};
use crate::pool::LeasePool;
use crate::tunnel::SshTunnel;
use crate::verify::HostKeyVerifier;

/// Why [`TunnelLease::acquire`] could not hand out a lease.
#[derive(Debug, Clone)]
pub enum LeaseError {
    /// The tunnel failed, as its [`TunnelEvent::Error`] said. A
    /// [`SshErrorKind::HostKeyRejected`] is the caller's verifier having said
    /// no, which only the caller can explain.
    Failed(SshErrorKind, String),
    /// The tunnel ended, or could not be watched, without ever coming up.
    Ended(String),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(kind, message) => write!(f, "{kind}: {message}"),
            Self::Ended(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for LeaseError {}

/// Identity of a tunnel, for the purpose of sharing one.
///
/// The bastion, the jump hosts before it and the target — and also *how* each
/// host was asked to let the user in. Sharing a tunnel is sharing the
/// authentication that opened it, so a key that left the authentication out
/// would hand a profile whose password is wrong, or whose key file is someone
/// else's, a tunnel it could never have opened itself, and its "connect" would
/// succeed on another profile's credentials. Two profiles that authenticate
/// the same way with the same secrets still share one tunnel. The requested
/// local port is part of it too: a profile that pins a port is asking for that
/// port and must not be handed somebody else's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TunnelKey {
    /// The jump hosts, in the order they are reached.
    jumps: Vec<HostKey>,
    /// The bastion.
    bastion: HostKey,
    remote_host: String,
    remote_port: u16,
    local_port: u16,
}

/// One login of a [`TunnelKey`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct HostKey {
    host: String,
    port: u16,
    username: String,
    auth: AuthKey,
}

impl HostKey {
    fn new(host: &str, port: u16, username: &str, auth: &TunnelAuth, secret: Option<&str>) -> Self {
        let auth = match auth {
            TunnelAuth::Agent => AuthKey::Agent,
            TunnelAuth::Key { path } => AuthKey::Key {
                path: path.clone(),
                passphrase: secret_fingerprint(secret),
            },
            TunnelAuth::Password => AuthKey::Password(secret_fingerprint(secret)),
        };
        Self {
            host: host.to_owned(),
            port,
            username: username.to_owned(),
            auth,
        }
    }
}

/// The authentication half of a [`HostKey`].
///
/// [`TunnelAuth`] itself could not tell two passwords apart: no variant
/// carries the secret. The secret is therefore taken in as a
/// [`secret_fingerprint`] — never as itself, so the pool's keys, and anything
/// that ever prints one, hold nothing a password could be read back out of.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AuthKey {
    /// The agent: the secret, if a stale one was stored, is not what it uses.
    Agent,
    /// A key file, and the fingerprint of the passphrase it was unlocked with.
    Key {
        path: PathBuf,
        passphrase: Option<u64>,
    },
    /// A password, by fingerprint.
    Password(Option<u64>),
}

/// A one-way stand-in for a tunnel secret, comparable within this process.
///
/// SipHash under a key drawn at random once per process, which is what
/// [`RandomState`](std::hash::RandomState) is: nothing is written anywhere, the
/// key dies with the process, and without it the 64 bits are no help in
/// guessing the password. Equal secrets give equal fingerprints, and that is
/// all a pool lookup needs. A collision would only ever share a tunnel between
/// two secrets that the bastion has already accepted one of.
fn secret_fingerprint(secret: Option<&str>) -> Option<u64> {
    static KEY: OnceLock<std::hash::RandomState> = OnceLock::new();
    secret.map(|secret| {
        KEY.get_or_init(std::hash::RandomState::new)
            .hash_one(secret)
    })
}

impl TunnelKey {
    /// The key of one profile's tunnel block, opened with `secrets`.
    fn of(config: &TunnelConfig, secrets: &TunnelSecrets) -> Self {
        TunnelKey {
            jumps: config
                .jumps
                .iter()
                .map(|jump| {
                    HostKey::new(
                        &jump.host,
                        jump.port,
                        &jump.username,
                        &jump.auth,
                        secrets.jump(jump.id),
                    )
                })
                .collect(),
            bastion: HostKey::new(
                &config.host,
                config.port,
                &config.username,
                &config.auth,
                secrets.bastion.as_deref(),
            ),
            remote_host: config.remote_host.clone(),
            remote_port: config.remote_port,
            local_port: config.local_port,
        }
    }
}

/// One shared tunnel and everything hanging off it.
struct Shared {
    /// The transport. Closed by the last lease to be dropped.
    tunnel: SshTunnel,
    /// The port the OS actually bound, which is what goes into the URL.
    local_port: u16,
    /// Set once the tunnel has ended, so a lease taken in the same instant is
    /// not handed a corpse.
    dead: Arc<AtomicBool>,
    /// One sender per lease, fired with the reason when the tunnel ends.
    watchers: Arc<Mutex<Vec<oneshot::Sender<String>>>>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.tunnel.close();
    }
}

/// The tunnels currently up, keyed by bastion, jump hosts and target.
///
/// Process-wide rather than something the application owns, because it has
/// to be reachable from the background threads that do the connecting.
static TUNNELS: LeasePool<TunnelKey, Mutex<Shared>> = LeasePool::new();

/// One session's claim on a shared tunnel.
///
/// Dropping it releases the claim, and the last one out closes the tunnel.
pub struct TunnelLease {
    key: TunnelKey,
    shared: Arc<Mutex<Shared>>,
    local_port: u16,
}

impl fmt::Debug for TunnelLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bastion = &self.key.bastion;
        f.debug_struct("TunnelLease")
            .field(
                "bastion",
                &format_args!("{}:{}", bastion.host, bastion.port),
            )
            .field("jumps", &self.key.jumps.len())
            .field(
                "target",
                &format_args!("{}:{}", self.key.remote_host, self.key.remote_port),
            )
            .field("local_port", &self.local_port)
            .finish()
    }
}

impl TunnelLease {
    /// Takes a lease on the tunnel `config` describes, opening one if none is
    /// up, and waits until it forwards.
    ///
    /// **Blocks** for as long as setup takes — bounded by the spec's setup
    /// timeout — so call it from a background thread. `verifier` rules on the
    /// host keys of a tunnel opened here, and is not consulted when a live one
    /// is shared; keep a handle on it to explain a
    /// [`SshErrorKind::HostKeyRejected`] failure.
    pub fn acquire(
        config: &TunnelConfig,
        secrets: TunnelSecrets,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self, LeaseError> {
        let key = TunnelKey::of(config, &secrets);
        let shared = TUNNELS.acquire(
            key.clone(),
            |shared| !shared.lock().dead.load(Ordering::Acquire),
            || create(config, secrets, verifier),
        )?;
        let local_port = shared.lock().local_port;
        Ok(TunnelLease {
            key,
            shared,
            local_port,
        })
    }

    /// The local port the tunnel is listening on.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// A channel that fires once, with the reason, when the tunnel ends.
    ///
    /// The session above it is then dead and stays dead: a transaction may
    /// have been open, and the user has to be the one who decides what happens
    /// next.
    ///
    /// A tunnel that is *already* down fires immediately, so a caller cannot
    /// miss the news by having asked a moment too late.
    pub fn watch(&self) -> oneshot::Receiver<String> {
        let (sender, receiver) = oneshot::channel();
        let shared = self.shared.lock();
        let mut watchers = shared.watchers.lock();
        if shared.dead.load(Ordering::Acquire) {
            let _ = sender.send("the tunnel is down".to_string());
        } else {
            watchers.push(sender);
        }
        receiver
    }
}

/// How many shared tunnels are currently up in this process.
///
/// An assertion helper above all: a connection attempt that fails has to leave
/// the registry as it found it, and that is not observable any other way.
pub fn live_tunnels() -> usize {
    TUNNELS.live_count()
}

/// Opens the tunnel for a new generation and waits for it to forward.
fn create(
    config: &TunnelConfig,
    secrets: TunnelSecrets,
    verifier: Arc<dyn HostKeyVerifier>,
) -> Result<Mutex<Shared>, LeaseError> {
    let spec = TunnelSpec::from_config(config, secrets);
    let (tunnel, mut events) = SshTunnel::open(spec, verifier);

    // `open` returns before the transport has done anything; the port is only
    // real once `Ready` says so.
    let local_port = loop {
        match block_on(events.next()) {
            Some(TunnelEvent::Ready { local_port }) => break local_port,
            Some(TunnelEvent::Error(kind, message)) => {
                tunnel.close();
                return Err(LeaseError::Failed(kind, message));
            }
            Some(TunnelEvent::Disconnected { reason }) => {
                tunnel.close();
                return Err(LeaseError::Ended(reason));
            }
            Some(_) => continue,
            None => {
                tunnel.close();
                return Err(LeaseError::Ended(
                    "the tunnel ended without ever reporting a bound port".to_string(),
                ));
            }
        }
    };

    let dead = Arc::new(AtomicBool::new(false));
    let watchers = Arc::new(Mutex::new(Vec::new()));
    let shared = Mutex::new(Shared {
        tunnel,
        local_port,
        dead: Arc::clone(&dead),
        watchers: Arc::clone(&watchers),
    });

    // The rest of the event stream is drained on a thread of its own: a tunnel
    // that dies has to reach the sessions above it, and nothing else is
    // listening once the lease has been handed out.
    std::thread::Builder::new()
        .name("rudbkit-tunnel-watch".to_string())
        .spawn(move || {
            let reason = block_on(async move {
                while let Some(event) = events.next().await {
                    match event {
                        TunnelEvent::Error(kind, message) => return format!("{kind}: {message}"),
                        TunnelEvent::Disconnected { reason } => return reason,
                        // A single forwarded socket dying is not the tunnel
                        // dying; the transport is still healthy.
                        other => log::debug!("tunnel event: {other:?}"),
                    }
                }
                "the tunnel ended".to_string()
            });
            let mut watching = watchers.lock();
            dead.store(true, Ordering::Release);
            let watchers = std::mem::take(&mut *watching);
            drop(watching);
            for watcher in watchers {
                let _ = watcher.send(reason.clone());
            }
        })
        .map_err(|error| LeaseError::Ended(error.to_string()))?;

    Ok(shared)
}

#[cfg(test)]
mod tests {
    use rudbkit_core::JumpHost;

    use super::*;

    fn config() -> TunnelConfig {
        TunnelConfig {
            host: "bastion".into(),
            username: "ops".into(),
            auth: TunnelAuth::Password,
            remote_host: "db".into(),
            remote_port: 5432,
            jumps: vec![JumpHost {
                host: "edge".into(),
                username: "ops".into(),
                auth: TunnelAuth::Password,
                ..JumpHost::new()
            }],
            ..TunnelConfig::default()
        }
    }

    fn secrets(config: &TunnelConfig, bastion: &str, jump: &str) -> TunnelSecrets {
        let mut secrets = TunnelSecrets::bastion(Some(bastion.into()));
        secrets.jumps.insert(config.jumps[0].id, jump.into());
        secrets
    }

    #[test]
    fn a_tunnel_is_shared_only_on_the_same_chain_and_the_same_secrets() {
        let config = config();
        let key = TunnelKey::of(&config, &secrets(&config, "a", "b"));
        assert_eq!(key, TunnelKey::of(&config, &secrets(&config, "a", "b")));
        // Another jump host password is another tunnel, as another bastion
        // password is: sharing would let in a profile that could not log in.
        assert_ne!(key, TunnelKey::of(&config, &secrets(&config, "a", "c")));
        assert_ne!(key, TunnelKey::of(&config, &secrets(&config, "z", "b")));

        // So is another chain to the same bastion and target.
        let mut direct = config.clone();
        direct.jumps.clear();
        assert_ne!(key, TunnelKey::of(&direct, &secrets(&config, "a", "b")));
        let mut moved = config.clone();
        moved.jumps[0].host = "elsewhere".into();
        assert_ne!(key, TunnelKey::of(&moved, &secrets(&config, "a", "b")));
    }

    fn key(config: &TunnelConfig, secret: Option<&str>) -> TunnelKey {
        TunnelKey::of(config, &TunnelSecrets::bastion(secret.map(str::to_owned)))
    }

    #[test]
    fn two_profiles_through_one_bastion_share_a_key() {
        let base = TunnelConfig {
            host: "bastion".into(),
            port: 22,
            username: "ops".into(),
            remote_host: "db.internal".into(),
            remote_port: 5432,
            ..TunnelConfig::default()
        };
        // Same bastion, same target, same way in: one tunnel.
        assert_eq!(key(&base, None), key(&base.clone(), None));

        // A different target is a different tunnel, and so is a pinned local
        // port: a profile that asks for one is asking for that one.
        let other_target = TunnelConfig {
            remote_port: 5433,
            ..base.clone()
        };
        assert_ne!(key(&base, None), key(&other_target, None));
        let pinned = TunnelConfig {
            local_port: 15432,
            ..base.clone()
        };
        assert_ne!(key(&base, None), key(&pinned, None));
    }

    #[test]
    fn a_tunnel_is_shared_only_with_the_same_credentials() {
        let agent = TunnelConfig {
            host: "bastion".into(),
            username: "ops".into(),
            remote_host: "db.internal".into(),
            remote_port: 5432,
            ..TunnelConfig::default()
        };
        let with_key = |path: &str| TunnelConfig {
            auth: TunnelAuth::Key { path: path.into() },
            ..agent.clone()
        };
        let password = TunnelConfig {
            auth: TunnelAuth::Password,
            ..agent.clone()
        };

        // Another method is another tunnel: an agent's tunnel must not carry a
        // profile whose own key the bastion has never seen.
        assert_ne!(key(&agent, None), key(&with_key("/k"), None));
        assert_ne!(key(&agent, None), key(&password, None));
        // So is another key file, or the same one under another passphrase.
        assert_ne!(key(&with_key("/a"), None), key(&with_key("/b"), None));
        assert_ne!(
            key(&with_key("/a"), Some("one")),
            key(&with_key("/a"), Some("two"))
        );
        // A wrong password is not let through on a right one's tunnel, while
        // the same password is the same tunnel.
        assert_ne!(key(&password, Some("right")), key(&password, Some("wrong")));
        assert_eq!(key(&password, Some("right")), key(&password, Some("right")));
        // The agent ignores a stale secret, so it does not split its tunnel.
        assert_eq!(key(&agent, Some("stale")), key(&agent, None));
    }

    #[test]
    fn a_tunnel_key_holds_no_secret() {
        let config = config();
        let key = TunnelKey::of(&config, &secrets(&config, "hunter2", "swordfish"));
        let printed = format!("{key:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(!printed.contains("swordfish"), "{printed}");
    }
}
