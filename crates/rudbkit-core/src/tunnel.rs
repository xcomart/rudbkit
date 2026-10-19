//! Shared SSH profile settings.
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, path::PathBuf};
const DEFAULT_SSH_PORT: u16 = 22;

/// How the SSH tunnel authenticates against the bastion host.
///
/// Serialized as an internally tagged enum, e.g.
/// `{"kind":"key","path":"/home/me/.ssh/id_ed25519"}`. A bare string —
/// `"agent"`, `"key"`, `"password"` — is also accepted on the way in, because
/// that is how the architecture document spells the field.
///
/// No variant carries a secret: the password and the key passphrase both live
/// in the application keychain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunnelAuth {
    /// Delegate authentication to a running SSH agent. The default: it is the
    /// only method that needs nothing stored anywhere.
    #[default]
    Agent,
    /// Public key authentication using the private key at `path`.
    Key {
        /// Path of the private key file to offer to the bastion.
        ///
        /// Stored as written: a leading `~` or `~/` is expanded to the home
        /// directory only when `rudbkit-ssh` reads the key, so a saved
        /// `~/.ssh/id_ed25519` follows the user running the app. `~user/…` is
        /// not expanded.
        path: PathBuf,
    },
    /// Password authentication, with the password read from the keychain.
    Password,
}

/// On-disk shapes [`TunnelAuth`] accepts.
///
/// The tagged form is what this build writes. The bare string is what the
/// architecture document shows and what a user is most likely to type by hand;
/// with it, the key path comes from the `key_path` sibling on the tunnel block
/// (see [`TunnelConfigRepr`]).
#[derive(Deserialize)]
#[serde(untagged)]
enum TunnelAuthRepr {
    /// `"agent"` / `"key"` / `"password"`.
    Bare(String),
    /// `{"kind": "key", "path": "..."}`.
    Tagged {
        /// Which method; unknown values fall back to the agent.
        kind: String,
        /// Key path, spelled either way round.
        #[serde(default, alias = "key_path")]
        path: Option<PathBuf>,
    },
}

impl<'de> Deserialize<'de> for TunnelAuth {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (kind, path) = match TunnelAuthRepr::deserialize(deserializer)? {
            TunnelAuthRepr::Bare(kind) => (kind, None),
            TunnelAuthRepr::Tagged { kind, path } => (kind, path),
        };
        Ok(TunnelAuth::from_parts(&kind, path))
    }
}

impl TunnelAuth {
    /// Build a variant from a method name and an optional key path.
    ///
    /// An unrecognized name degrades to [`TunnelAuth::Agent`] rather than
    /// failing the load: one mistyped word must not cost the user the rest of
    /// `connections.json`, and the agent is the method that cannot leak a
    /// secret if it is the wrong guess.
    fn from_parts(kind: &str, path: Option<PathBuf>) -> Self {
        match kind.trim().to_ascii_lowercase().as_str() {
            "key" | "public_key" | "publickey" => Self::Key {
                path: path.unwrap_or_default(),
            },
            "password" => Self::Password,
            "agent" => Self::Agent,
            other => {
                log::warn!("unknown tunnel auth method {other:?}, falling back to the SSH agent");
                Self::Agent
            }
        }
    }
}

/// SSH local port forwarding for one connection profile.
///
/// Production databases usually sit behind a bastion host: the application opens a
/// forwarding channel to the bastion, binds a local port, and points JDBC at
/// that port. See the architecture document, §9.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "TunnelConfigRepr")]
pub struct TunnelConfig {
    /// Hostname or IP address of the bastion.
    pub host: String,
    /// TCP port of the bastion's SSH service.
    pub port: u16,
    /// Login user on the bastion.
    pub username: String,
    /// How to authenticate against the bastion.
    pub auth: TunnelAuth,
    /// Host the bastion should connect onwards to — the database, as named
    /// from *inside* the remote network.
    pub remote_host: String,
    /// Port of the database on `remote_host`.
    pub remote_port: u16,
    /// Local port to bind; `0` — the default — lets the OS pick a free one.
    ///
    /// A fixed port is a footgun: two profiles that name the same one cannot be
    /// open at the same time. The actual bound port is what gets substituted
    /// into the JDBC URL, so nothing downstream needs to know which it was.
    pub local_port: u16,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_SSH_PORT,
            username: String::new(),
            auth: TunnelAuth::default(),
            remote_host: String::new(),
            remote_port: 0,
            local_port: 0,
        }
    }
}

/// On-disk shape of [`TunnelConfig`], with the fields the document puts beside
/// the auth method rather than inside it.
///
/// Only the `key_path` sibling makes this necessary: the document writes
/// `"auth": "key", "key_path": "~/.ssh/id_ed25519"`, and the path has to be
/// folded into [`TunnelAuth::Key`] before the public struct sees it.
#[derive(Deserialize)]
#[serde(default)]
struct TunnelConfigRepr {
    host: String,
    port: u16,
    username: String,
    auth: TunnelAuth,
    key_path: Option<PathBuf>,
    remote_host: String,
    remote_port: u16,
    local_port: u16,
}

impl Default for TunnelConfigRepr {
    fn default() -> Self {
        let base = TunnelConfig::default();
        Self {
            host: base.host,
            port: base.port,
            username: base.username,
            auth: base.auth,
            key_path: None,
            remote_host: base.remote_host,
            remote_port: base.remote_port,
            local_port: base.local_port,
        }
    }
}

impl From<TunnelConfigRepr> for TunnelConfig {
    fn from(repr: TunnelConfigRepr) -> Self {
        let auth = match (repr.auth, repr.key_path) {
            // A sibling `key_path` fills in a key whose own path is empty; an
            // inline path wins, since it is the more specific spelling.
            (TunnelAuth::Key { path }, Some(sibling)) if path.as_os_str().is_empty() => {
                TunnelAuth::Key { path: sibling }
            }
            (auth, _) => auth,
        };
        Self {
            host: repr.host,
            port: repr.port,
            username: repr.username,
            auth,
            remote_host: repr.remote_host,
            remote_port: repr.remote_port,
            local_port: repr.local_port,
        }
    }
}

impl fmt::Debug for TunnelConfig {
    /// Renders the tunnel without disclosing anything secret.
    ///
    /// Nothing here holds a secret today — [`TunnelAuth`] deliberately carries
    /// none — but the impl is written by hand anyway so that adding a field
    /// that does is a decision someone has to make in this function rather than
    /// something a `derive` does silently.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("remote_host", &self.remote_host)
            .field("remote_port", &self.remote_port)
            .field("local_port", &self.local_port)
            .finish()
    }
}
