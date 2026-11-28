//! Shared SSH profile settings.
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, path::PathBuf};
use uuid::Uuid;
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
    /// Whether this method needs a secret from the keychain: the password, or
    /// the key's passphrase. The agent keeps its own.
    pub fn needs_secret(&self) -> bool {
        !matches!(self, Self::Agent)
    }

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
    /// SSH hosts to pass through on the way to the bastion, in the order they
    /// are reached — OpenSSH's `ProxyJump`. The first is connected to
    /// directly, each one opens the connection to the next, and the last one
    /// opens it to [`host`](Self::host).
    ///
    /// Empty — the usual case — connects to the bastion directly, and is not
    /// written, so a profile without jump hosts reads as it did before they
    /// existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jumps: Vec<JumpHost>,
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
            jumps: Vec::new(),
        }
    }
}

/// One SSH host passed through on the way to the bastion.
///
/// The same login a bastion has — host, port, user and method — and nothing
/// to forward to: a jump host only ever connects onwards to the next host of
/// the chain.
///
/// Like [`TunnelAuth`], it carries no secret. Its password or key passphrase
/// lives in the application keychain, under [`id`](Self::id), which is why a
/// hop has one: the slot has to stay its own when another hop is added or
/// removed before it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "JumpHostRepr")]
pub struct JumpHost {
    /// Names this hop's keychain slot. Stable for the life of the hop.
    pub id: Uuid,
    /// Hostname or IP address, as the previous hop — or, for the first, this
    /// machine — resolves it.
    pub host: String,
    /// TCP port of its SSH service.
    pub port: u16,
    /// Login user.
    pub username: String,
    /// How to authenticate against it.
    pub auth: TunnelAuth,
}

impl JumpHost {
    /// A hop with a fresh id, nothing filled in, on port 22 and the agent.
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            host: String::new(),
            port: DEFAULT_SSH_PORT,
            username: String::new(),
            auth: TunnelAuth::default(),
        }
    }

    /// `user@host:port`, the way messages name the hop.
    pub fn label(&self) -> String {
        if self.username.is_empty() {
            format!("{}:{}", self.host, self.port)
        } else {
            format!("{}@{}:{}", self.username, self.host, self.port)
        }
    }
}

impl Default for JumpHost {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for JumpHost {
    /// Written by hand for the reason [`TunnelConfig`]'s is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JumpHost")
            .field("id", &self.id)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .finish()
    }
}

/// On-disk shape of [`JumpHost`]: the same `key_path` sibling the tunnel
/// block accepts, and an id that a hand-written hop may leave out.
#[derive(Deserialize)]
#[serde(default)]
struct JumpHostRepr {
    id: Option<Uuid>,
    host: String,
    port: u16,
    username: String,
    auth: TunnelAuth,
    key_path: Option<PathBuf>,
}

impl Default for JumpHostRepr {
    fn default() -> Self {
        Self {
            id: None,
            host: String::new(),
            port: DEFAULT_SSH_PORT,
            username: String::new(),
            auth: TunnelAuth::default(),
            key_path: None,
        }
    }
}

impl From<JumpHostRepr> for JumpHost {
    fn from(repr: JumpHostRepr) -> Self {
        Self {
            // A hop written by hand without one gets a fresh id. It has nothing
            // in the keychain yet, so there is no slot for it to lose.
            id: repr.id.unwrap_or_else(Uuid::new_v4),
            host: repr.host,
            port: repr.port,
            username: repr.username,
            auth: fold_key_path(repr.auth, repr.key_path),
        }
    }
}

/// Folds a `key_path` written beside the method into [`TunnelAuth::Key`].
///
/// A sibling fills in a key whose own path is empty; an inline path wins,
/// since it is the more specific spelling.
fn fold_key_path(auth: TunnelAuth, key_path: Option<PathBuf>) -> TunnelAuth {
    match (auth, key_path) {
        (TunnelAuth::Key { path }, Some(sibling)) if path.as_os_str().is_empty() => {
            TunnelAuth::Key { path: sibling }
        }
        (auth, _) => auth,
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
    jumps: Vec<JumpHost>,
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
            jumps: base.jumps,
        }
    }
}

impl From<TunnelConfigRepr> for TunnelConfig {
    fn from(repr: TunnelConfigRepr) -> Self {
        Self {
            host: repr.host,
            port: repr.port,
            username: repr.username,
            auth: fold_key_path(repr.auth, repr.key_path),
            remote_host: repr.remote_host,
            remote_port: repr.remote_port,
            local_port: repr.local_port,
            jumps: repr.jumps,
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
            .field("jumps", &self.jumps)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jump(host: &str, auth: TunnelAuth) -> JumpHost {
        JumpHost {
            host: host.to_owned(),
            username: "ops".to_owned(),
            auth,
            ..JumpHost::new()
        }
    }

    #[test]
    fn a_tunnel_without_jump_hosts_is_written_as_it_was_before_they_existed() {
        let config = TunnelConfig {
            host: "bastion".into(),
            ..TunnelConfig::default()
        };
        let value = serde_json::to_value(&config).unwrap();
        assert!(value.get("jumps").is_none(), "{value}");
        let back: TunnelConfig = serde_json::from_value(value).unwrap();
        assert_eq!(back, config);

        // And an old file, which never had the field, reads as no jump hosts.
        let old: TunnelConfig =
            serde_json::from_str(r#"{"host":"bastion","username":"ops","auth":"agent"}"#).unwrap();
        assert!(old.jumps.is_empty());
    }

    #[test]
    fn jump_hosts_round_trip_in_order_with_their_ids() {
        let config = TunnelConfig {
            host: "bastion".into(),
            jumps: vec![
                jump("first", TunnelAuth::Password),
                jump(
                    "second",
                    TunnelAuth::Key {
                        path: "~/.ssh/id_ed25519".into(),
                    },
                ),
                jump("third", TunnelAuth::Agent),
            ],
            ..TunnelConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: TunnelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
        let hosts: Vec<_> = back.jumps.iter().map(|hop| hop.host.as_str()).collect();
        assert_eq!(hosts, ["first", "second", "third"]);
    }

    #[test]
    fn a_hand_written_jump_host_needs_only_a_host() {
        let config: TunnelConfig = serde_json::from_str(
            r#"{"host":"bastion","jumps":[
                {"host":"edge","username":"ops","auth":"key","key_path":"~/.ssh/edge"},
                {"host":"inner"}
            ]}"#,
        )
        .unwrap();
        let [edge, inner] = config.jumps.as_slice() else {
            panic!("two hops: {config:?}");
        };
        assert_eq!(
            edge.auth,
            TunnelAuth::Key {
                path: "~/.ssh/edge".into()
            }
        );
        assert_eq!(edge.port, 22);
        assert_eq!(inner.auth, TunnelAuth::Agent);
        assert_eq!(inner.port, 22);
        // Each gets an id of its own, so each gets a keychain slot of its own.
        assert_ne!(edge.id, inner.id);
    }

    #[test]
    fn only_the_agent_needs_no_secret() {
        assert!(!TunnelAuth::Agent.needs_secret());
        assert!(TunnelAuth::Password.needs_secret());
        assert!(
            TunnelAuth::Key {
                path: PathBuf::new()
            }
            .needs_secret()
        );
    }

    #[test]
    fn a_jump_host_is_named_user_at_host_and_port() {
        let mut hop = jump("edge", TunnelAuth::Agent);
        hop.port = 2222;
        assert_eq!(hop.label(), "ops@edge:2222");
        hop.username.clear();
        assert_eq!(hop.label(), "edge:2222");
    }
}
