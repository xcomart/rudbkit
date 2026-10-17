//! Connection settings for an SSH tunnel.
//!
//! Everything the transport needs in order to forward a local port through a
//! bastion host lives in [`TunnelSpec`]. Credentials are carried by [`SshAuth`];
//! both types implement [`Debug`](std::fmt::Debug) by hand so that secrets are
//! never rendered into logs or panic messages.
//!
//! [`TunnelSpec::from_config`] converts the on-disk
//! [`TunnelConfig`](rudbkit_core::TunnelConfig) a connection profile carries.
//! That type deliberately holds no secret — the password and the key passphrase
//! live in the OS keychain — so the caller supplies the secret separately.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use rudbkit_core::{TunnelAuth, TunnelConfig};

/// Default keepalive interval, in seconds.
pub const DEFAULT_KEEPALIVE_SECS: u64 = 30;

/// How many keepalives in a row may go unanswered before the bastion is given
/// up for dead.
///
/// Any packet from the bastion counts as an answer, so a busy tunnel never
/// sends one; an idle one with the default interval notices a dead peer in
/// about two minutes.
pub const DEFAULT_KEEPALIVE_MAX: usize = 3;

/// Default TCP connect timeout, in seconds.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 15;

/// Default limit, in seconds, on the whole of setup: TCP connect, SSH banner,
/// key exchange, host key check and authentication together.
pub const DEFAULT_SETUP_TIMEOUT_SECS: u64 = 30;

/// Address the forwarded port is bound to unless something says otherwise.
///
/// Loopback, never `0.0.0.0`: binding the wildcard address would republish a
/// database that is behind a bastion precisely because it is not meant to be
/// reachable, and would do so unauthenticated.
pub const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Placeholder rendered in place of a secret by the manual `Debug` impls.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Maps `Some(secret)` to `Some(<redacted>)` so optional secrets keep their
/// shape in debug output without disclosing anything.
fn mask<T>(value: &Option<T>) -> Option<Redacted> {
    value.as_ref().map(|_| Redacted)
}

/// How to authenticate against the bastion host.
///
/// Exactly one method is attempted per tunnel — there is no fallback chain, so
/// a rejected password is reported as an authentication failure rather than
/// silently retried with a key.
#[derive(Clone)]
pub enum SshAuth {
    /// Keyboard-less password authentication (`ssh-userauth` `password`).
    Password(String),
    /// Public key authentication using a private key read from disk.
    PrivateKeyFile {
        /// Path of the private key file (OpenSSH or PKCS#8 PEM).
        path: PathBuf,
        /// Passphrase, when the key on disk is encrypted.
        passphrase: Option<String>,
    },
    /// Public key authentication using private key material held in memory.
    PrivateKeyData {
        /// The private key, in PEM form.
        pem: String,
        /// Passphrase, when the key material is encrypted.
        passphrase: Option<String>,
    },
    /// Public key authentication delegated to a running SSH agent.
    ///
    /// The only method that needs nothing stored anywhere, which is why it is
    /// what [`TunnelAuth`] defaults to. Every identity the agent offers is
    /// tried in the order the agent lists them.
    Agent,
}

impl SshAuth {
    /// Builds the method a profile's [`TunnelAuth`] asks for.
    ///
    /// `secret` is the password for [`TunnelAuth::Password`] and the key
    /// passphrase for [`TunnelAuth::Key`]; it is ignored by
    /// [`TunnelAuth::Agent`]. A missing password degrades to the empty string
    /// rather than to another method: an empty password is rejected by the
    /// bastion, which is the honest outcome, whereas silently falling back to
    /// the agent would report the wrong failure.
    pub fn from_tunnel_auth(auth: &TunnelAuth, secret: Option<String>) -> Self {
        match auth {
            TunnelAuth::Agent => Self::Agent,
            TunnelAuth::Password => Self::Password(secret.unwrap_or_default()),
            TunnelAuth::Key { path } => Self::PrivateKeyFile {
                path: path.clone(),
                // An empty passphrase and no passphrase mean different things to
                // the key parser, so `None` has to survive the round trip.
                passphrase: secret,
            },
        }
    }
}

impl fmt::Debug for SshAuth {
    /// Renders the authentication method without disclosing any secret.
    ///
    /// Passwords, passphrases and private key material are all replaced by
    /// `<redacted>`; only the key *path* — which is not sensitive and is useful
    /// when diagnosing a failure — is printed verbatim.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&Redacted).finish(),
            Self::PrivateKeyFile { path, passphrase } => f
                .debug_struct("PrivateKeyFile")
                .field("path", path)
                .field("passphrase", &mask(passphrase))
                .finish(),
            Self::PrivateKeyData { passphrase, .. } => f
                .debug_struct("PrivateKeyData")
                .field("pem", &Redacted)
                .field("passphrase", &mask(passphrase))
                .finish(),
            Self::Agent => f.write_str("Agent"),
        }
    }
}

/// Everything needed to forward a local port to a host behind a bastion.
///
/// The shape mirrors [`TunnelConfig`], with the two settings that are transport
/// concerns rather than profile data — the bind address and the timers — added
/// on top.
#[derive(Clone)]
pub struct TunnelSpec {
    /// Hostname or IP address of the bastion.
    pub host: String,
    /// TCP port of the bastion's SSH service.
    pub port: u16,
    /// Login user on the bastion.
    pub username: String,
    /// The single authentication method to attempt.
    pub auth: SshAuth,
    /// Host the bastion connects onwards to, as named from *inside* the remote
    /// network.
    pub remote_host: String,
    /// Port of the target service on [`remote_host`](Self::remote_host).
    pub remote_port: u16,
    /// Local port to bind; `0` — the default — lets the OS pick a free one.
    ///
    /// A fixed port is a footgun: two profiles that name the same one cannot be
    /// open at the same time. Ask for `0` and read the answer back from
    /// [`SshTunnel::local_port`](crate::SshTunnel::local_port).
    pub local_port: u16,
    /// Address the local port is bound to. Defaults to
    /// [`DEFAULT_BIND_ADDRESS`]; see the note there before widening it.
    pub bind_address: IpAddr,
    /// Keepalive interval in seconds; `0` disables keepalives. Defaults to
    /// [`DEFAULT_KEEPALIVE_SECS`].
    ///
    /// A keepalive is only sent after this long with nothing heard from the
    /// bastion, and it is what turns a half-dead TCP connection — a bastion that
    /// lost power, a NAT entry that expired — into an error instead of a tunnel
    /// that hangs every query sent through it.
    pub keepalive_secs: u64,
    /// How many keepalives in a row may go unanswered before the tunnel fails
    /// with [`SshErrorKind::Timeout`](crate::SshErrorKind::Timeout); `0` never
    /// gives up. Defaults to [`DEFAULT_KEEPALIVE_MAX`].
    pub keepalive_max: usize,
    /// TCP connect timeout in seconds; `0` disables the timeout and defers to
    /// the operating system. Defaults to [`DEFAULT_CONNECT_TIMEOUT_SECS`].
    pub connect_timeout_secs: u64,
    /// Limit in seconds on the whole of setup, from the TCP connect to the end
    /// of authentication; `0` disables it. Defaults to
    /// [`DEFAULT_SETUP_TIMEOUT_SECS`].
    ///
    /// The TCP connect timeout alone does not cover a bastion that accepts the
    /// connection and then never sends its banner, or stalls in the key
    /// exchange or in authentication; without this limit such a tunnel never
    /// reaches [`TunnelEvent::Ready`](crate::TunnelEvent::Ready) *or* an error,
    /// and a caller waiting for one of them waits forever. The host key
    /// verifier runs inside this window, so it must answer promptly.
    pub setup_timeout_secs: u64,
}

impl TunnelSpec {
    /// Builds a specification from the mandatory settings, filling in the
    /// documented defaults for everything else.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        auth: SshAuth,
        remote_host: impl Into<String>,
        remote_port: u16,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            auth,
            remote_host: remote_host.into(),
            remote_port,
            local_port: 0,
            bind_address: DEFAULT_BIND_ADDRESS,
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
            keepalive_max: DEFAULT_KEEPALIVE_MAX,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            setup_timeout_secs: DEFAULT_SETUP_TIMEOUT_SECS,
        }
    }

    /// Converts the `tunnel` block of a connection profile.
    ///
    /// `secret` is whatever the keychain holds for this profile's
    /// the application’s tunnel secret slot — a password or
    /// a key passphrase, depending on the method. See
    /// [`SshAuth::from_tunnel_auth`].
    pub fn from_config(config: &TunnelConfig, secret: Option<String>) -> Self {
        Self {
            host: config.host.clone(),
            port: config.port,
            username: config.username.clone(),
            auth: SshAuth::from_tunnel_auth(&config.auth, secret),
            remote_host: config.remote_host.clone(),
            remote_port: config.remote_port,
            local_port: config.local_port,
            bind_address: DEFAULT_BIND_ADDRESS,
            keepalive_secs: DEFAULT_KEEPALIVE_SECS,
            keepalive_max: DEFAULT_KEEPALIVE_MAX,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            setup_timeout_secs: DEFAULT_SETUP_TIMEOUT_SECS,
        }
    }
}

impl fmt::Debug for TunnelSpec {
    /// Written by hand rather than derived so that adding a secret-bearing
    /// field later cannot accidentally start leaking it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelSpec")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            .field("remote_host", &self.remote_host)
            .field("remote_port", &self.remote_port)
            .field("local_port", &self.local_port)
            .field("bind_address", &self.bind_address)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("keepalive_max", &self.keepalive_max)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field("setup_timeout_secs", &self.setup_timeout_secs)
            .finish()
    }
}
