//! SSH local port forwarding for rudbkit.
//!
//! Production databases usually sit behind a bastion host. This crate turns a
//! connection profile's `tunnel` block into a local TCP port that anything can
//! connect to, and forwards every connection made to it through the bastion.
//! [`SshTunnel::open`] hands back a handle plus a stream of [`TunnelEvent`]s;
//! the protocol work happens on a dedicated thread with its own Tokio runtime,
//! which makes the handle safe to hold from a GUI thread.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use rudbkit_ssh::{AcceptAllVerifier, SshAuth, SshTunnel, TunnelSpec};
//!
//! let spec = TunnelSpec::new(
//!     "bastion.example.com",
//!     22,
//!     "ops",
//!     SshAuth::Password("hunter2".into()),
//!     "db.internal",
//!     5432,
//! );
//! let (tunnel, mut events) = SshTunnel::open(spec, Arc::new(AcceptAllVerifier));
//!
//! // Ready to be substituted into a connection URL: with `local_port` left at
//! // 0 the operating system picked a free one, and this is which.
//! println!("forwarding 127.0.0.1:{}", tunnel.local_port());
//! while let Ok(Some(event)) = events.try_next() {
//!     println!("{event:?}");
//! }
//! ```
//!
//! **This crate does not know what runs over the tunnel.** It knows nothing of
//! JDBC, of drivers, or of sessions; it opens a port. Ordering a tunnel against
//! the database session that uses it — tunnel up first, tunnel down last, and
//! reference counting when several sessions share one — belongs to the
//! application layer (architecture document, §3.1 and §9.3).
//!
//! Three things are worth knowing before using it:
//!
//! * **The port is the OS's to choose.** `local_port: 0` is the default, and
//!   [`SshTunnel::local_port`] reports what was actually bound. A fixed port
//!   means two profiles that name the same one cannot be open at once.
//! * **A tunnel that breaks is never repaired silently.** The failure arrives as
//!   a [`TunnelEvent::Error`] and the tunnel stays down, because a transaction
//!   may have been open on top of it and a reconnect would hide that.
//! * **A forwarding refusal is not a connection failure.**
//!   [`TunnelEvent::ForwardRejected`] says the bastion is reachable but would
//!   not forward — a different problem, in a different configuration file, than
//!   a bastion that cannot be logged into.
//!
//! Host key policy is deliberately left to the caller through the
//! [`HostKeyVerifier`] trait: this crate ships only [`AcceptAllVerifier`] and
//! [`RejectAllVerifier`], so that `known_hosts` storage stays in
//! the application’s known-host store and the "do you trust this fingerprint?" dialog
//! stays in the UI.
//!
//! Secrets are contained by design — [`SshAuth`] and [`TunnelSpec`] implement
//! `Debug` by hand and render passwords, passphrases and key material as
//! `<redacted>`, and no error message or log line produced here includes them.

#![warn(missing_docs)]

mod config;
mod event;
mod forward;
mod tunnel;
mod verify;

pub use config::{
    DEFAULT_BIND_ADDRESS, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_KEEPALIVE_SECS, SshAuth, TunnelSpec,
};
pub use event::{SshErrorKind, TunnelEvent};
pub use tunnel::SshTunnel;
pub use verify::{
    AcceptAllVerifier, HostKeyVerifier, RejectAllVerifier, algorithm_name, fingerprint,
};

// `HostKeyVerifier::verify` takes this type, so an implementor outside the
// crate needs its name; re-exported so that naming it does not require a
// direct dependency on `russh` — which would also mean restating the crate's
// non-default feature set, a second place for the `ring` pin to rot.
pub use russh::keys::PublicKey;

mod pool;
pub use pool::LeasePool;
