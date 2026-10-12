//! Events published by a running [`SshTunnel`](crate::SshTunnel).
//!
//! A tunnel never blocks its caller: everything it learns about the bastion
//! arrives as a [`TunnelEvent`] on the receiver handed out by
//! [`SshTunnel::open`](crate::SshTunnel::open).

use std::fmt;

/// A single observation about the life of a tunnel.
///
/// The stream always ends with either [`TunnelEvent::Disconnected`] or
/// [`TunnelEvent::Error`]; no further events follow those.
#[derive(Clone, Debug)]
pub enum TunnelEvent {
    /// The transport is about to open a TCP connection to the bastion.
    Connecting,
    /// The bastion presented its host key and the verifier ruled on it.
    ///
    /// Emitted for display purposes even when the key was rejected, in which
    /// case a [`TunnelEvent::Error`] with [`SshErrorKind::HostKeyRejected`]
    /// follows.
    HostKey {
        /// SSH name of the key algorithm, e.g. `ssh-ed25519`.
        algorithm: String,
        /// OpenSSH-style SHA-256 fingerprint, e.g. `SHA256:...`.
        fingerprint: String,
        /// Whether the verifier accepted the key.
        accepted: bool,
    },
    /// Authentication succeeded and the local port is now accepting.
    ///
    /// This is the point at which the bound port may be substituted into a JDBC
    /// URL. The port is repeated here so a caller that only watches the event
    /// stream never has to reach back into the handle.
    Ready {
        /// The port that was actually bound, which is what the OS chose when
        /// the specification asked for `0`.
        local_port: u16,
    },
    /// A local client connected to the forwarded port.
    Accepted {
        /// Serial number of the forwarded connection, counted from 1. Reused as
        /// the key of the events that report on the same connection later.
        connection: u64,
    },
    /// The bastion refused to forward one connection.
    ///
    /// Deliberately *not* an [`TunnelEvent::Error`]: the SSH transport is
    /// healthy, and only this one socket died. It is reported separately from a
    /// connection failure because the fix is somewhere else — the bastion's
    /// `AllowTcpForwarding`, or the target host and port — and the user has to
    /// know which end to look at.
    ForwardRejected {
        /// Serial number of the forwarded connection.
        connection: u64,
        /// Human-readable explanation, suitable for display in the UI.
        reason: String,
    },
    /// A forwarded connection finished, in either direction.
    ConnectionClosed {
        /// Serial number of the forwarded connection.
        connection: u64,
        /// Human-readable explanation, suitable for display in the UI.
        reason: String,
    },
    /// The tunnel finished. Covers orderly shutdowns and any unexpected end
    /// that is not classified as an error.
    ///
    /// The local port is already closed by the time this is published, so a
    /// caller that waits for it can safely rebind the same port afterwards.
    Disconnected {
        /// Human-readable explanation, suitable for display in the UI.
        reason: String,
    },
    /// The tunnel failed and cannot continue.
    ///
    /// A failure that arrives *after* [`TunnelEvent::Ready`] means the tunnel
    /// broke under whatever was using it. It is never repaired silently: a
    /// transaction may have been open on the connection above, and the user has
    /// to be told (architecture document, §9.3).
    Error(SshErrorKind, String),
}

/// Coarse classification of a fatal tunnel failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshErrorKind {
    /// The local port could not be bound — almost always because something else
    /// already holds it, which is why `local_port: 0` is the default.
    LocalBind,
    /// Name resolution, TCP connect, connect timeout, or protocol handshake
    /// failure — the tunnel never reached authentication.
    Connect,
    /// The host key verifier refused the key the bastion presented.
    HostKeyRejected,
    /// The bastion rejected our credentials.
    Auth,
    /// A private key could not be read, parsed, or decrypted, or no SSH agent
    /// could be reached.
    KeyLoad,
    /// Forwarding itself failed, as opposed to connecting to the bastion: the
    /// bastion forbids `direct-tcpip`, or it could not reach the target host.
    Forward,
    /// Transport-level I/O failure, or an internal error while running the
    /// tunnel. This is what a tunnel that dies mid-flight reports.
    Io,
}

impl fmt::Display for SshErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::LocalBind => "the local port could not be bound",
            Self::Connect => "connection failed",
            Self::HostKeyRejected => "host key rejected",
            Self::Auth => "authentication failed",
            Self::KeyLoad => "private key could not be loaded",
            Self::Forward => "port forwarding failed",
            Self::Io => "i/o error",
        };
        f.write_str(text)
    }
}
