//! One forwarded connection.
//!
//! Everything in here runs as a task of its own, one per accepted socket. That
//! is the whole of the multiplexing story: the task opens exactly one
//! `direct-tcpip` channel, copies bytes both ways until one side stops, and
//! ends. Nothing is shared with the other forwarded connections except the
//! transport handle, whose methods all take `&self`, so a connection that is
//! refused, that fails, or that is simply closed cannot reach any of the others.

use std::net::SocketAddr;
use std::sync::Arc;

use futures::channel::mpsc::UnboundedSender;
use russh::client::Handle;
use russh::{ChannelOpenFailure, Error as RusshError};
use tokio::net::TcpStream;

use crate::event::TunnelEvent;
use crate::tunnel::{ClientHandler, emit};

/// Forwards one accepted socket through the bastion and reports the outcome.
///
/// Never returns an error: a forwarded connection is a leaf, and everything it
/// can go wrong with is either a per-connection event or nothing worth telling
/// anyone about.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward(
    handle: Arc<Handle<ClientHandler>>,
    remote_host: String,
    remote_port: u16,
    socket: TcpStream,
    origin: SocketAddr,
    connection: u64,
    events: UnboundedSender<TunnelEvent>,
) {
    // Database traffic is a long run of small request/response pairs, so waiting
    // to coalesce them costs a round trip per statement and saves nothing.
    if let Err(error) = socket.set_nodelay(true) {
        log::debug!("could not disable Nagle's algorithm on connection {connection}: {error}");
    }

    let channel = match handle
        .channel_open_direct_tcpip(
            remote_host.clone(),
            u32::from(remote_port),
            origin.ip().to_string(),
            u32::from(origin.port()),
        )
        .await
    {
        Ok(channel) => channel,
        Err(error) => {
            let reason = describe_open_failure(&error, &remote_host, remote_port);
            log::warn!("connection {connection} was not forwarded: {reason}");
            emit(&events, TunnelEvent::ForwardRejected { connection, reason });
            return;
        }
    };

    // `into_stream` is what makes a channel look like a socket. Dropping the
    // stream closes the channel, so the channel's lifetime is exactly this
    // task's.
    let mut remote = channel.into_stream();
    let mut local = socket;

    let reason = match tokio::io::copy_bidirectional(&mut local, &mut remote).await {
        Ok((to_remote, to_local)) => {
            format!("closed after {to_remote} bytes out and {to_local} bytes in")
        }
        // Reported rather than escalated: one broken forwarded connection says
        // nothing about the transport, and if the transport really is gone the
        // accept loop reports that on its own.
        Err(error) => format!("forwarding stopped: {error}"),
    };
    log::debug!("connection {connection} {reason}");
    emit(
        &events,
        TunnelEvent::ConnectionClosed { connection, reason },
    );
}

/// Explains why the bastion would not open a forwarding channel.
///
/// The distinction the message has to draw is *whose* configuration is at
/// fault — the bastion's forwarding policy, or the target host and port — since
/// that is the difference between two completely different fixes.
fn describe_open_failure(error: &RusshError, remote_host: &str, remote_port: u16) -> String {
    match error {
        RusshError::ChannelOpenFailure(ChannelOpenFailure::AdministrativelyProhibited) => format!(
            "the bastion refused to forward to {remote_host}:{remote_port}; it most likely has \
             AllowTcpForwarding disabled, or restricts the destinations it will open"
        ),
        RusshError::ChannelOpenFailure(ChannelOpenFailure::ConnectFailed) => format!(
            "the bastion could not reach {remote_host}:{remote_port}; check the host name as it \
             resolves inside the remote network, the port, and the target's own firewall"
        ),
        RusshError::ChannelOpenFailure(ChannelOpenFailure::ResourceShortage) => format!(
            "the bastion is out of resources and would not open a channel to \
             {remote_host}:{remote_port}"
        ),
        RusshError::ChannelOpenFailure(ChannelOpenFailure::UnknownChannelType) => format!(
            "the bastion does not implement direct-tcpip forwarding, so {remote_host}:\
             {remote_port} cannot be reached through it"
        ),
        RusshError::ChannelOpenFailure(ChannelOpenFailure::Other { code, reason }) => format!(
            "the bastion refused to forward to {remote_host}:{remote_port} with code {code}: \
             {reason}"
        ),
        other => format!("could not forward to {remote_host}:{remote_port}: {other}"),
    }
}
