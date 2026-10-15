//! A UDP socket for noq that sends multipath paths through different OpenBSD
//! routing tables (`--path .../rtable=N`, see rtable(4)).
//!
//! noq runs every path of an endpoint over one socket, and a socket's routing
//! table (`SO_RTABLE`) applies to everything it sends. So the client binds one
//! extra socket per routing table and wraps them all in [`RoutedUdpSocket`]:
//! each outgoing datagram goes out on the socket of the path it belongs to,
//! matched by its destination and source address (what noq's `Transmit`
//! carries), and datagrams are received on every socket. A path's replies come
//! back to the socket it sent from, since that is the source the peer saw.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, Runtime, TokioRuntime, UdpSender};

use crate::quic;
use crate::util::canonical;

/// Datagrams to `remote` (from `local_ip`, if set) use a socket in routing
/// table `rtable`. `rtable: None` means a separate socket in the default
/// table (tests only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub remote: SocketAddr,
    pub local_ip: Option<IpAddr>,
    pub rtable: Option<u32>,
}

/// Wrap `default` (used for everything no route matches) and one new socket
/// per distinct routing table in `routes` into a single noq socket.
pub fn build(
    default: std::net::UdpSocket,
    routes: &[Route],
) -> io::Result<Box<dyn AsyncUdpSocket>> {
    let local = default.local_addr()?;
    // Same family as the default socket: on a dual-stack IPv6 socket noq
    // addresses IPv4 peers in mapped form, which only an IPv6 socket can send.
    let unspecified = match local.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let runtime = TokioRuntime;
    let mut sockets = vec![runtime.wrap_udp_socket(default)?];
    let mut by_table: BTreeMap<Option<u32>, usize> = BTreeMap::new();
    let mut entries = Vec::new();
    for route in routes {
        let socket = match by_table.get(&route.rtable) {
            Some(&i) => i,
            None => {
                let sock = quic::bind_endpoint_socket_in((unspecified, 0).into(), route.rtable)
                    .map_err(|e| {
                        io::Error::other(format!("routing table {:?}: {e:#}", route.rtable))
                    })?;
                log::info!(
                    "routing table {}: socket {}",
                    route.rtable.map_or("default".into(), |t| t.to_string()),
                    sock.local_addr()?
                );
                sockets.push(runtime.wrap_udp_socket(sock)?);
                by_table.insert(route.rtable, sockets.len() - 1);
                sockets.len() - 1
            }
        };
        entries.push(RouteEntry {
            remote: canonical(route.remote),
            local_ip: route.local_ip.map(|ip| ip.to_canonical()),
            socket,
        });
    }
    Ok(Box::new(RoutedUdpSocket {
        sockets,
        routes: entries.into(),
        next_recv: 0,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteEntry {
    remote: SocketAddr,
    local_ip: Option<IpAddr>,
    socket: usize,
}

/// The socket (index) a datagram to `destination` from `src_ip` goes out on:
/// a route for exactly that remote and source address, else a route for the
/// remote with any source, else the default socket (0). A path opened without
/// a source address learns one from the packets it receives, so its later
/// datagrams carry one.
fn route(routes: &[RouteEntry], destination: SocketAddr, src_ip: Option<IpAddr>) -> usize {
    let destination = canonical(destination);
    let src_ip = src_ip.map(|ip| ip.to_canonical());
    routes
        .iter()
        .find(|r| r.remote == destination && r.local_ip.is_some() && r.local_ip == src_ip)
        .or_else(|| {
            routes
                .iter()
                .find(|r| r.remote == destination && r.local_ip.is_none())
        })
        .map_or(0, |r| r.socket)
}

/// Several UDP sockets behind one noq socket; see the module docs.
struct RoutedUdpSocket {
    /// `sockets[0]` is the default socket.
    sockets: Vec<Box<dyn AsyncUdpSocket>>,
    routes: Arc<[RouteEntry]>,
    /// Where the next receive poll starts, so no socket starves the others.
    next_recv: usize,
}

impl fmt::Debug for RoutedUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedUdpSocket")
            .field("sockets", &self.sockets.len())
            .field("routes", &self.routes)
            .finish()
    }
}

impl AsyncUdpSocket for RoutedUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(RoutedSender {
            senders: self.sockets.iter().map(|s| s.create_sender()).collect(),
            routes: self.routes.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = self.sockets.len();
        for i in 0..n {
            let index = (self.next_recv + i) % n;
            // Every pending socket registers the waker.
            if let Poll::Ready(result) = self.sockets[index].poll_recv(cx, bufs, meta) {
                self.next_recv = (index + 1) % n;
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sockets[0].local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.sockets
            .iter()
            .map(|s| s.max_receive_segments())
            .max()
            .unwrap_or(NonZeroUsize::MIN)
    }

    fn may_fragment(&self) -> bool {
        self.sockets.iter().any(|s| s.may_fragment())
    }
}

struct RoutedSender {
    senders: Vec<Pin<Box<dyn UdpSender>>>,
    routes: Arc<[RouteEntry]>,
}

impl fmt::Debug for RoutedSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RoutedSender")
    }
}

impl UdpSender for RoutedSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let index = route(&this.routes, transmit.destination, transmit.src_ip);
        this.senders[index].as_mut().poll_send(transmit, cx)
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.senders
            .iter()
            .map(|s| s.max_transmit_segments())
            .min()
            .unwrap_or(NonZeroUsize::MIN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(remote: &str, local_ip: Option<&str>, socket: usize) -> RouteEntry {
        RouteEntry {
            remote: remote.parse().unwrap(),
            local_ip: local_ip.map(|ip| ip.parse().unwrap()),
            socket,
        }
    }

    #[test]
    fn routes_by_remote_and_source() {
        let routes = [
            entry("192.0.2.1:443", Some("10.0.0.2"), 1),
            entry("192.0.2.1:443", Some("10.0.0.3"), 2),
            entry("198.51.100.1:443", None, 3),
        ];
        let r = |dst: &str, src: Option<&str>| {
            route(
                &routes,
                dst.parse().unwrap(),
                src.map(|ip| ip.parse().unwrap()),
            )
        };
        assert_eq!(r("192.0.2.1:443", Some("10.0.0.2")), 1);
        assert_eq!(r("192.0.2.1:443", Some("10.0.0.3")), 2);
        // Another source, or none yet: the default socket.
        assert_eq!(r("192.0.2.1:443", Some("10.0.0.9")), 0);
        assert_eq!(r("192.0.2.1:443", None), 0);
        // A route without a source takes the remote from any source.
        assert_eq!(r("198.51.100.1:443", None), 3);
        assert_eq!(r("198.51.100.1:443", Some("10.0.0.2")), 3);
        // Another port is another remote.
        assert_eq!(r("198.51.100.1:444", None), 0);
        // IPv4-mapped forms (dual-stack sockets) match too.
        assert_eq!(r("[::ffff:192.0.2.1]:443", Some("::ffff:10.0.0.3")), 2);
    }
}
