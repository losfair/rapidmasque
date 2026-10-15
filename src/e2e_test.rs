//! In-process end-to-end tests over real noq connections on loopback: the
//! BoringSSL backend (with certificate verification against a test CA), ECH
//! acceptance observed on both peers, the SNI guard, QUIC multipath, and the
//! full client → server → UDP target tunnel.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use noq::{Endpoint, FourTuple, PathStatus, TokioRuntime};
use tokio::net::UdpSocket;

use crate::cc::CongestionControl;
use crate::client::{self, ConnectParams, PathSpec, ProxyOptions};
use crate::ech::key::EchKeySet;
use crate::ech_test::{ech_config_list_and_key_set, self_signed};
use crate::endpoint::Endpoint as ProxyEndpoint;
use crate::h3;
use crate::quic::{self, TransportOptions, Verify, WIREGUARD_1280_DATAGRAM};
use crate::ranking::{self, PathPriorities, RankingConfig};
use crate::routed_socket;
use crate::rules::RuleTable;
use crate::server::{self, ServerState};
use crate::stats;
use crate::tls::HandshakeData;
use crate::util::canonical;

/// The certificate from `ech_test::self_signed` covers this name.
const HOST: &str = "secret.internal";

struct Fixture {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    ech_list: Vec<u8>,
    ech_keys: EchKeySet,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("rapidmasque-e2e-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = self_signed();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.to_pem().unwrap()).unwrap();
        std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let (ech_list, ech_keys) = ech_config_list_and_key_set();
        Self {
            dir,
            cert: cert_path,
            key: key_path,
            ech_list,
            ech_keys,
        }
    }

    /// A server endpoint on loopback whose SNI guard allows `allowed`.
    fn server(&self, allowed: &str) -> Endpoint {
        let config = quic::build_server_config(
            &self.cert,
            &self.key,
            Some(&self.ech_keys),
            vec![allowed.to_string()],
            transport(CongestionControl::Bbr3),
        )
        .unwrap();
        let socket = quic::bind_endpoint_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        Endpoint::new(
            quic::endpoint_config(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap()
    }

    /// A client config that verifies the server against the test certificate.
    fn client_config(&self, ech: bool) -> noq::ClientConfig {
        let verify = Verify::Roots {
            ca_file: Some(self.cert.clone()),
        };
        quic::build_client_config(
            &verify,
            ech.then(|| self.ech_list.clone()),
            transport(CongestionControl::Bbr3),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn transport(congestion_control: CongestionControl) -> TransportOptions {
    TransportOptions {
        congestion_control,
        ..Default::default()
    }
}

fn client_endpoint(dual_stack: bool) -> Endpoint {
    let socket =
        quic::client_bind_socket("127.0.0.1:1".parse().unwrap(), dual_stack, None).unwrap();
    Endpoint::new(
        quic::endpoint_config(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap()
}

fn handshake_data(conn: &noq::Connection) -> HandshakeData {
    *conn
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn ech_accepted_over_quic() {
    let fx = Fixture::new("ech");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let hs = handshake_data(&conn);
        conn.closed().await;
        hs
    });

    let client = client_endpoint(false);
    let conn = client
        .connect_with(fx.client_config(true), addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let hs = handshake_data(&conn);
    assert!(hs.ech_accepted, "client must report ECH accepted");
    assert_eq!(hs.protocol.as_deref(), Some(&b"h3"[..]));
    assert!(conn.is_multipath_enabled(), "multipath must be negotiated");
    let der = conn.peer_identity().unwrap().downcast::<Vec<u8>>().unwrap();
    assert!(!der.is_empty());
    conn.close(0u32.into(), b"");

    let server_hs = accept.await.unwrap();
    assert!(server_hs.ech_accepted, "server must report ECH accepted");
    // With ECH accepted, the server sees the protected inner name.
    assert_eq!(server_hs.server_name.as_deref(), Some(HOST));
}

#[tokio::test(flavor = "multi_thread")]
async fn unmatched_sni_is_rejected() {
    let fx = Fixture::new("sni");
    let server = fx.server("other.internal");
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let client = client_endpoint(false);
    for ech in [false, true] {
        let res = client
            .connect_with(fx.client_config(ech), addr, HOST)
            .unwrap()
            .await;
        assert!(
            res.is_err(),
            "handshake with SNI {HOST} must fail (ech={ech})"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_certificate_is_rejected() {
    let fx = Fixture::new("verify");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    // Trust a different self-signed certificate than the one served.
    let other = Fixture::new("verify-other");
    let client = client_endpoint(false);
    let res = client
        .connect_with(other.client_config(false), addr, HOST)
        .unwrap()
        .await;
    assert!(
        res.is_err(),
        "unverifiable certificate must fail the handshake"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multipath_second_path_carries_datagrams() {
    let fx = Fixture::new("multipath");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    // Echo every datagram back.
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok(d) = conn.read_datagram().await {
            let _ = conn.send_datagram(d);
        }
    });

    let client = client_endpoint(true);
    let conn = client
        .connect_with(fx.client_config(false), addr, HOST)
        .unwrap()
        .await
        .unwrap();
    assert!(conn.is_multipath_enabled());

    // A second path from another loopback source address. The first attempt
    // may race the server's path CID issuance, so retry briefly.
    let tuple = FourTuple::new(addr, Some("127.0.0.2".parse().unwrap()));
    let mut path = None;
    for _ in 0..40 {
        match conn.open_path_ensure(tuple, PathStatus::Available).await {
            Ok(p) => {
                path = Some(p);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let path = path.expect("second path must open");
    assert_ne!(path.id(), noq::PathId::ZERO);

    // Make the new path the only usable one, then prove datagrams still flow.
    conn.path(noq::PathId::ZERO)
        .unwrap()
        .set_status(PathStatus::Backup)
        .unwrap();
    conn.send_datagram(bytes::Bytes::from_static(b"over path 1"))
        .unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"over path 1");
    assert!(path.stats().udp_tx.datagrams > 0, "path 1 must have sent");
}

/// Client path priorities (`--path .../priority=N`, `--primary-priority`)
/// apply on both ends: locally, and on the proxy through the PATH_PRIORITY
/// control frame. With an extra path to the same proxy address, the primary
/// path's maintainer is pinned to the handshake's source address.
#[tokio::test(flavor = "multi_thread")]
async fn path_priorities_apply_on_both_ends() {
    let fx = Fixture::new("priority");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    let (server_tx, server_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let _control = h3::open_control(&conn).await.unwrap();
        tokio::spawn(h3::serve_uni_streams(
            conn.clone(),
            Default::default(),
            None,
        ));
        let _ = server_tx.send(conn.clone());
        conn.closed().await;
    });

    let client = client_endpoint(true);
    let conn = client
        .connect_with(fx.client_config(false), addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let server_conn = server_rx.await.unwrap();
    let control = h3::open_control(&conn).await.unwrap();

    let extra: PathSpec = format!("{addr}@127.0.0.2/priority=3").parse().unwrap();
    let primary = client::primary_path_spec(&conn, addr, std::slice::from_ref(&extra), 1).await;
    assert_eq!(
        primary.local_ip.map(|ip| ip.to_canonical()),
        Some("127.0.0.1".parse().unwrap()),
        "primary path must be pinned to the handshake's source address"
    );
    for spec in [primary, extra] {
        tokio::spawn(client::maintain_path(
            conn.clone(),
            spec,
            control.clone(),
            Default::default(),
        ));
    }

    // Path 0 (primary) gets priority 1 and the extra path priority 3, on both
    // ends.
    let applied = |c: &noq::Connection| {
        let primary = c.path(noq::PathId::ZERO).and_then(|p| p.priority().ok()) == Some(1);
        let extra = (1..quic::MAX_PATHS * 4)
            .filter_map(|id| c.path(noq::PathId::from(id)))
            .any(|p| p.priority().ok() == Some(3));
        primary && extra
    };
    for _ in 0..100 {
        if applied(&conn) && applied(&server_conn) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "priorities not applied (client: {}, server: {})",
        applied(&conn),
        applied(&server_conn)
    );
}

/// A UDP relay standing in for an impaired network path between one client
/// and `upstream`: it drops `loss_permille`/1000 of the packets in each
/// direction (evenly spread, so the rate is exact).
async fn lossy_relay(upstream: SocketAddr, loss_permille: Arc<AtomicU32>) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.3:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut client = None;
        let mut debt = [0u32; 2];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let (to, dir) = if from == upstream {
                match client {
                    Some(c) => (c, 0),
                    None => continue,
                }
            } else {
                client = Some(from);
                (upstream, 1)
            };
            debt[dir] += loss_permille.load(Ordering::Relaxed);
            if debt[dir] >= 1000 {
                debt[dir] -= 1000;
                continue;
            }
            let _ = sock.send_to(&buf[..n], to).await;
        }
    });
    addr
}

/// The local priority of the path to `remote`, if open. On a dual-stack
/// client socket noq reports IPv4 remotes in IPv4-mapped form.
fn priority_towards(conn: &noq::Connection, remote: SocketAddr) -> Option<u8> {
    (0..4 * quic::MAX_PATHS)
        .filter_map(|id| conn.path(noq::PathId::from(id)))
        .find(|p| p.remote_address().ok().map(canonical) == Some(canonical(remote)))
        .and_then(|p| p.priority().ok())
}

/// `--path-ranking auto`: a path whose loss is clearly worse than another path
/// of the same priority is demoted on both ends (each end ranking what it
/// sends), and promoted again once the loss stops.
#[tokio::test(flavor = "multi_thread")]
async fn lossy_path_is_demoted_and_recovers_on_both_ends() {
    // Fast sampling; idle paths (only keepalives, 1/s) still yield samples.
    let config = RankingConfig {
        interval: Duration::from_millis(100),
        min_sample_packets: 30,
        max_sample_age: Duration::from_millis(500),
        min_idle_sample_packets: 2,
        sample_weight: 1.0,
        demote_after: 2,
        promote_after: 2,
        min_change_interval: Duration::from_millis(500),
        ..Default::default()
    };
    let fx = Fixture::new("ranking");
    let server = fx.server(HOST);
    let server_addr = server.local_addr().unwrap();
    let (server_tx, server_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let priorities = Arc::new(PathPriorities::default());
        ranking::start(conn.clone(), priorities.clone(), config);
        let _control = h3::open_control(&conn).await.unwrap();
        tokio::spawn(h3::serve_uni_streams(conn.clone(), priorities, None));
        let _ = server_tx.send(conn.clone());
        while let Ok(d) = conn.read_datagram().await {
            let _ = conn.send_datagram(d);
        }
    });

    // The handshake path (path 0, preferred by noq at equal priority, so it
    // carries the traffic) goes through the relay; the extra path is direct.
    let loss = Arc::new(AtomicU32::new(0));
    let relay = lossy_relay(server_addr, loss.clone()).await;
    let client = client_endpoint(true);
    let conn = client
        .connect_with(fx.client_config(false), relay, HOST)
        .unwrap()
        .await
        .unwrap();
    let server_conn = server_rx.await.unwrap();
    let control = h3::open_control(&conn).await.unwrap();
    let priorities = Arc::new(PathPriorities::default());
    control.send_path_ranking().await.unwrap();
    ranking::start(conn.clone(), priorities.clone(), config);
    let direct: PathSpec = server_addr.to_string().parse().unwrap();
    let primary = client::primary_path_spec(&conn, relay, std::slice::from_ref(&direct), 0).await;
    for spec in [primary, direct] {
        tokio::spawn(client::maintain_path(
            conn.clone(),
            spec,
            control.clone(),
            priorities.clone(),
        ));
    }
    tokio::spawn({
        let conn = conn.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_millis(2));
            loop {
                tick.tick().await;
                if conn
                    .send_datagram(bytes::Bytes::from_static(&[7; 1000]))
                    .is_err()
                {
                    return;
                }
            }
        }
    });
    tokio::spawn({
        let conn = conn.clone();
        async move { while conn.read_datagram().await.is_ok() {} }
    });

    // The server sees the relayed path as coming from the relay itself.
    let relayed = |c: &noq::Connection| priority_towards(c, relay);
    let wait_for = |want: u8| {
        let (conn, server_conn) = (conn.clone(), server_conn.clone());
        async move {
            for _ in 0..300 {
                if relayed(&conn) == Some(want) && relayed(&server_conn) == Some(want) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            panic!(
                "relayed path priority: client {:?}, server {:?}, want {want}",
                relayed(&conn),
                relayed(&server_conn)
            );
        }
    };

    // Let the extra path come up and both paths collect clean samples.
    wait_for(0).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(priority_towards(&conn, server_addr), Some(0));

    loss.store(200, Ordering::Relaxed);
    wait_for(1).await; // 2 * base 0 + demoted
    assert_eq!(
        priority_towards(&conn, server_addr),
        Some(0),
        "the clean path must stay preferred"
    );

    loss.store(0, Ordering::Relaxed);
    wait_for(0).await;
}

/// A path routed onto its own socket (`--path .../rtable=N` on OpenBSD; here a
/// second socket in the default table) sends and receives through that
/// socket: the server sees it from another source port than the primary.
#[tokio::test(flavor = "multi_thread")]
async fn routed_path_uses_its_own_socket() {
    let fx = Fixture::new("routed");
    let server = fx.server(HOST);
    let server_addr = server.local_addr().unwrap();
    let (server_tx, server_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let _ = server_tx.send(conn.clone());
        while let Ok(d) = conn.read_datagram().await {
            let _ = conn.send_datagram(d);
        }
    });

    let extra_local: std::net::IpAddr = "127.0.0.2".parse().unwrap();
    let socket = quic::client_bind_socket(server_addr, true, None).unwrap();
    let routed = routed_socket::build(
        socket,
        &[routed_socket::Route {
            remote: server_addr,
            local_ip: Some(extra_local),
            rtable: None,
        }],
    )
    .unwrap();
    let client = Endpoint::new_with_abstract_socket(
        quic::endpoint_config(),
        None,
        routed,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let conn = client
        .connect_with(fx.client_config(false), server_addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let server_conn = server_rx.await.unwrap();

    let tuple = FourTuple::new(server_addr, Some(extra_local));
    let mut path = None;
    for _ in 0..40 {
        match conn.open_path_ensure(tuple, PathStatus::Available).await {
            Ok(p) => {
                path = Some(p);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let path = path.expect("routed path must open");
    conn.path(noq::PathId::ZERO)
        .unwrap()
        .set_status(PathStatus::Backup)
        .unwrap();
    conn.send_datagram(bytes::Bytes::from_static(b"routed"))
        .unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed[..], b"routed");
    assert!(
        path.stats().udp_rx.datagrams > 0,
        "replies arrive on the routed socket"
    );

    let remote_of = |id| {
        server_conn
            .path(id)
            .and_then(|p| p.remote_address().ok())
            .map(canonical)
            .unwrap()
    };
    let (primary, routed) = (remote_of(noq::PathId::ZERO), remote_of(path.id()));
    assert_eq!(routed.ip(), extra_local);
    assert_ne!(
        primary.port(),
        routed.port(),
        "the routed path must leave through its own socket"
    );
}

/// `--bbr3-initial-window` reaches the connection's BBRv3 controllers.
#[tokio::test(flavor = "multi_thread")]
async fn bbr3_initial_window_applies_to_connections() {
    const WINDOW: u64 = 256 * 1024;
    let fx = Fixture::new("initcwnd");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        conn.closed().await;
    });
    let config = quic::build_client_config(
        &Verify::Roots {
            ca_file: Some(fx.cert.clone()),
        },
        None,
        TransportOptions {
            bbr3_initial_window: WINDOW,
            ..Default::default()
        },
    )
    .unwrap();
    let client = client_endpoint(false);
    let conn = client
        .connect_with(config, addr, HOST)
        .unwrap()
        .await
        .unwrap();
    // BBRv3 only grows the window from its initial value during startup.
    let cwnd = conn.path(noq::PathId::ZERO).unwrap().stats().cwnd;
    assert!(cwnd >= WINDOW, "cwnd {cwnd} below the configured {WINDOW}");
}

/// A UDP relay for one client in front of `upstream` whose client-to-upstream
/// direction is a bottleneck: a token bucket of `rate` bytes per second (and a
/// 32 KiB burst) that drops what exceeds it, like a policer.
async fn policed_relay(upstream: SocketAddr, rate: f64) -> SocketAddr {
    const BURST: f64 = 32.0 * 1024.0;
    let sock = UdpSocket::bind("127.0.0.3:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut client = None;
        let mut tokens = BURST;
        let mut last = tokio::time::Instant::now();
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let to = if from == upstream {
                match client {
                    Some(c) => c,
                    None => continue,
                }
            } else {
                client = Some(from);
                let now = tokio::time::Instant::now();
                tokens = (tokens + rate * (now - last).as_secs_f64()).min(BURST);
                last = now;
                if tokens < n as f64 {
                    continue;
                }
                tokens -= n as f64;
                upstream
            };
            let _ = sock.send_to(&buf[..n], to).await;
        }
    });
    addr
}

/// Offer 4 MB/s of echoed datagrams through a 2 MB/s bottleneck for 3 s and
/// return the median round-trip time of the echoes received in the last
/// second, plus the client's datagram drop counters.
async fn overloaded_tunnel_rtt(codel: Option<noq::DatagramCodel>) -> (Duration, u64, u64) {
    let fx = Fixture::new(if codel.is_some() { "codel" } else { "nocodel" });
    let server = fx.server(HOST);
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok(d) = conn.read_datagram().await {
            let _ = conn.send_datagram(d);
        }
    });
    let relay = policed_relay(server_addr, 2_000_000.0).await;
    let config = quic::build_client_config(
        &Verify::Roots {
            ca_file: Some(fx.cert.clone()),
        },
        None,
        TransportOptions {
            datagram_codel: codel,
            ..Default::default()
        },
    )
    .unwrap();
    let client = client_endpoint(false);
    let conn = client
        .connect_with(config, relay, HOST)
        .unwrap()
        .await
        .unwrap();

    let start = std::time::Instant::now();
    let sender = tokio::spawn({
        let conn = conn.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_millis(1));
            while start.elapsed() < Duration::from_secs(3) {
                tick.tick().await;
                for _ in 0..4 {
                    let mut payload = vec![0u8; 1000];
                    let sent = start.elapsed().as_nanos() as u64;
                    payload[..8].copy_from_slice(&sent.to_be_bytes());
                    let _ = conn.send_datagram(payload.into());
                }
            }
        }
    });
    let mut rtts = Vec::new();
    while start.elapsed() < Duration::from_secs(3) {
        let Ok(Ok(d)) =
            tokio::time::timeout(Duration::from_millis(100), conn.read_datagram()).await
        else {
            continue;
        };
        let sent = Duration::from_nanos(u64::from_be_bytes(d[..8].try_into().unwrap()));
        let received = start.elapsed();
        if received >= Duration::from_secs(2) {
            rtts.push(received - sent);
        }
    }
    sender.abort();
    let stats = conn.stats();
    rtts.sort();
    let median = rtts.get(rtts.len() / 2).copied().unwrap_or(Duration::MAX);
    (
        median,
        stats.datagrams_dropped_delay,
        stats.datagrams_dropped_overflow,
    )
}

/// With queue management (the default), tunnelled datagrams that outpace the
/// path are dropped instead of queueing for seconds in front of everything
/// else. The offered load here does not slow down on loss, so it is the
/// 200 ms hard limit, not CoDel's gradual drops, that bounds the delay.
#[tokio::test(flavor = "multi_thread")]
async fn datagram_queue_delay_stays_low_under_overload() {
    let (unmanaged, delay_drops, _) = overloaded_tunnel_rtt(None).await;
    assert_eq!(delay_drops, 0);
    let (managed, delay_drops, _) =
        overloaded_tunnel_rtt(TransportOptions::default().datagram_codel).await;
    eprintln!("median RTT under overload: {unmanaged:?} unmanaged, {managed:?} managed");
    assert!(delay_drops > 0, "CoDel never dropped");
    assert!(
        unmanaged > Duration::from_millis(500),
        "without CoDel the queue should have grown, median RTT {unmanaged:?}"
    );
    assert!(
        managed < Duration::from_millis(300),
        "median RTT {managed:?} with CoDel (without: {unmanaged:?})"
    );
}

async fn udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&reply, from).await;
        }
    });
    addr
}

/// A running server + local client proxy, tunnelling to a UDP echo target.
struct Tunnel {
    /// The client's local UDP listen address.
    listen: SocketAddr,
}

/// Start a server (rule-pinned to a UDP echo target) and a client proxy with
/// ECH and the extra paths `paths(proxy_addr)`, optionally listing their
/// connections in stats registries.
async fn start_tunnel(
    fx: &Fixture,
    paths: impl FnOnce(SocketAddr) -> Vec<PathSpec> + 'static,
    server_stats: Option<Arc<stats::Registry>>,
    client_stats: Option<Arc<stats::Registry>>,
) -> Tunnel {
    start_tunnel_with(
        fx,
        TunnelConfig {
            paths: Box::new(paths),
            server_stats,
            client_stats,
            ..Default::default()
        },
    )
    .await
}

type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// Options for [`start_tunnel_with`].
struct TunnelConfig {
    /// Extra paths, given the server's address.
    paths: Box<dyn FnOnce(SocketAddr) -> Vec<PathSpec>>,
    server_stats: Option<Arc<stats::Registry>>,
    client_stats: Option<Arc<stats::Registry>>,
    /// The client's primary path goes here instead of to the server, given
    /// the server's address (e.g. a relay in front of it).
    primary_via: Option<Box<dyn FnOnce(SocketAddr) -> BoxFuture<SocketAddr>>>,
    primary_rate: Option<u64>,
    max_path_rate: Option<u64>,
    in_order_delivery: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            paths: Box::new(|_| Vec::new()),
            server_stats: None,
            client_stats: None,
            primary_via: None,
            primary_rate: None,
            max_path_rate: None,
            in_order_delivery: true,
        }
    }
}

async fn start_tunnel_with(fx: &Fixture, cfg: TunnelConfig) -> Tunnel {
    let TunnelConfig {
        paths,
        server_stats,
        client_stats,
        primary_via,
        primary_rate,
        max_path_rate,
        in_order_delivery,
    } = cfg;
    let target = udp_echo().await;

    // Server: bind first to learn the port the rule's authority must carry.
    let socket = quic::bind_endpoint_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let rules_path = fx.dir.join("rules.json");
    std::fs::write(
        &rules_path,
        format!(r#"[{{"endpoint":"https://{HOST}:{port}/connect","target":"{target}"}}]"#),
    )
    .unwrap();
    let rules = RuleTable::load(&rules_path).unwrap();
    let config = quic::build_server_config(
        &fx.cert,
        &fx.key,
        Some(&fx.ech_keys),
        rules.allowed_sni_hosts(),
        transport(CongestionControl::None),
    )
    .unwrap();
    let endpoint = Endpoint::new(
        quic::endpoint_config(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let state = Arc::new(ServerState {
        rules: ArcSwap::from_pointee(rules),
        stats: server_stats,
        max_path_rate,
    });
    tokio::spawn(server::run(endpoint, state));

    let listen = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let proxy_addr = match primary_via {
        Some(via) => via(server_addr).await,
        None => server_addr,
    };
    let opts = ProxyOptions {
        conn: ConnectParams {
            endpoint: ProxyEndpoint::parse(&format!("https://{HOST}:{port}/connect")).unwrap(),
            proxy_addr: Some(proxy_addr),
            verify: Verify::Roots {
                ca_file: Some(fx.cert.clone()),
            },
            ech_config_list: Some(fx.ech_list.clone()),
            paths: paths(server_addr),
            primary_priority: 0,
            primary_rate,
            in_order_delivery,
            rtable: None,
            path_ranking: Default::default(),
            stats: client_stats,
            transport: transport(CongestionControl::None),
        },
        listen,
    };
    tokio::spawn(client::run_proxy(opts));
    Tunnel { listen }
}

impl Tunnel {
    /// Send datagrams through the tunnel until one is echoed back.
    async fn roundtrip(&self) {
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = vec![0u8; 2048];
        for attempt in 0..50 {
            app.send_to(format!("hello {attempt}").as_bytes(), self.listen)
                .await
                .unwrap();
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(200), app.recv(&mut buf)).await
            {
                let reply = std::str::from_utf8(&buf[..n]).unwrap();
                assert!(
                    reply.starts_with("echo:hello "),
                    "unexpected reply {reply:?}"
                );
                return;
            }
        }
        panic!("no reply through the tunnel");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_roundtrip_with_ech_and_multipath() {
    let fx = Fixture::new("tunnel");
    // An extra multipath path from another loopback source address.
    let tunnel = start_tunnel(
        &fx,
        |proxy| vec![format!("{proxy}@127.0.0.2").parse().unwrap()],
        None,
        None,
    )
    .await;
    tunnel.roundtrip().await;
}

/// `GET` `path` from an HTTP server; returns the status code and body.
async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: stats\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    sock.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_string())
}

/// The stats endpoint lists the tunnel's connection on both ends, with its
/// paths, their priorities and the (default) automatic ranking.
#[tokio::test(flavor = "multi_thread")]
async fn stats_endpoint_reports_connections_and_paths() {
    let fx = Fixture::new("stats");
    let (server_stats, client_stats) = (
        stats::Registry::new("server"),
        stats::Registry::new("client"),
    );
    let mut endpoints = Vec::new();
    for registry in [&server_stats, &client_stats] {
        let listener = stats::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        endpoints.push(listener.local_addr().unwrap());
        tokio::spawn(stats::serve(listener, registry.clone()));
    }
    let tunnel = start_tunnel(
        &fx,
        |proxy| vec![format!("{proxy}@127.0.0.2/priority=2").parse().unwrap()],
        Some(server_stats),
        Some(client_stats),
    )
    .await;
    tunnel.roundtrip().await;

    // Both ends report one connection with the primary path and the extra
    // path at priority 2 (announced to the server), and one flow.
    let mut last = Vec::new();
    for _ in 0..50 {
        last.clear();
        for (addr, role) in endpoints.iter().zip(["server", "client"]) {
            let (status, body) = http_get(*addr, "/stats").await;
            assert_eq!(status, 200);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["role"], role);
            last.push(v);
        }
        let done = last.iter().all(|v| {
            let Some([conn]) = v["connections"].as_array().map(Vec::as_slice) else {
                return false;
            };
            let paths = conn["paths"].as_array().unwrap();
            conn["flows"] == 1
                && conn["multipath"] == true
                // Ranking is on by default (the client asks the proxy too), so
                // the effective noq priority is 2 * configured priority.
                && conn["path_ranking"] == true
                && paths
                    .iter()
                    .any(|p| p["priority"] == 0 && p["status"] == "available")
                && paths
                    .iter()
                    .any(|p| p["priority"] == 4 && p["base_priority"] == 2 && p["rtt_ms"].is_f64())
        });
        if done {
            assert_eq!(last[0]["connections"][0]["info"]["sni"], HOST);
            assert_eq!(last[0]["connections"][0]["info"]["ech"], true);
            assert_eq!(http_get(endpoints[0], "/nope").await.0, 404);
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("unexpected stats: {last:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_congestion_control_never_limits_any_path() {
    let fx = Fixture::new("nocc");
    let config = quic::build_server_config(
        &fx.cert,
        &fx.key,
        None,
        vec![HOST.to_string()],
        transport(CongestionControl::None),
    )
    .unwrap();
    let socket = quic::bind_endpoint_socket("127.0.0.1:0".parse().unwrap()).unwrap();
    let server = Endpoint::new(
        quic::endpoint_config(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let _ = tx.send(conn.clone());
        conn.closed().await;
    });

    let verify = Verify::Roots {
        ca_file: Some(fx.cert.clone()),
    };
    let client_config =
        quic::build_client_config(&verify, None, transport(CongestionControl::None)).unwrap();
    let client = client_endpoint(true);
    let conn = client
        .connect_with(client_config, addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let server_conn = rx.await.unwrap();

    // A second path gets its own controller instance; it must be unbounded too.
    let tuple = FourTuple::new(addr, Some("127.0.0.2".parse().unwrap()));
    let mut second = None;
    for _ in 0..40 {
        if let Ok(p) = conn.open_path_ensure(tuple, PathStatus::Available).await {
            second = Some(p.id());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let second = second.expect("second path must open");

    for (side, c, path) in [
        ("client", &conn, noq::PathId::ZERO),
        ("client", &conn, second),
        ("server", &server_conn, noq::PathId::ZERO),
    ] {
        let window = c.congestion_state(path).expect("path exists").window();
        assert!(
            window > u64::from(u32::MAX),
            "{side} path {path}: window {window} must be unbounded"
        );
    }
}

/// A WireGuard tunnel with MTU 1280 needs 1318-byte HTTP datagrams (1280-byte
/// inner packet + 32 bytes of WireGuard framing + 2 bytes of flow/context
/// prefix + 4 bytes of sequence number). That must fit from the first packet, not only once DPLPMTUD has
/// probed the path.
#[tokio::test(flavor = "multi_thread")]
async fn wireguard_1280_fits_right_after_handshake() {
    let fx = Fixture::new("mtu");
    let server = fx.server(HOST);
    let addr = server.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let _ = tx.send(conn.max_datagram_size());
        conn.closed().await;
    });
    let client = client_endpoint(false);
    let conn = client
        .connect_with(fx.client_config(false), addr, HOST)
        .unwrap()
        .await
        .unwrap();
    let client_max = conn.max_datagram_size().unwrap();
    assert!(
        client_max >= WIREGUARD_1280_DATAGRAM,
        "client datagram room {client_max} < {WIREGUARD_1280_DATAGRAM}"
    );
    let server_max = rx.await.unwrap().unwrap();
    assert!(
        server_max >= WIREGUARD_1280_DATAGRAM,
        "server datagram room {server_max} < {WIREGUARD_1280_DATAGRAM}"
    );
}

/// An idle extra path must survive the 10 s per-path idle timeout (both ends
/// send per-path keepalives), and with several live paths a 1280-MTU
/// WireGuard datagram must still fit (noq sizes datagrams for the smallest
/// path MTU).
#[tokio::test(flavor = "multi_thread")]
async fn idle_extra_path_stays_up_and_fits_wireguard() {
    let fx = Fixture::new("mpidle");
    let config = quic::build_server_config(
        &fx.cert,
        &fx.key,
        None,
        vec![HOST.to_string()],
        transport(CongestionControl::Bbr3),
    )
    .unwrap();
    // Wildcard bind so the server answers on 127.0.0.2 too.
    let socket = quic::bind_endpoint_socket("0.0.0.0:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Endpoint::new(
        quic::endpoint_config(),
        Some(config),
        socket,
        Arc::new(TokioRuntime),
    )
    .unwrap();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        conn.closed().await;
    });

    let primary: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let client = client_endpoint(true);
    let conn = client
        .connect_with(fx.client_config(false), primary, HOST)
        .unwrap()
        .await
        .unwrap();
    let extra: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
    let mut path = None;
    for _ in 0..40 {
        if let Ok(p) = conn.open_path_ensure(extra, PathStatus::Available).await {
            path = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let path = path.expect("extra path must open");

    // Idle for longer than the path idle timeout.
    tokio::time::sleep(Duration::from_secs(13)).await;
    assert!(
        path.status().is_ok(),
        "idle extra path {} was abandoned",
        path.id()
    );
    let room = conn.max_datagram_size().unwrap();
    assert!(
        room >= WIREGUARD_1280_DATAGRAM,
        "datagram room {room} with two paths"
    );
}

/// With the primary proxy address dead, the client completes the handshake
/// over an extra path's proxy address and the tunnel works.
#[tokio::test(flavor = "multi_thread")]
async fn handshake_falls_back_to_an_extra_path() {
    let fx = Fixture::new("fallback");
    // A bound socket nobody reads: the primary path's handshake gets no answer.
    let blackhole = std::net::UdpSocket::bind("127.0.0.4:0").unwrap();
    let dead = blackhole.local_addr().unwrap();
    let tunnel = start_tunnel_with(
        &fx,
        TunnelConfig {
            paths: Box::new(|server| vec![format!("{server}/priority=1").parse().unwrap()]),
            primary_via: Some(Box::new(move |_| Box::pin(async move { dead }))),
            ..Default::default()
        },
    )
    .await;
    // The fallback waits 3 s for the primary; roundtrip() keeps trying for 10.
    tunnel.roundtrip().await;
    drop(blackhole);
}

/// The fixed-rate window for `rate` bits per second on a loopback path: the
/// 20 ms floor dominates two loopback round trips and four packets.
fn fixed_rate_window(rate: u64) -> u64 {
    rate / 8 / 50
}

/// The first path's `field` in a stats registry's only connection.
fn first_path_stat(registry: &stats::Registry, field: &str) -> serde_json::Value {
    registry.snapshot()["connections"][0]["paths"][0][field].clone()
}

/// `--primary-rate` sends the primary path at a fixed rate on the client, and
/// on the proxy too, capped to its `--max-path-rate`.
#[tokio::test(flavor = "multi_thread")]
async fn fixed_rate_path_applies_on_both_ends_up_to_the_proxy_cap() {
    let fx = Fixture::new("fixed-rate");
    let (server_stats, client_stats) = (
        stats::Registry::new("server"),
        stats::Registry::new("client"),
    );
    let tunnel = start_tunnel_with(
        &fx,
        TunnelConfig {
            server_stats: Some(server_stats.clone()),
            client_stats: Some(client_stats.clone()),
            primary_rate: Some(8_000_000),
            max_path_rate: Some(4_000_000),
            ..Default::default()
        },
    )
    .await;
    tunnel.roundtrip().await;

    let expected = [(&client_stats, 8_000_000u64), (&server_stats, 4_000_000u64)];
    for _ in 0..50 {
        let done = expected.iter().all(|(registry, rate)| {
            first_path_stat(registry, "fixed_rate_bps") == *rate
                && first_path_stat(registry, "cwnd") == fixed_rate_window(*rate)
        });
        if done {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "client path {:?}, server path {:?}",
        client_stats.snapshot()["connections"][0]["paths"][0],
        server_stats.snapshot()["connections"][0]["paths"][0]
    );
}

/// A relay in front of `upstream` that swaps every two consecutive packets
/// from `upstream` (a held packet goes out after 5 ms without a successor).
async fn swapping_relay(upstream: SocketAddr) -> SocketAddr {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut client = None;
        let mut held: Option<Vec<u8>> = None;
        loop {
            let received = if held.is_some() {
                match tokio::time::timeout(Duration::from_millis(5), sock.recv_from(&mut buf)).await
                {
                    Ok(r) => r,
                    Err(_) => {
                        if let (Some(packet), Some(c)) = (held.take(), client) {
                            let _ = sock.send_to(&packet, c).await;
                        }
                        continue;
                    }
                }
            } else {
                sock.recv_from(&mut buf).await
            };
            let Ok((n, from)) = received else { return };
            if from != upstream {
                client = Some(from);
                let _ = sock.send_to(&buf[..n], upstream).await;
                continue;
            }
            let Some(c) = client else { continue };
            match held.take() {
                None => held = Some(buf[..n].to_vec()),
                Some(first) => {
                    let _ = sock.send_to(&buf[..n], c).await;
                    let _ = sock.send_to(&first, c).await;
                }
            }
        }
    });
    addr
}

/// Send `count` numbered datagrams through the tunnel, paced 2 ms apart, and
/// return the order their echoes came back in.
async fn echo_order(tunnel: &Tunnel, count: u32) -> Vec<u32> {
    let app = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender = {
        let (app, listen) = (app.clone(), tunnel.listen);
        tokio::spawn(async move {
            for i in 0..count {
                let mut payload = i.to_be_bytes().to_vec();
                payload.resize(1000, 0);
                app.send_to(&payload, listen).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
    };
    let mut order = Vec::new();
    let mut buf = vec![0u8; 2048];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(500), app.recv(&mut buf)).await
    {
        assert!(n >= 9 && buf.starts_with(b"echo:"));
        order.push(u32::from_be_bytes(buf[5..9].try_into().unwrap()));
    }
    sender.await.unwrap();
    order
}

/// Datagrams reordered on the way back arrive in order with in-order delivery
/// (the default), and out of order without it.
#[tokio::test(flavor = "multi_thread")]
async fn in_order_delivery_undoes_reordering() {
    let fx = Fixture::new("in-order");
    let mut inversions = Vec::new();
    for in_order_delivery in [true, false] {
        let tunnel = start_tunnel_with(
            &fx,
            TunnelConfig {
                primary_via: Some(Box::new(|server| Box::pin(swapping_relay(server)))),
                in_order_delivery,
                ..Default::default()
            },
        )
        .await;
        tunnel.roundtrip().await;
        // Warm up: the hold time learns how late the relay's swaps are.
        echo_order(&tunnel, 50).await;
        let order = echo_order(&tunnel, 200).await;
        assert!(order.len() >= 190, "{} of 200 echoes", order.len());
        inversions.push(order.windows(2).filter(|w| w[1] < w[0]).count());
    }
    // A swap delayed beyond the learned hold time (a busy test machine) is
    // still delivered, late; allow a couple.
    assert!(
        inversions[0] <= 2,
        "reordered with in-order delivery: {inversions:?}"
    );
    assert!(
        inversions[1] > 20,
        "the relay did not reorder: {inversions:?}"
    );
}
