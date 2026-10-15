//! In-process end-to-end tests over real noq connections on loopback: the
//! BoringSSL backend (with certificate verification against a test CA), ECH
//! acceptance observed on both peers, the SNI guard, QUIC multipath, and the
//! full client → server → UDP target tunnel.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use noq::{Endpoint, FourTuple, PathStatus, TokioRuntime};
use tokio::net::UdpSocket;

use crate::cc::CongestionControl;
use crate::client::{self, ConnectParams, PathSpec, ProxyOptions};
use crate::ech::key::EchKeySet;
use crate::ech_test::{ech_config_list_and_key_set, self_signed};
use crate::endpoint::Endpoint as ProxyEndpoint;
use crate::quic::{self, Verify};
use crate::rules::RuleTable;
use crate::server::{self, ServerState};
use crate::tls::HandshakeData;

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
            CongestionControl::Bbr3,
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
            CongestionControl::Bbr3,
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn client_endpoint(dual_stack: bool) -> Endpoint {
    let socket = quic::client_bind_socket("127.0.0.1:1".parse().unwrap(), dual_stack).unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_roundtrip_with_ech_and_multipath() {
    let fx = Fixture::new("tunnel");
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
        CongestionControl::None,
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
    });
    tokio::spawn(server::run(endpoint, state));

    // Client: a local UDP proxy with ECH and an extra multipath path.
    let listen = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap()
    };
    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let opts = ProxyOptions {
        conn: ConnectParams {
            endpoint: ProxyEndpoint::parse(&format!("https://{HOST}:{port}/connect")).unwrap(),
            proxy_addr: Some(proxy_addr),
            verify: Verify::Roots {
                ca_file: Some(fx.cert.clone()),
            },
            ech_config_list: Some(fx.ech_list.clone()),
            paths: vec![
                format!("{proxy_addr}@127.0.0.2")
                    .parse::<PathSpec>()
                    .unwrap(),
            ],
            congestion_control: CongestionControl::None,
        },
        listen,
    };
    tokio::spawn(client::run_proxy(opts));

    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 2048];
    for attempt in 0..50 {
        app.send_to(format!("hello {attempt}").as_bytes(), listen)
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

#[tokio::test(flavor = "multi_thread")]
async fn no_congestion_control_never_limits_any_path() {
    let fx = Fixture::new("nocc");
    let config = quic::build_server_config(
        &fx.cert,
        &fx.key,
        None,
        vec![HOST.to_string()],
        CongestionControl::None,
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
    let client_config = quic::build_client_config(&verify, None, CongestionControl::None).unwrap();
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

/// A WireGuard tunnel with MTU 1280 needs 1314-byte HTTP datagrams (1280-byte
/// inner packet + 32 bytes of WireGuard framing + 2 bytes of flow/context
/// prefix). That must fit from the first packet, not only once DPLPMTUD has
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
    const WIREGUARD_1280_DATAGRAM: usize = 1280 + 32 + 2;
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
        CongestionControl::Bbr3,
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
    assert!(room >= 1280 + 32 + 2, "datagram room {room} with two paths");
}
