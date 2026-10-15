//! noq transport + BoringSSL TLS configuration shared by the proxy server and
//! client.
//!
//! Both ends build a `boring::ssl::SslContextBuilder` first — that is where ECH
//! keys (server) and trust roots (client) are installed, exactly as in
//! zeromasque — then hand it to the BoringSSL-for-noq backend in `crate::tls`.
//! The QUIC transport negotiates the multipath extension; outer congestion
//! control is selectable (BBRv3 by default, or none; see `crate::cc`).

use std::net::{Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use boring::ssl::{
    NameType, SelectCertError, SslContextBuilder, SslEchKeys, SslMethod, SslVerifyMode, SslVersion,
};
use noq::{EndpointConfig, IdleTimeout, TransportConfig, VarInt};

use crate::cc::CongestionControl;
use crate::ech::key::EchKeySet;
use crate::tls::{self, ClientTls, ServerTls};

/// Structured-field value `?1` (Boolean true) for the `capsule-protocol` header
/// carried on every CONNECT-UDP request and response.
pub(crate) const CAPSULE_PROTOCOL_TRUE: &str = "?1";

/// Connection (and per-path) idle timeout: a dead path or peer is detected
/// within this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Keepalive cadence. The client pings the connection and every path; the
/// server pings every path too (see `transport_config`). Keeps NAT mappings
/// warm and lets a dead path be detected quickly.
const KEEPALIVE: Duration = Duration::from_secs(1);
/// Upper bound on concurrently open multipath paths, per connection.
pub(crate) const MAX_PATHS: u32 = 8;
/// Bytes of outgoing/incoming QUIC DATAGRAMs buffered inside noq. When the
/// send buffer is full, noq drops the oldest datagram (UDP is lossy by
/// contract).
const DGRAM_SEND_BUFFER: usize = 4 * 1024 * 1024;
const DGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;

/// HTTP datagram size for a full-size packet of a 1280-MTU WireGuard tunnel: a
/// 1280-byte inner packet inside WireGuard is a 1312-byte UDP payload (16B
/// header + 16B tag), plus our 2B HTTP-datagram prefix (quarter-stream ID +
/// context ID) = 1314B. It must fit in one QUIC DATAGRAM frame, which cannot
/// be fragmented.
pub(crate) const WIREGUARD_1280_DATAGRAM: usize = 1280 + 32 + 2;

/// noq's per-packet bound on DATAGRAM overhead (`Datagrams::max_size`): flags
/// byte (1) + destination CID (8, noq's default CID length, which every
/// rapidmasque peer issues) + packet number (4, noq's conservative bound) +
/// AEAD tag (16) + DATAGRAM frame type and length bound (9). Against a peer
/// that issues longer CIDs (up to 20 bytes) the room shrinks accordingly.
const DATAGRAM_OVERHEAD: usize = 1 + 8 + 4 + 16 + 9;

/// Initial and minimum outer (client<->proxy) QUIC packet size, i.e. UDP
/// payload bytes: exactly what a 1280-MTU WireGuard packet needs (1352).
/// noq's default of 1200 leaves only 1162B, so until DPLPMTUD had probed the
/// path upward (and indefinitely where probing never succeeds) every
/// full-size packet would be dropped. It is also the floor: DPLPMTUD may raise
/// the size (up to 1452) but its black-hole detection never lowers it below
/// this, because shrinking would silently stop the tunnel from carrying
/// full-size inner packets. The client<->proxy path must therefore carry
/// 1380-byte IPv4 / 1400-byte IPv6 packets; on a path that cannot, large
/// packets are lost rather than the tunnel narrowing.
const INITIAL_MTU: u16 = (WIREGUARD_1280_DATAGRAM + DATAGRAM_OVERHEAD) as u16;
const _: () = assert!(INITIAL_MTU == 1352);

/// Size requested (per direction) for every UDP socket's kernel buffers.
///
/// The whole tunnel is one QUIC connection; on a high-RTT path its
/// bandwidth-delay product is large (e.g. 20 Mbit/s × 270 ms ≈ 675 KB). The
/// default socket buffer (~208 KB on stock Linux) is far smaller, so an
/// in-flight burst overflows it and packets are dropped. Because CONNECT-UDP
/// rides *unreliable* QUIC DATAGRAMs (no retransmission), every such drop
/// surfaces as loss to the tunnelled protocol — and at high RTT even a few
/// percent loss collapses an inner TCP flow (Mathis: BW ≈ MSS/(RTT·√p)). Sizing
/// the buffers to absorb the BDP is the single biggest throughput lever.
///
/// NOTE: the kernel clamps the effective size to `net.core.rmem_max` /
/// `wmem_max`. On stock Linux those default to ~208 KB, which would silently cap
/// this request — operators on high-RTT links must raise them (see README).
const SOCKET_BUFFER_BYTES: libc::c_int = 8 * 1024 * 1024;

/// Set a C-`int`-valued socket option via `setsockopt(2)`. Shared by the buffer
/// sizing, `SO_MARK`, and `IP_TRANSPARENT` paths.
pub(crate) fn set_sockopt_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enlarge a UDP socket's send and receive buffers to [`SOCKET_BUFFER_BYTES`]
/// (best effort; failures are logged, not fatal). Call right after binding.
pub(crate) fn enlarge_udp_buffers(sock: &impl std::os::fd::AsRawFd) {
    let fd = sock.as_raw_fd();
    for (opt, name) in [
        (libc::SO_RCVBUF, "SO_RCVBUF"),
        (libc::SO_SNDBUF, "SO_SNDBUF"),
    ] {
        if let Err(e) = set_sockopt_int(fd, libc::SOL_SOCKET, opt, SOCKET_BUFFER_BYTES) {
            log::debug!("setsockopt {name} failed: {e}");
        }
    }
}

/// Bind the UDP socket a noq endpoint runs on, with enlarged buffers. An
/// unspecified IPv6 address is bound dual-stack so multipath can mix IPv4 and
/// IPv6 paths on one endpoint.
pub(crate) fn bind_endpoint_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("creating UDP socket for {addr}"))?;
    if let SocketAddr::V6(v6) = addr
        && v6.ip().is_unspecified()
    {
        let _ = sock.set_only_v6(false);
    }
    enlarge_udp_buffers(&sock);
    sock.bind(&addr.into())
        .with_context(|| format!("binding UDP {addr}"))?;
    Ok(sock.into())
}

/// The unspecified address to bind a client endpoint on. With extra multipath
/// paths configured this is dual-stack `[::]:0` (falling back to the primary
/// family if IPv6 is unavailable).
pub(crate) fn client_bind_socket(
    primary: SocketAddr,
    dual_stack: bool,
) -> Result<std::net::UdpSocket> {
    if dual_stack && let Ok(s) = bind_endpoint_socket((Ipv6Addr::UNSPECIFIED, 0).into()) {
        return Ok(s);
    }
    let bind: SocketAddr = if primary.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    bind_endpoint_socket(bind)
}

/// Endpoint-level config: QUIC v1 only (the BoringSSL backend's version).
pub(crate) fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.supported_versions(vec![tls::QUIC_V1]);
    config
}

/// The QUIC transport parameters common to client and server.
fn transport_config(keepalive: bool, cc: CongestionControl) -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    let idle = IdleTimeout::try_from(IDLE_TIMEOUT).expect("idle timeout fits a varint");
    t.max_idle_timeout(Some(idle));
    // The whole tunnel is one QUIC connection and every UDP payload rides an
    // (unreliable but still congestion-controlled — RFC 9221 §5) DATAGRAM frame.
    // A loss-based controller (CUBIC/NewReno) is a poor outer controller for a
    // tunnel over a high-RTT, sporadically-lossy path: it treats any loss as
    // congestion and backs off multiplicatively, so path loss collapses the
    // tunnel. BBRv3 (the default) is rate/model-based and tolerates
    // non-congestive loss; with multipath, noq runs one instance per path.
    // `none` drops outer congestion control entirely, for payloads that are
    // already congestion-controlled end to end (see `crate::cc`).
    t.congestion_controller_factory(cc.factory());
    // Multipath (draft-ietf-quic-multipath): both ends advertise support, so
    // the client may open extra paths (other local interfaces / server
    // addresses) and noq schedules datagrams across them.
    t.max_concurrent_multipath_paths(MAX_PATHS);
    t.default_path_max_idle_timeout(Some(IDLE_TIMEOUT));
    // Each path is abandoned after IDLE_TIMEOUT without receiving anything on
    // it, so both ends must keep every path busy: ACKs for one path may travel
    // on another (the lowest-numbered usable one), so a peer that only answers
    // would leave the other side's extra paths silent, and they would time out
    // and churn every ~10 s on an idle tunnel even though the links are fine.
    t.default_path_keep_alive_interval(Some(KEEPALIVE));
    if keepalive {
        t.keep_alive_interval(Some(KEEPALIVE));
    }
    t.receive_window(VarInt::from_u32(10_000_000));
    t.stream_receive_window(VarInt::from_u32(2_000_000));
    t.max_concurrent_bidi_streams(VarInt::from_u32(128));
    t.max_concurrent_uni_streams(VarInt::from_u32(128));
    // HTTP/3 datagrams ride on QUIC DATAGRAM frames, which cannot be
    // fragmented, so a tunnelled packet must fit one QUIC packet. Start at
    // INITIAL_MTU and never go below it; noq's DPLPMTUD (enabled by default,
    // probing up to 1452 bytes) can raise it further.
    t.initial_mtu(INITIAL_MTU);
    t.min_mtu(INITIAL_MTU);
    t.datagram_receive_buffer_size(Some(DGRAM_RECV_BUFFER));
    t.datagram_send_buffer_size(DGRAM_SEND_BUFFER);
    Arc::new(t)
}

/// Install ECH keys (server-side termination) onto a context builder. Each pair
/// is advertised as a retry config so stale clients are sent fresh configs.
pub(crate) fn install_ech_keys(builder: &mut SslContextBuilder, ech: &EchKeySet) -> Result<()> {
    let mut keys = SslEchKeys::builder().map_err(|e| anyhow!("SSL_ECH_KEYS_new failed: {e}"))?;
    for pair in &ech.pairs {
        // BoringSSL's only X25519 HPKE constructor is misnamed `dhkem_p256...`;
        // its body uses EVP_hpke_x25519_hkdf_sha256, matching our keygen suite.
        let key = boring::hpke::HpkeKey::dhkem_p256_sha256(&pair.private_key).map_err(|e| {
            anyhow!(
                "invalid ECH HPKE key (config_id 0x{:02x}): {e}",
                pair.config.config_id
            )
        })?;
        keys.add_key(true, &pair.config.encode(), key)
            .map_err(|e| {
                anyhow!(
                    "SSL_ECH_KEYS_add failed (config_id 0x{:02x}): {e}",
                    pair.config.config_id
                )
            })?;
    }
    builder
        .set_ech_keys(&keys.build())
        .map_err(|e| anyhow!("SSL_CTX_set1_ech_keys failed: {e}"))?;
    Ok(())
}

/// Reject handshakes whose ClientHello SNI is missing or not one of the
/// configured proxy endpoint hosts. With ECH accepted, BoringSSL exposes the
/// protected inner SNI here; without ECH this checks the ordinary SNI.
pub(crate) fn install_sni_guard(builder: &mut SslContextBuilder, allowed_hosts: Vec<String>) {
    builder.set_select_certificate_callback(move |client_hello| {
        let Some(sni) = client_hello.servername(NameType::HOST_NAME) else {
            log::debug!("rejecting TLS ClientHello without SNI");
            return Err(SelectCertError::ERROR);
        };
        if allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(sni)) {
            return Ok(());
        }
        log::debug!("rejecting TLS ClientHello with unmatched SNI {sni:?}");
        Err(SelectCertError::ERROR)
    });
}

/// Build the server-side noq config from a cert/key PEM pair, optionally
/// terminating ECH with the supplied key set.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    ech: Option<&EchKeySet>,
    allowed_sni_hosts: Vec<String>,
    cc: CongestionControl,
) -> Result<noq::ServerConfig> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).context("creating BoringSSL server context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("min TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("max TLS version")?;
    builder
        .set_certificate_chain_file(cert_path)
        .with_context(|| format!("loading cert chain {}", cert_path.display()))?;
    builder
        .set_private_key_file(key_path, boring::ssl::SslFiletype::PEM)
        .with_context(|| format!("loading private key {}", key_path.display()))?;
    builder.check_private_key().with_context(|| {
        format!(
            "certificate/key mismatch: {} and {}",
            cert_path.display(),
            key_path.display()
        )
    })?;
    if let Some(ech) = ech {
        install_ech_keys(&mut builder, ech)?;
    }
    install_sni_guard(&mut builder, allowed_sni_hosts);

    let mut config = noq::ServerConfig::with_crypto(ServerTls::new(builder)?);
    config.transport_config(transport_config(false, cc));
    Ok(config)
}

/// Common system CA bundle locations, in probe order. BoringSSL's compiled-in
/// default paths are unreliable across distros, so we also look here.
const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
    "/etc/ssl/cert.pem",                  // BSD/macOS (Homebrew)/some musl
    "/etc/ssl/ca-bundle.pem",             // openSUSE
];

/// Load system trust anchors into the client context (best effort): BoringSSL's
/// compiled-in default paths plus the first known CA bundle that exists.
fn load_system_roots(builder: &mut SslContextBuilder) {
    let _ = builder.set_default_verify_paths();
    for path in CA_BUNDLE_PATHS {
        if std::path::Path::new(path).exists() && builder.set_ca_file(path).is_ok() {
            log::debug!("loaded system CA bundle {path}");
            return;
        }
    }
    log::warn!(
        "no system CA bundle found ({CA_BUNDLE_PATHS:?}); server certificate \
         verification may fail (use --ca or --insecure)"
    );
}

/// How the client verifies the proxy's certificate.
pub enum Verify {
    /// Verify against the system trust store plus an optional extra CA file.
    Roots { ca_file: Option<std::path::PathBuf> },
    /// Skip verification (testing only).
    Insecure,
}

/// Build the client-side noq config. When `ech_config_list` is set, the client
/// offers Encrypted Client Hello on every connection.
pub fn build_client_config(
    verify: &Verify,
    ech_config_list: Option<Vec<u8>>,
    cc: CongestionControl,
) -> Result<noq::ClientConfig> {
    let mut builder =
        SslContextBuilder::new(SslMethod::tls()).context("creating BoringSSL client context")?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("min TLS version")?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("max TLS version")?;

    let verify_peer = match verify {
        Verify::Insecure => {
            builder.set_verify(SslVerifyMode::NONE);
            false
        }
        Verify::Roots { ca_file } => {
            builder.set_verify(SslVerifyMode::PEER);
            // BoringSSL's trust store starts empty, so without this every real
            // server certificate fails to verify. Load the system trust anchors.
            load_system_roots(&mut builder);
            if let Some(ca) = ca_file {
                builder
                    .set_ca_file(ca)
                    .with_context(|| format!("loading CA file {}", ca.display()))?;
            }
            true
        }
    };

    let mut config = noq::ClientConfig::new(ClientTls::new(builder, verify_peer, ech_config_list)?);
    config.transport_config(transport_config(true, cc));
    Ok(config)
}

/// Install a client-side ECH offering as a handshake-start info callback on a
/// context. The live client offers ECH directly on each `SSL` (see
/// `tls::ClientTls`); this context-level variant serves plain BoringSSL
/// connectors such as the in-memory ECH test.
#[cfg(test)]
pub(crate) fn install_client_ech(builder: &mut SslContextBuilder, list: Vec<u8>) {
    use boring::ssl::{SslInfoCallbackMode, SslRef};
    use foreign_types_shared::ForeignTypeRef;
    builder.set_info_callback(move |ssl: &SslRef, mode: SslInfoCallbackMode, _| {
        if mode == SslInfoCallbackMode::HANDSHAKE_START {
            // Reconstruct a &mut SslRef from the live pointer to offer ECH.
            // Sound here: the callback holds the only reference to this SSL
            // during the call.
            let ssl_mut = unsafe { SslRef::from_ptr_mut(ssl.as_ptr()) };
            if let Err(e) = tls::offer_ech(ssl_mut, &list) {
                log::warn!("failed to install client ECH config list: {e}");
            }
        }
    });
}

/// Log multipath path lifecycle events for a connection. Returns when the
/// connection closes (the event stream alone would never end while this task
/// holds a `Connection` handle).
pub(crate) async fn log_path_events(conn: noq::Connection) {
    use tokio_stream::StreamExt;
    let mut events = conn.path_events();
    let id = conn.stable_id();
    loop {
        let ev = tokio::select! {
            ev = events.next() => ev,
            _ = conn.closed() => return,
        };
        match ev {
            None => return,
            Some(Ok(noq::PathEvent::Established { id: path, .. })) => {
                let remote = conn.path(path).and_then(|p| p.remote_address().ok());
                log::info!("connection {id}: path {path} established ({remote:?})");
            }
            Some(Ok(noq::PathEvent::Abandoned {
                id: path, reason, ..
            })) => {
                log::info!("connection {id}: path {path} abandoned ({reason:?})");
            }
            Some(Ok(other)) => log::debug!("connection {id}: {other:?}"),
            Some(Err(e)) => log::debug!("connection {id}: path events lagged: {e}"),
        }
    }
}

/// Queue an HTTP datagram on the connection. Returns `false` once the
/// connection is gone. Oversize datagrams are dropped with a warning: QUIC
/// DATAGRAMs cannot be fragmented.
pub(crate) fn send_datagram(
    conn: &noq::Connection,
    flow_id: u64,
    datagram: bytes::Bytes,
    what: &str,
) -> bool {
    let len = datagram.len();
    match conn.send_datagram(datagram) {
        Ok(()) => true,
        Err(noq::SendDatagramError::TooLarge) => {
            log::warn!(
                "dropping {len}-byte {what} datagram on flow {flow_id}: exceeds writable QUIC \
                 datagram ({:?}B). The payload is too large for the client<->proxy path MTU; \
                 QUIC DATAGRAMs cannot fragment. Lower the tunnelled interface MTU or ensure \
                 the proxy path carries larger packets.",
                conn.max_datagram_size(),
            );
            true
        }
        Err(noq::SendDatagramError::ConnectionLost(_)) => false,
        Err(e) => {
            log::debug!("send_datagram failed: {e}");
            true
        }
    }
}
