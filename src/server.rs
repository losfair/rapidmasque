//! CONNECT-UDP proxy (RFC 9298) over tokio + noq.
//!
//! Every accepted QUIC connection gets its own task. Each CONNECT-UDP request
//! (one HTTP/3 request stream) becomes a flow task that owns the target UDP
//! socket; client→target datagrams are dispatched to flows through bounded
//! channels by a per-connection datagram reader. The forwarding target is
//! pinned by the server's rule table — clients never choose it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use bytes::Bytes;
use noq::{Connection, Endpoint, Incoming, RecvStream, SendStream};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::dgram;
use crate::h3::{self, FrameReader};
use crate::quic::{self, CAPSULE_PROTOCOL_TRUE};
use crate::rules::RuleTable;
use crate::tls::HandshakeData;
use crate::util::{CHANNEL_CAP, RECV_BUF};

/// HTTP/3 error code used to reset an idle flow's request stream.
const FLOW_IDLE_ERROR: u32 = 0x100; // H3_NO_ERROR

/// Hot-reloadable server state. The reload task swaps the endpoint's TLS config
/// (rotated certificates / ECH keys) and this rule table; new connections and
/// requests pick up the new values, while live connections keep the TLS state
/// they handshook with.
pub struct ServerState {
    pub rules: ArcSwap<RuleTable>,
}

/// Client→target side of one active flow, as seen by the datagram dispatcher.
struct FlowHandle {
    to_target: mpsc::Sender<Bytes>,
    activity: Arc<Activity>,
}

type FlowMap = Arc<Mutex<HashMap<u64, FlowHandle>>>;

/// Last time a datagram crossed a flow in either direction.
struct Activity {
    epoch: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let ms = self.epoch.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.epoch + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

/// Accept connections until the endpoint is closed.
pub async fn run(endpoint: Endpoint, state: Arc<ServerState>) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let from = incoming.remote_address();
            if let Err(e) = handle_connection(incoming, state).await {
                log::debug!("connection from {from} ended: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(incoming: Incoming, state: Arc<ServerState>) -> Result<()> {
    let from = incoming.remote_address();
    let conn = incoming.await.context("QUIC handshake")?;
    let hs = conn
        .handshake_data()
        .and_then(|d| d.downcast::<HandshakeData>().ok());
    log::info!(
        "new QUIC connection from {from} (id={}, sni={:?}, ech={}, multipath={})",
        conn.stable_id(),
        hs.as_ref().and_then(|h| h.server_name.clone()),
        hs.as_ref().is_some_and(|h| h.ech_accepted),
        conn.is_multipath_enabled(),
    );

    // Our control stream must stay open for the connection's lifetime.
    let _control = h3::open_control(&conn).await?;
    tokio::spawn(h3::serve_uni_streams(conn.clone()));
    tokio::spawn(quic::log_path_events(conn.clone()));

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(dispatch_datagrams(conn.clone(), flows.clone()));

    // The client's external (handshake path) address — the preserved source
    // for transparent rules.
    let client_addr = from;
    let reason = loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_request(
                    conn.clone(),
                    send,
                    recv,
                    state.clone(),
                    flows.clone(),
                    client_addr,
                ));
            }
            Err(e) => break e,
        }
    };
    log::info!(
        "connection closed (id={}, {from}): {reason}",
        conn.stable_id()
    );
    Ok(())
}

/// Forward client→target datagrams to their flow tasks.
async fn dispatch_datagrams(conn: Connection, flows: FlowMap) {
    while let Ok(datagram) = conn.read_datagram().await {
        let Some(parsed) = dgram::decode(&datagram) else {
            continue;
        };
        if parsed.context_id != dgram::CONTEXT_ID_UDP {
            continue; // only raw UDP payloads are supported
        }
        let flows = flows.lock().unwrap();
        match flows.get(&parsed.flow_id) {
            Some(flow) => {
                log::debug!(
                    "client datagram flow {} -> target: {} bytes",
                    parsed.flow_id,
                    parsed.payload.len()
                );
                // Drop on full: UDP is lossy by contract.
                let payload = datagram.slice_ref(parsed.payload);
                let _ = flow.to_target.try_send(payload);
                // Client→target traffic keeps the flow alive.
                flow.activity.touch();
            }
            None => log::debug!("no flow for client datagram flow_id {}", parsed.flow_id),
        }
    }
}

/// Serve one CONNECT-UDP request stream: validate, match a rule, open the
/// target socket, answer 200, then relay until the flow ends.
async fn handle_request(
    conn: Connection,
    mut send: SendStream,
    recv: RecvStream,
    state: Arc<ServerState>,
    flows: FlowMap,
    client_addr: SocketAddr,
) {
    let flow_id = u64::from(recv.id()) / 4;
    let mut reader = FrameReader::new(recv);
    let fields = match reader.read_headers().await {
        Ok(Some(fields)) => fields,
        Ok(None) => return,
        Err(e) => {
            log::debug!("flow {flow_id}: bad request: {e:#}");
            respond_status(&mut send, 400).await;
            return;
        }
    };
    let req = match ConnectRequest::parse(&fields) {
        Ok(req) => req,
        Err(status) => {
            respond_status(&mut send, status).await;
            return;
        }
    };

    // Look up the forwarding rule for this request's authority + path. The
    // client never selects a destination.
    let Some(rule) = state.rules.load().match_target(&req.authority, &req.path) else {
        log::debug!(
            "no rule for authority {:?} path {:?}",
            req.authority,
            req.path
        );
        respond_status(&mut send, 404).await;
        return;
    };

    let target = match bind_target(rule.target, client_addr, rule.transparent, rule.fwmark) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("failed to open target socket for {}: {e:#}", rule.target);
            respond_status(&mut send, 502).await;
            return;
        }
    };

    let (to_target_tx, to_target_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
    let activity = Arc::new(Activity::new());
    flows.lock().unwrap().insert(
        flow_id,
        FlowHandle {
            to_target: to_target_tx,
            activity: activity.clone(),
        },
    );

    let mut extra = String::new();
    if rule.transparent {
        extra.push_str(&format!(" transparent src {}", client_addr.ip()));
    }
    if let Some(mark) = rule.fwmark {
        extra.push_str(&format!(" fwmark {mark}"));
    }
    log::info!("CONNECT-UDP flow {flow_id} -> {}{extra}", rule.target);

    // Keep the stream open (no FIN) so datagrams keep flowing.
    let response = h3::headers_frame(&[
        (":status", "200"),
        ("capsule-protocol", CAPSULE_PROTOCOL_TRUE),
    ]);
    if let Err(e) = send.write_all(&response).await {
        log::warn!("failed to send CONNECT-UDP 200 response: {e}");
    } else {
        relay_flow(
            &conn,
            flow_id,
            &target,
            to_target_rx,
            &mut send,
            &mut reader,
            &activity,
            rule.idle_timeout,
        )
        .await;
    }
    flows.lock().unwrap().remove(&flow_id);
}

/// Relay one flow until the client closes its request stream, the connection
/// dies, or the flow idles out (which resets the stream so the client frees it
/// and reopens lazily on its next datagram).
#[allow(clippy::too_many_arguments)]
async fn relay_flow(
    conn: &Connection,
    flow_id: u64,
    target: &UdpSocket,
    mut from_client: mpsc::Receiver<Bytes>,
    send: &mut SendStream,
    reader: &mut FrameReader,
    activity: &Activity,
    idle_timeout: Option<Duration>,
) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let deadline = idle_timeout.map(|d| activity.last() + d);
        tokio::select! {
            maybe = from_client.recv() => {
                let Some(payload) = maybe else { break };
                if let Err(e) = target.send(&payload).await {
                    log::debug!("send to target failed: {e}");
                }
            }
            r = target.recv(&mut buf) => match r {
                Ok(n) => {
                    activity.touch();
                    let datagram = Bytes::from(dgram::encode(flow_id, &buf[..n]));
                    if !quic::send_datagram(conn, flow_id, datagram, "reply") {
                        break;
                    }
                }
                Err(e) => {
                    log::debug!("recv from target failed: {e}");
                    break;
                }
            },
            _ = reader.drain() => break, // client closed / reset the flow
            _ = sleep_until_opt(deadline) => {
                if activity.last() + idle_timeout.unwrap() <= Instant::now() {
                    let code = noq::VarInt::from_u32(FLOW_IDLE_ERROR);
                    let _ = send.reset(code);
                    reader.stop(FLOW_IDLE_ERROR);
                    log::info!("flow {flow_id} idle-timed-out; closed");
                    break;
                }
            }
        }
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Parsed pseudo-headers of a CONNECT-UDP request.
struct ConnectRequest {
    authority: String,
    path: String,
}

impl ConnectRequest {
    /// Validate the request line; on failure return the HTTP status to reply.
    fn parse(fields: &[crate::qpack::Field]) -> std::result::Result<Self, u16> {
        if h3::header(fields, ":method") != Some(b"CONNECT") {
            return Err(405);
        }
        if h3::header(fields, ":protocol") != Some(b"connect-udp") {
            return Err(501);
        }
        let text = |name| {
            h3::header(fields, name)
                .and_then(|v| std::str::from_utf8(v).ok())
                .map(str::to_owned)
                .ok_or(400u16)
        };
        Ok(Self {
            authority: text(":authority")?,
            path: text(":path")?,
        })
    }
}

/// Answer a request with a bare status and close the stream.
async fn respond_status(send: &mut SendStream, status: u16) {
    let status = status.to_string();
    let frame = h3::headers_frame(&[(":status", &status)]);
    if let Err(e) = send.write_all(&frame).await {
        log::debug!("failed to send error status {status}: {e}");
    }
    let _ = send.finish();
}

/// Open the UDP socket used to relay one flow to its target. In transparent mode
/// (Linux only) the socket forwards with the client's external source IP
/// preserved via `IP_TRANSPARENT`; otherwise it uses an ephemeral local source.
/// `fwmark`, when set, applies `SO_MARK` for policy routing (Linux only).
fn bind_target(
    target: SocketAddr,
    client_addr: SocketAddr,
    transparent: bool,
    fwmark: Option<u32>,
) -> Result<UdpSocket> {
    if transparent {
        return bind_target_transparent(target, client_addr, fwmark);
    }
    #[cfg(not(target_os = "linux"))]
    if fwmark.is_some() {
        bail!("fwmark is only supported on Linux");
    }
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    // Connect with std (synchronous, non-blocking for datagram sockets) so the
    // socket has a fixed peer, then adopt it into tokio.
    let std_sock = std::net::UdpSocket::bind(bind).context("binding target UDP socket")?;
    quic::enlarge_udp_buffers(&std_sock);
    #[cfg(target_os = "linux")]
    if let Some(mark) = fwmark {
        use std::os::fd::AsRawFd;
        set_so_mark(std_sock.as_raw_fd(), mark)
            .with_context(|| format!("setting fwmark {mark} (needs CAP_NET_ADMIN)"))?;
    }
    std_sock
        .connect(target)
        .context("connecting target socket")?;
    std_sock
        .set_nonblocking(true)
        .context("set target nonblocking")?;
    UdpSocket::from_std(std_sock).context("adopting target socket into tokio")
}

/// Set `SO_MARK` (fwmark) on a socket. Requires `CAP_NET_ADMIN`.
#[cfg(target_os = "linux")]
fn set_so_mark(fd: std::os::fd::RawFd, mark: u32) -> std::io::Result<()> {
    quic::set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int)
}

/// Transparent forwarding: send to `target` with the client's external source IP
/// preserved (`IP_TRANSPARENT`). Tries the client's exact `ip:port`, falling back
/// to an ephemeral port on that IP if it's already in use (a client multiplexes
/// many flows over one QUIC address). Requires `CAP_NET_ADMIN`; the operator must
/// also route the target's replies (to the spoofed source) back to the proxy,
/// which is straightforward for a local target.
#[cfg(target_os = "linux")]
fn bind_target_transparent(
    target: SocketAddr,
    client_addr: SocketAddr,
    fwmark: Option<u32>,
) -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::fd::AsRawFd;

    // Source and target must share an address family. Canonicalise so an
    // IPv4-mapped IPv6 client address (dual-stack listener) compares as IPv4.
    let src_ip = client_addr.ip().to_canonical();
    let (domain, is_v6) = match (src_ip.is_ipv4(), target.is_ipv4()) {
        (true, true) => (Domain::IPV4, false),
        (false, false) => (Domain::IPV6, true),
        _ => bail!(
            "transparent rule: client {client_addr} and target {target} address families differ"
        ),
    };

    let make = |src: SocketAddr| -> std::io::Result<Socket> {
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        quic::enlarge_udp_buffers(&sock);
        // IP_TRANSPARENT must be set before bind; it requires CAP_NET_ADMIN.
        let (level, optname) = if is_v6 {
            (libc::SOL_IPV6, libc::IPV6_TRANSPARENT)
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT)
        };
        quic::set_sockopt_int(sock.as_raw_fd(), level, optname, 1)?;
        if let Some(mark) = fwmark {
            set_so_mark(sock.as_raw_fd(), mark)?;
        }
        sock.set_reuse_address(true)?;
        sock.bind(&src.into())?;
        sock.connect(&target.into())?;
        sock.set_nonblocking(true)?;
        Ok(sock)
    };

    let exact = SocketAddr::new(src_ip, client_addr.port());
    let sock = match make(exact) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            log::debug!("transparent source {exact} busy; using ephemeral port");
            make(SocketAddr::new(src_ip, 0)).map_err(|e| {
                anyhow!("transparent bind to {src_ip} failed: {e} (needs CAP_NET_ADMIN)")
            })?
        }
        Err(e) => {
            return Err(anyhow!(
                "transparent bind to {exact} failed: {e} (transparent rules need CAP_NET_ADMIN)"
            ));
        }
    };

    UdpSocket::from_std(sock.into()).context("adopting transparent target socket into tokio")
}

#[cfg(not(target_os = "linux"))]
fn bind_target_transparent(
    _target: SocketAddr,
    _client_addr: SocketAddr,
    _fwmark: Option<u32>,
) -> Result<UdpSocket> {
    bail!("transparent proxy mode (transparent rules) is only supported on Linux")
}
