//! MASQUE CONNECT-UDP client (RFC 9298) over tokio + noq.
//!
//! Opens a QUIC/HTTP3 connection to the proxy and issues Extended CONNECT
//! requests, tunnelling UDP payloads as HTTP datagrams. [`run_proxy`] binds a
//! local UDP socket and acts as a UDP→CONNECT-UDP proxy, opening one flow per
//! local source address and relaying both directions. Extra QUIC multipath
//! paths (other local interfaces and/or proxy addresses) can be attached to the
//! tunnel; noq then schedules datagrams across every live path, preferring
//! paths with a lower `/priority=N`.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use noq::{Connection, Endpoint, FourTuple, PathId, PathStatus, TokioRuntime};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::dgram;
use crate::endpoint::Endpoint as ProxyEndpoint;
use crate::h3::{self, FrameReader};
use crate::quic::{self, CAPSULE_PROTOCOL_TRUE, TransportOptions, Verify, send_datagram};
use crate::ranking::{self, PathPriorities, PathRanking, RankingConfig};
use crate::reorder::Reorder;
use crate::routed_socket;
use crate::stats;
use crate::tls::HandshakeData;
use crate::util::{CHANNEL_CAP, RECV_BUF, hex};

/// Per-source bound on datagrams buffered before the flow's request is
/// answered.
const MAX_PENDING: usize = 32;
/// Reconnect backoff bounds. The client never gives up; it keeps redialing the
/// proxy, backing off on repeated failures and resetting once a tunnel comes up.
const RECONNECT_MIN: Duration = Duration::from_millis(100);
const RECONNECT_MAX: Duration = Duration::from_secs(5);
/// Re-open cadence for a configured multipath path that is down: starts at
/// `PATH_RETRY_MIN`, backs off to `PATH_RETRY` (also the health-check period
/// for a path that is up).
const PATH_RETRY_MIN: Duration = Duration::from_millis(250);
const PATH_RETRY: Duration = Duration::from_secs(5);
/// Consecutive failures before a down path is reported at `warn`.
const PATH_WARN_AFTER: u32 = 3;
/// How long the primary path's maintainer waits for the handshake path to
/// learn its source address (see [`primary_path_spec`]).
const PRIMARY_LOCAL_IP_WAIT: Duration = Duration::from_secs(5);
/// How long a handshake path gets before the client tries the next candidate
/// (see [`handshake_candidates`]); the last candidate gets the full handshake
/// timeout.
const HANDSHAKE_FALLBACK_AFTER: Duration = Duration::from_secs(3);

/// An extra multipath path:
/// `REMOTE_IP:PORT[@LOCAL_IP][/backup][/priority=N][/rate=RATE][/rtable=N]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSpec {
    pub remote: SocketAddr,
    pub local_ip: Option<IpAddr>,
    pub backup: bool,
    /// Scheduling priority, lower is preferred (noq `Path::set_priority`).
    pub priority: u8,
    /// Fixed sending rate (bits per second) in place of congestion control,
    /// for a link of known, dedicated capacity (`crate::cc::FixedRate`).
    pub rate: Option<u64>,
    /// OpenBSD routing table to send this path's packets through.
    pub rtable: Option<u32>,
}

impl PathSpec {
    /// A path to `remote` with `priority` and no other options.
    pub fn to(remote: SocketAddr, priority: u8) -> Self {
        Self {
            remote,
            local_ip: None,
            backup: false,
            priority,
            rate: None,
            rtable: None,
        }
    }
}

impl FromStr for PathSpec {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        let mut options = s.split('/');
        let s = options.next().unwrap_or_default();
        let mut backup = false;
        let mut priority = 0;
        let mut rtable = None;
        let mut rate = None;
        for option in options {
            if option == "backup" {
                backup = true;
            } else if let Some(n) = option.strip_prefix("priority=") {
                priority = n
                    .parse()
                    .map_err(|e| format!("bad priority {n:?} (0-255): {e}"))?;
            } else if let Some(n) = option.strip_prefix("rtable=") {
                rtable = Some(
                    n.parse()
                        .map_err(|e| format!("bad routing table {n:?}: {e}"))?,
                );
            } else if let Some(r) = option.strip_prefix("rate=") {
                rate = Some(crate::cc::parse_rate(r)?);
            } else {
                return Err(format!(
                    "unknown path option {option:?} (expected backup, priority=N, rate=RATE \
                     or rtable=N)"
                ));
            }
        }
        let (remote, local) = match s.rsplit_once('@') {
            Some((r, l)) => (r, Some(l)),
            None => (s, None),
        };
        let remote = remote
            .parse()
            .map_err(|e| format!("bad remote address {remote:?}: {e}"))?;
        let local_ip = local
            .map(|l| l.trim_matches(|c| c == '[' || c == ']').parse())
            .transpose()
            .map_err(|e| format!("bad local IP {:?}: {e}", local.unwrap_or_default()))?;
        Ok(Self {
            remote,
            local_ip,
            backup,
            priority,
            rate,
            rtable,
        })
    }
}

impl fmt::Display for PathSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.remote)?;
        if let Some(ip) = self.local_ip {
            write!(f, "@{ip}")?;
        }
        if self.backup {
            write!(f, "/backup")?;
        }
        if self.priority != 0 {
            write!(f, "/priority={}", self.priority)?;
        }
        if let Some(rate) = self.rate {
            write!(f, "/rate={}", crate::cc::format_rate(rate))?;
        }
        if let Some(rtable) = self.rtable {
            write!(f, "/rtable={rtable}")?;
        }
        Ok(())
    }
}

/// Connection parameters for the proxy client.
pub struct ConnectParams {
    pub endpoint: ProxyEndpoint,
    /// Override for the proxy UDP address; the endpoint host is still used for
    /// SNI / `:authority`.
    pub proxy_addr: Option<SocketAddr>,
    pub verify: Verify,
    pub ech_config_list: Option<Vec<u8>>,
    /// Extra multipath paths to attach once the tunnel is up.
    pub paths: Vec<PathSpec>,
    /// Scheduling priority of the primary path (only used with `paths`).
    pub primary_priority: u8,
    /// Fixed sending rate of the primary path (bits per second).
    pub primary_rate: Option<u64>,
    /// Ask the proxy for sequenced datagrams and deliver each flow in order
    /// (`crate::reorder`).
    pub in_order_delivery: bool,
    /// OpenBSD routing table of the client's main socket: the primary path
    /// and every path without its own `rtable`.
    pub rtable: Option<u32>,
    /// Rank paths by measured loss, on both ends (only used with `paths`).
    pub path_ranking: PathRanking,
    /// Connections listed on the stats endpoint, if enabled.
    pub stats: Option<Arc<stats::Registry>>,
    pub transport: TransportOptions,
}

pub struct ProxyOptions {
    pub conn: ConnectParams,
    pub listen: SocketAddr,
}

type LocalPacket = (Bytes, SocketAddr);

/// Run as a local UDP→CONNECT-UDP proxy. The local listen socket is bound once
/// and persists; the QUIC connection to the proxy is (re)established in a loop
/// that never gives up, so a server restart, a dropped NAT mapping, or any other
/// failure recovers automatically. Flows reopen lazily as local datagrams
/// arrive (apps retransmit lost UDP, so they self-heal).
pub async fn run_proxy(opts: ProxyOptions) -> Result<()> {
    let std_sock = std::net::UdpSocket::bind(opts.listen)
        .with_context(|| format!("binding local UDP listen socket {}", opts.listen))?;
    quic::enlarge_udp_buffers(&std_sock);
    std_sock.set_nonblocking(true)?;
    let lsock = Arc::new(UdpSocket::from_std(std_sock)?);
    log::info!("local UDP proxy listening on {}", opts.listen);

    // The local recv task persists across reconnects, buffering datagrams that
    // arrive while the tunnel is briefly down.
    let (ltx, mut lrx) = mpsc::channel::<LocalPacket>(CHANNEL_CAP);
    tokio::spawn(local_recv(lsock.clone(), ltx));

    let mut backoff = RECONNECT_MIN;
    loop {
        let established = run_session(&opts.conn, &lsock, &mut lrx).await;
        if established {
            backoff = RECONNECT_MIN;
        }
        log::warn!("tunnel down; reconnecting in {backoff:?}");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

async fn local_recv(lsock: Arc<UdpSocket>, ltx: mpsc::Sender<LocalPacket>) {
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        match lsock.recv_from(&mut buf).await {
            Ok((n, src)) => {
                // Drop when full: datagrams are lossy by contract.
                let _ = ltx.try_send((Bytes::copy_from_slice(&buf[..n]), src));
            }
            Err(e) => {
                log::debug!("local recv: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

/// A connected QUIC connection to the proxy (plus its endpoint, which must
/// outlive it).
struct Dialed {
    endpoint: Endpoint,
    conn: Connection,
    proxy_addr: SocketAddr,
    /// Where the handshake went: `proxy_addr`, or an extra path's proxy
    /// address if the primary path did not answer.
    handshake_addr: SocketAddr,
}

/// Proxy addresses to try the handshake on, in order: the primary, then the
/// extra paths' remotes by priority (`/backup` paths last). Only paths
/// without `@LOCAL_IP` qualify, and only remotes other than the primary's: a
/// handshake cannot pick its source address, and the path it creates must not
/// be mistaken for another configured path (see [`primary_path_spec`]).
fn handshake_candidates(proxy_addr: SocketAddr, paths: &[PathSpec]) -> Vec<SocketAddr> {
    let mut extra: Vec<&PathSpec> = paths
        .iter()
        .filter(|spec| spec.local_ip.is_none() && spec.remote != proxy_addr)
        .collect();
    extra.sort_by_key(|spec| (spec.backup, spec.priority));
    let mut out = vec![proxy_addr];
    for spec in extra {
        if !out.contains(&spec.remote) {
            out.push(spec.remote);
        }
    }
    out
}

async fn dial(p: &ConnectParams) -> Result<Dialed> {
    let config = quic::build_client_config(&p.verify, p.ech_config_list.clone(), p.transport)?;
    let proxy_addr = match p.proxy_addr {
        Some(addr) => addr,
        None => resolve_authority(&p.endpoint.authority)?,
    };
    let server_name = host_of(&p.endpoint.authority);

    validate_routing_tables(&p.paths, proxy_addr)?;
    let socket = quic::client_bind_socket(proxy_addr, !p.paths.is_empty(), p.rtable)
        .context("binding client UDP socket")?;
    let routes: Vec<routed_socket::Route> = p
        .paths
        .iter()
        .filter_map(|spec| {
            Some(routed_socket::Route {
                remote: spec.remote,
                local_ip: spec.local_ip,
                rtable: Some(spec.rtable?),
            })
        })
        .collect();
    let endpoint = if routes.is_empty() {
        Endpoint::new(
            quic::endpoint_config(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
    } else {
        Endpoint::new_with_abstract_socket(
            quic::endpoint_config(),
            None,
            routed_socket::build(socket, &routes).context("binding routing-table sockets")?,
            Arc::new(TokioRuntime),
        )
    }
    .context("creating QUIC endpoint")?;

    let candidates = handshake_candidates(proxy_addr, &p.paths);
    let mut failure = None;
    for (i, &remote) in candidates.iter().enumerate() {
        log::info!("connecting to proxy {remote} (sni={server_name})");
        let connecting = endpoint
            .connect_with(config.clone(), remote, &server_name)
            .map_err(|e| anyhow!("connect: {e}"))?;
        let result = if i + 1 == candidates.len() {
            Ok(connecting.await)
        } else {
            tokio::time::timeout(HANDSHAKE_FALLBACK_AFTER, connecting).await
        };
        match result {
            Ok(Ok(conn)) => {
                if remote != proxy_addr {
                    log::warn!(
                        "primary path to {proxy_addr} unavailable; tunnel established over \
                         {remote}"
                    );
                }
                return Ok(Dialed {
                    endpoint,
                    conn,
                    proxy_addr,
                    handshake_addr: remote,
                });
            }
            Ok(Err(e)) => {
                log::warn!("QUIC handshake via {remote} failed: {e}");
                failure = Some(anyhow!(e).context("QUIC handshake"));
            }
            Err(_) => log::warn!(
                "QUIC handshake via {remote}: no answer within {HANDSHAKE_FALLBACK_AFTER:?}; \
                 trying the next path"
            ),
        }
    }
    Err(failure.unwrap_or_else(|| anyhow!("QUIC handshake: no path answered")))
}

/// One local source's flow state.
struct FlowState {
    /// Distinguishes this flow from earlier ones for the same source, so late
    /// events from a closed flow are ignored.
    token: u64,
    /// Quarter-stream id, set once the request stream is open.
    flow_id: Option<u64>,
    /// Set once the proxy answers 2xx. Datagrams must not be sent before this:
    /// the server only creates the flow when it processes the CONNECT request,
    /// and a datagram can otherwise overtake the request and be dropped.
    established: bool,
    /// Datagrams buffered until the flow is established.
    pending: Vec<Bytes>,
    /// Sequence number of the next datagram, if the proxy agreed to numbered
    /// datagrams.
    next_seq: Option<u32>,
}

impl FlowState {
    /// `data` as an HTTP datagram for flow `fid`, numbered if agreed.
    fn encode(&mut self, fid: u64, data: &[u8]) -> Bytes {
        let seq = self.next_seq;
        if let Some(seq) = seq {
            self.next_seq = Some(seq.wrapping_add(1));
        }
        dgram::encode_udp(fid, seq, data).into()
    }
}

/// A flow as seen by datagrams arriving from the proxy.
struct TunnelFlow {
    /// The local source the flow belongs to.
    src: SocketAddr,
    /// Puts numbered datagrams back in order, once the first arrives.
    reorder: Option<Reorder>,
}

/// Progress reports from per-flow request tasks to the session loop.
enum FlowEvent {
    Opened {
        src: SocketAddr,
        token: u64,
        flow_id: u64,
    },
    Accepted {
        src: SocketAddr,
        token: u64,
        /// The proxy numbers its datagrams and accepts numbered ones.
        sequenced: bool,
    },
    Closed {
        src: SocketAddr,
        token: u64,
    },
}

/// Drive one connection lifetime to the proxy. Returns whether the tunnel became
/// established (so the caller resets its backoff). Never propagates connection
/// errors: on any failure it logs and returns so the caller reconnects.
async fn run_session(
    p: &ConnectParams,
    lsock: &Arc<UdpSocket>,
    lrx: &mut mpsc::Receiver<LocalPacket>,
) -> bool {
    let Dialed {
        endpoint,
        conn,
        proxy_addr,
        handshake_addr,
    } = match dial(p).await {
        Ok(d) => d,
        Err(e) => {
            log::warn!("dial failed: {e:#}");
            return false;
        }
    };

    if let Some(der) = conn
        .peer_identity()
        .and_then(|id| id.downcast::<Vec<u8>>().ok())
    {
        log::info!(
            "proxy certificate sha256: {}",
            hex(&boring::sha::sha256(&der))
        );
    }
    let ech = conn
        .handshake_data()
        .and_then(|d| d.downcast::<HandshakeData>().ok())
        .is_some_and(|h| h.ech_accepted);

    // Our control stream must stay open for the connection's lifetime.
    let control = match h3::open_control(&conn).await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("HTTP/3 setup failed: {e:#}");
            return false;
        }
    };
    let priorities = Arc::new(PathPriorities::default());
    // The proxy never asks this end for fixed path rates.
    tokio::spawn(h3::serve_uni_streams(
        conn.clone(),
        priorities.clone(),
        None,
    ));
    tokio::spawn(quic::log_path_events(conn.clone()));
    if !p.paths.is_empty() && p.path_ranking == PathRanking::Auto && conn.is_multipath_enabled() {
        // Rank what we send, and ask the proxy to rank what it sends.
        if let Err(e) = control.send_path_ranking().await {
            log::warn!("requesting path ranking from the proxy failed: {e:#}");
        }
        ranking::start(conn.clone(), priorities.clone(), RankingConfig::default());
    }
    if !p.paths.is_empty() {
        // Also keep the primary path: if it is abandoned (e.g. its uplink went
        // away) while extra paths carry the tunnel, re-open it once it works.
        tokio::spawn({
            let (conn, control, priorities) = (conn.clone(), control.clone(), priorities.clone());
            let (paths, priority, rate) = (p.paths.clone(), p.primary_priority, p.primary_rate);
            async move {
                let mut primary = if handshake_addr == proxy_addr {
                    primary_path_spec(&conn, proxy_addr, &paths, priority).await
                } else {
                    // The handshake went over an extra path (path 0 is that
                    // path), so the primary is opened like any other path.
                    PathSpec::to(proxy_addr, priority)
                };
                primary.rate = rate;
                maintain_path(conn, primary, control, priorities).await
            }
        });
        for spec in p.paths.iter().cloned() {
            tokio::spawn(maintain_path(
                conn.clone(),
                spec,
                control.clone(),
                priorities.clone(),
            ));
        }
    } else if let Some(rate) = p.primary_rate {
        // A single path: give it its fixed rate here.
        if priorities.set_rate(&conn, PathId::ZERO, rate)
            && let Err(e) = control.send_path_rate(PathId::ZERO, rate).await
        {
            log::warn!("announcing the primary path's rate failed: {e:#}");
        }
    }
    log::info!(
        "tunnel established (ech={ech}, multipath={})",
        conn.is_multipath_enabled()
    );

    let authority: Arc<str> = p.endpoint.authority.as_str().into();
    let path: Arc<str> = p.endpoint.path.as_str().into();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<FlowEvent>();
    let mut by_addr: HashMap<SocketAddr, FlowState> = HashMap::new();
    let mut flows: HashMap<u64, TunnelFlow> = HashMap::new();
    let mut ready: Vec<Bytes> = Vec::new();
    let mut next_token = 0u64;
    let flow_count = Arc::new(AtomicUsize::new(0));
    let _stats = p.stats.as_ref().map(|registry| {
        let flow_count = flow_count.clone();
        registry.register(
            &conn,
            priorities.clone(),
            serde_json::json!({
                "endpoint": p.endpoint.authority,
                "proxy_addr": proxy_addr.to_string(),
                "handshake_addr": handshake_addr.to_string(),
                "ech": ech,
            }),
            move || flow_count.load(Ordering::Relaxed),
        )
    });

    let reason = loop {
        flow_count.store(by_addr.len(), Ordering::Relaxed);
        tokio::select! {
            local = lrx.recv() => {
                let Some(first) = local else { break "local socket closed".to_string() };
                // Absorb the whole queued burst in one wakeup.
                let mut batch = vec![first];
                while let Ok(pkt) = lrx.try_recv() {
                    batch.push(pkt);
                }
                for (data, src) in batch {
                    let st = by_addr.entry(src).or_insert_with(|| {
                        next_token += 1;
                        tokio::spawn(open_flow(
                            conn.clone(),
                            authority.clone(),
                            path.clone(),
                            src,
                            next_token,
                            p.in_order_delivery,
                            ev_tx.clone(),
                        ));
                        FlowState {
                            token: next_token,
                            flow_id: None,
                            established: false,
                            pending: Vec::new(),
                            next_seq: None,
                        }
                    });
                    match (st.established, st.flow_id) {
                        (true, Some(fid)) => {
                            log::debug!("-> tunnel flow {fid}: {} bytes", data.len());
                            send_datagram(&conn, fid, st.encode(fid, &data), "local");
                        }
                        _ => {
                            if st.pending.len() < MAX_PENDING {
                                st.pending.push(data);
                            }
                        }
                    }
                }
            }
            datagram = conn.read_datagram() => match datagram {
                Ok(d) => {
                    if let Some(src) = take_tunnel_datagram(&mut flows, d, &mut ready) {
                        deliver_local(lsock, src, &mut ready).await;
                    }
                }
                Err(e) => break e.to_string(),
            },
            _ = sleep_until_opt(next_reorder_deadline(&flows)) => {
                let now = std::time::Instant::now();
                for flow in flows.values_mut() {
                    if let Some(reorder) = flow.reorder.as_mut() {
                        reorder.on_timeout(now, &mut ready);
                    }
                    deliver_local(lsock, flow.src, &mut ready).await;
                }
            },
            Some(ev) = ev_rx.recv() => match ev {
                FlowEvent::Opened { src, token, flow_id } => {
                    if let Some(st) = by_addr.get_mut(&src).filter(|st| st.token == token) {
                        st.flow_id = Some(flow_id);
                        flows.insert(flow_id, TunnelFlow { src, reorder: None });
                        log::info!("opened flow {flow_id} for local {src}");
                    }
                }
                FlowEvent::Accepted { src, token, sequenced } => {
                    if let Some(st) = by_addr.get_mut(&src).filter(|st| st.token == token)
                        && let Some(fid) = st.flow_id
                    {
                        // The server has created the flow; release buffered data.
                        st.established = true;
                        if sequenced {
                            st.next_seq = Some(0);
                        }
                        for data in std::mem::take(&mut st.pending) {
                            let datagram = st.encode(fid, &data);
                            send_datagram(&conn, fid, datagram, "local");
                        }
                    }
                }
                FlowEvent::Closed { src, token } => {
                    if by_addr.get(&src).is_some_and(|st| st.token == token)
                        && let Some(st) = by_addr.remove(&src)
                        && let Some(fid) = st.flow_id
                    {
                        flows.remove(&fid);
                    }
                }
            },
        }
    };
    log::info!("tunnel closed: {reason}");
    conn.close(0u32.into(), b"");
    drop(endpoint);
    true
}

/// Open one CONNECT-UDP request stream for local `src`, report its progress,
/// and hold the stream open until the proxy finishes or resets it.
async fn open_flow(
    conn: Connection,
    authority: Arc<str>,
    path: Arc<str>,
    src: SocketAddr,
    token: u64,
    in_order: bool,
    events: mpsc::UnboundedSender<FlowEvent>,
) {
    let closed = |events: &mpsc::UnboundedSender<FlowEvent>| {
        let _ = events.send(FlowEvent::Closed { src, token });
    };
    let (mut send, recv) = match conn.open_bi().await {
        Ok(s) => s,
        Err(e) => {
            log::warn!("opening flow for {src} failed: {e}");
            return closed(&events);
        }
    };
    let flow_id = u64::from(send.id()) / 4;
    let _ = events.send(FlowEvent::Opened {
        src,
        token,
        flow_id,
    });

    let mut fields = vec![
        (":method", "CONNECT"),
        (":protocol", "connect-udp"),
        (":scheme", "https"),
        (":authority", &*authority),
        (":path", &*path),
        ("capsule-protocol", CAPSULE_PROTOCOL_TRUE),
    ];
    if in_order {
        fields.push((dgram::SEQUENCE_HEADER, dgram::SEQUENCE_HEADER_ON));
    }
    let request = h3::headers_frame(&fields);
    if let Err(e) = send.write_all(&request).await {
        log::warn!("send_request for {src} failed: {e}");
        return closed(&events);
    }

    let mut reader = FrameReader::new(recv);
    loop {
        match reader.read_headers().await {
            Ok(Some(fields)) => match h3::status_of(&fields) {
                Some(s) if (100..200).contains(&s) => continue, // interim
                Some(s) if (200..300).contains(&s) => {
                    let sequenced = in_order
                        && h3::header(&fields, dgram::SEQUENCE_HEADER)
                            == Some(dgram::SEQUENCE_HEADER_ON.as_bytes());
                    log::debug!("flow {flow_id} accepted (status {s}, in order: {sequenced})");
                    let _ = events.send(FlowEvent::Accepted {
                        src,
                        token,
                        sequenced,
                    });
                    break;
                }
                status => {
                    log::warn!("flow {flow_id} rejected (status {status:?})");
                    return closed(&events);
                }
            },
            Ok(None) => return closed(&events),
            Err(e) => {
                log::debug!("flow {flow_id} response: {e:#}");
                return closed(&events);
            }
        }
    }

    // Ends when the proxy closes or resets the flow (e.g. idle timeout) or the
    // connection goes away.
    let _ = reader.drain().await;
    log::debug!("flow {flow_id} closed");
    closed(&events);
    drop(send);
}

/// Take in a datagram from the proxy: its flow's payloads that are now
/// deliverable, in order, are appended to `ready`. Returns the flow's local
/// source.
fn take_tunnel_datagram(
    flows: &mut HashMap<u64, TunnelFlow>,
    d: Bytes,
    ready: &mut Vec<Bytes>,
) -> Option<SocketAddr> {
    let p = dgram::decode(&d)?;
    let (seq, payload) = dgram::udp_payload(&p)?;
    let flow = flows.get_mut(&p.flow_id)?;
    let payload = d.slice_ref(payload);
    match seq {
        Some(seq) => {
            let now = std::time::Instant::now();
            flow.reorder
                .get_or_insert_with(|| Reorder::new(now))
                .push(seq, payload, now, ready);
        }
        None => ready.push(payload),
    }
    Some(flow.src)
}

/// Send `ready` payloads to local source `src`.
async fn deliver_local(lsock: &UdpSocket, src: SocketAddr, ready: &mut Vec<Bytes>) {
    for payload in ready.drain(..) {
        if let Err(e) = lsock.send_to(&payload, src).await {
            log::debug!("send to local {src} failed: {e}");
        }
    }
}

/// The earliest time a flow gives up waiting for a missing datagram.
fn next_reorder_deadline(flows: &HashMap<u64, TunnelFlow>) -> Option<std::time::Instant> {
    flows
        .values()
        .filter_map(|flow| flow.reorder.as_ref()?.deadline())
        .min()
}

async fn sleep_until_opt(deadline: Option<std::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d.into()).await,
        None => std::future::pending().await,
    }
}

/// Paths with their own routing table are told apart from other paths by
/// their remote address and source address (all noq's datagrams carry), so
/// those must be unique: one with a source address must not share both with
/// another path, and one without must not share its remote with any other
/// path, including the primary (`proxy_addr`, no source address).
pub(crate) fn validate_routing_tables(paths: &[PathSpec], proxy_addr: SocketAddr) -> Result<()> {
    for (i, spec) in paths.iter().enumerate() {
        if spec.rtable.is_none() {
            continue;
        }
        let others = paths
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, other)| (other.remote, other.local_ip))
            .chain(std::iter::once((proxy_addr, None)));
        for (remote, local_ip) in others {
            if remote == spec.remote && (spec.local_ip.is_none() || local_ip == spec.local_ip) {
                anyhow::bail!(
                    "path {spec}: a path with its own routing table needs a remote address, or \
                     remote and @LOCAL_IP, that no other path (including the primary, \
                     {proxy_addr}) uses"
                );
            }
        }
    }
    Ok(())
}

/// The spec that keeps the primary path (the handshake path to `proxy_addr`)
/// open.
///
/// The primary path has no configured source address, and noq treats a path
/// without one as the same path as any open path to that remote. So when an
/// extra path also goes to `proxy_addr`, pin the primary to the source address
/// the handshake used; otherwise its maintainer could adopt the extra path as
/// the primary (and give it the primary's priority) and never re-open the real
/// primary. The handshake path learns its source address from the first
/// packets the proxy sends once the handshake is done, so wait for it briefly.
pub(crate) async fn primary_path_spec(
    conn: &Connection,
    proxy_addr: SocketAddr,
    paths: &[PathSpec],
    priority: u8,
) -> PathSpec {
    let local_ip = if paths.iter().any(|spec| spec.remote == proxy_addr) {
        let deadline = tokio::time::Instant::now() + PRIMARY_LOCAL_IP_WAIT;
        let ip = loop {
            let ip = conn
                .path(PathId::ZERO)
                .and_then(|path| path.local_ip().ok().flatten());
            if ip.is_some()
                || conn.close_reason().is_some()
                || tokio::time::Instant::now() >= deadline
            {
                break ip;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        if ip.is_none() {
            log::warn!(
                "primary path's source address unknown; it may be confused with another \
                 path to {proxy_addr}"
            );
        }
        ip
    } else {
        None
    };
    PathSpec {
        local_ip,
        ..PathSpec::to(proxy_addr, priority)
    }
}

/// Keep one configured multipath path open for the connection's lifetime,
/// re-opening it whenever it fails or is abandoned. Each time the path comes
/// up (a re-opened path gets a new ID), its priority is set locally and sent
/// to the proxy, which applies it to its side of the path.
pub(crate) async fn maintain_path(
    conn: Connection,
    spec: PathSpec,
    control: h3::Control,
    priorities: Arc<PathPriorities>,
) {
    if !conn.is_multipath_enabled() {
        log::warn!("proxy did not negotiate QUIC multipath; not opening path {spec}");
        return;
    }
    let status = if spec.backup {
        PathStatus::Backup
    } else {
        PathStatus::Available
    };
    // Right after the handshake the proxy may not have issued connection IDs
    // for new paths yet, so retry quickly at first and back off to PATH_RETRY.
    // Log only on state changes, and warn only once a path keeps failing.
    let mut delay = PATH_RETRY_MIN;
    let mut up: Option<noq::PathId> = None;
    let mut failures = 0u32;
    while conn.close_reason().is_none() {
        let tuple = FourTuple::new(spec.remote, spec.local_ip);
        match conn.open_path_ensure(tuple, status).await {
            Ok(path) => {
                if up != Some(path.id()) {
                    log::info!("multipath path {spec} up (path id {})", path.id());
                    up = Some(path.id());
                    priorities.set_base(&conn, path.id(), spec.priority);
                    if let Err(e) = control.send_path_priority(path.id(), spec.priority).await {
                        log::debug!("multipath path {spec}: announcing priority: {e:#}");
                    }
                    if let Some(rate) = spec.rate
                        && priorities.set_rate(&conn, path.id(), rate)
                        && let Err(e) = control.send_path_rate(path.id(), rate).await
                    {
                        log::debug!("multipath path {spec}: announcing rate: {e:#}");
                    }
                }
                failures = 0;
                delay = PATH_RETRY_MIN;
            }
            Err(e) => {
                if up.take().is_some() {
                    log::warn!("multipath path {spec} lost: {e}");
                }
                failures += 1;
                if failures == PATH_WARN_AFTER {
                    log::warn!(
                        "multipath path {spec} unavailable: {e}; retrying every {PATH_RETRY:?}"
                    );
                } else {
                    log::debug!("multipath path {spec}: {e}");
                }
                delay = (delay * 2).min(PATH_RETRY);
            }
        }
        tokio::time::sleep(if up.is_some() { PATH_RETRY } else { delay }).await;
    }
}

fn host_of(authority: &str) -> String {
    // Strip the optional :port; handle bracketed IPv6 literals.
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest[..end].to_string();
    }
    authority
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| authority.to_string())
}

fn resolve_authority(authority: &str) -> Result<SocketAddr> {
    authority
        .to_socket_addrs()
        .with_context(|| format!("resolving proxy authority {authority}"))?
        .next()
        .ok_or_else(|| anyhow!("no addresses for proxy authority {authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_port_and_brackets() {
        assert_eq!(host_of("localhost:4433"), "localhost");
        assert_eq!(host_of("example.com"), "example.com");
        assert_eq!(host_of("[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn routing_table_paths_must_be_distinguishable() {
        let proxy: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let specs =
            |s: &[&str]| -> Vec<PathSpec> { s.iter().map(|s| s.parse().unwrap()).collect() };
        // Distinct source address, or distinct remote: fine.
        assert!(
            validate_routing_tables(&specs(&["192.0.2.1:4433@10.0.0.5/rtable=1"]), proxy).is_ok()
        );
        assert!(validate_routing_tables(&specs(&["192.0.2.2:4433/rtable=1"]), proxy).is_ok());
        assert!(
            validate_routing_tables(
                &specs(&[
                    "192.0.2.2:4433@10.0.0.5/rtable=1",
                    "192.0.2.2:4433@10.0.0.6"
                ]),
                proxy
            )
            .is_ok()
        );
        // Same remote as the primary without a source address.
        assert!(validate_routing_tables(&specs(&["192.0.2.1:4433/rtable=1"]), proxy).is_err());
        // Same remote and source as another path.
        assert!(
            validate_routing_tables(
                &specs(&[
                    "192.0.2.2:4433@10.0.0.5/rtable=1",
                    "192.0.2.2:4433@10.0.0.5"
                ]),
                proxy
            )
            .is_err()
        );
        // No source address but another path to the same remote.
        assert!(
            validate_routing_tables(
                &specs(&["192.0.2.2:4433/rtable=1", "192.0.2.2:4433@10.0.0.6"]),
                proxy
            )
            .is_err()
        );
        // Paths without a routing table are not constrained.
        assert!(validate_routing_tables(&specs(&["192.0.2.1:4433"]), proxy).is_ok());
    }

    #[test]
    fn path_spec_parsing() {
        let p: PathSpec = "192.0.2.1:4433".parse().unwrap();
        assert_eq!(p.remote, "192.0.2.1:4433".parse().unwrap());
        assert_eq!(p.local_ip, None);
        assert!(!p.backup);

        let p: PathSpec = "192.0.2.1:4433@10.0.0.5/backup".parse().unwrap();
        assert_eq!(p.local_ip, Some("10.0.0.5".parse().unwrap()));
        assert!(p.backup);
        assert_eq!(p.priority, 0);
        assert_eq!(p.to_string(), "192.0.2.1:4433@10.0.0.5/backup");

        let p: PathSpec = "192.0.2.1:4433@10.0.0.5/priority=2/backup".parse().unwrap();
        assert!(p.backup);
        assert_eq!(p.priority, 2);
        assert_eq!(p.to_string(), "192.0.2.1:4433@10.0.0.5/backup/priority=2");
        assert_eq!(p.to_string().parse::<PathSpec>().unwrap(), p);

        let p: PathSpec = "192.0.2.1:4433/priority=255".parse().unwrap();
        assert_eq!(p.priority, 255);
        assert!("192.0.2.1:4433/priority=256".parse::<PathSpec>().is_err());
        assert!("192.0.2.1:4433/priority=".parse::<PathSpec>().is_err());
        assert!("192.0.2.1:4433/fast".parse::<PathSpec>().is_err());

        let p: PathSpec = "192.0.2.1:4433@10.0.0.5/rtable=3/priority=1"
            .parse()
            .unwrap();
        assert_eq!(p.rtable, Some(3));
        assert_eq!(p.to_string(), "192.0.2.1:4433@10.0.0.5/priority=1/rtable=3");
        assert_eq!(p.to_string().parse::<PathSpec>().unwrap(), p);
        assert!("192.0.2.1:4433/rtable=-1".parse::<PathSpec>().is_err());

        let p: PathSpec = "[2001:db8::1]:443@[fe80::1]".parse().unwrap();
        assert_eq!(p.remote, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(p.local_ip, Some("fe80::1".parse().unwrap()));

        assert!("nonsense".parse::<PathSpec>().is_err());
        assert!("192.0.2.1:4433@not-an-ip".parse::<PathSpec>().is_err());
    }
}
