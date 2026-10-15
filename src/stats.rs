//! Optional HTTP stats endpoint (`--stats-listen`).
//!
//! `GET /stats` (or `/`) returns a JSON snapshot of every live QUIC connection
//! and each of its multipath paths: addresses, status, priorities and
//! automatic-ranking state, RTT, congestion window, MTU and traffic/loss
//! counters, plus how many outgoing datagrams were dropped for queueing
//! delay (CoDel) or a full send buffer. It is a minimal HTTP/1.1 responder (one request per TCP
//! connection, no TLS, no authentication), meant to be bound to loopback or a
//! management network.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use noq::{Connection, PathStatus};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::quic::PathScan;
use crate::ranking::PathPriorities;
use crate::util::{canonical, path_id_u32};

/// Largest request head accepted.
const MAX_REQUEST: usize = 8 * 1024;
/// Time allowed for a client to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How often each registered connection's path list is refreshed, so path IDs
/// opened between stats requests are not missed (see [`PathScan`]).
const PATH_SCAN_INTERVAL: Duration = Duration::from_secs(1);

/// The live connections whose stats are served.
pub struct Registry {
    role: &'static str,
    started: Instant,
    conns: Mutex<BTreeMap<usize, Entry>>,
}

struct Entry {
    conn: Connection,
    priorities: Arc<PathPriorities>,
    scan: Arc<Mutex<PathScan>>,
    opened: Instant,
    info: Value,
    flows: Box<dyn Fn() -> usize + Send + Sync>,
}

/// Keeps a connection listed until dropped.
pub struct Registration {
    registry: Arc<Registry>,
    id: usize,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.registry.conns.lock().unwrap().remove(&self.id);
    }
}

impl Registry {
    /// `role` is reported as is (`"server"` or `"client"`).
    pub fn new(role: &'static str) -> Arc<Self> {
        Arc::new(Self {
            role,
            started: Instant::now(),
            conns: Mutex::new(BTreeMap::new()),
        })
    }

    /// List `conn` until the returned guard is dropped. `info` is extra
    /// per-connection detail (e.g. SNI); `flows` counts its CONNECT-UDP flows.
    pub fn register(
        self: &Arc<Self>,
        conn: &Connection,
        priorities: Arc<PathPriorities>,
        info: Value,
        flows: impl Fn() -> usize + Send + Sync + 'static,
    ) -> Registration {
        let id = conn.stable_id();
        let scan = Arc::new(Mutex::new(PathScan::default()));
        tokio::spawn(track_paths(conn.clone(), scan.clone()));
        self.conns.lock().unwrap().insert(
            id,
            Entry {
                conn: conn.clone(),
                priorities,
                scan,
                opened: Instant::now(),
                info,
                flows: Box::new(flows),
            },
        );
        Registration {
            registry: self.clone(),
            id,
        }
    }

    /// The JSON document served at `/stats`.
    pub fn snapshot(&self) -> Value {
        let conns = self.conns.lock().unwrap();
        json!({
            "role": self.role,
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.started.elapsed().as_secs(),
            "connections": conns.values().map(connection_stats).collect::<Vec<_>>(),
        })
    }
}

async fn track_paths(conn: Connection, scan: Arc<Mutex<PathScan>>) {
    let mut tick = tokio::time::interval(PATH_SCAN_INTERVAL);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = conn.closed() => return,
        }
        scan.lock().unwrap().scan(&conn);
    }
}

fn connection_stats(entry: &Entry) -> Value {
    let conn = &entry.conn;
    let stats = conn.stats();
    let ranking = entry.priorities.ranking();
    let priorities = entry.priorities.snapshot();
    let paths: Vec<Value> = entry
        .scan
        .lock()
        .unwrap()
        .scan(conn)
        .iter()
        .map(|path| {
            let s = path.stats();
            let entry = priorities.get(&path.id()).copied().unwrap_or_default();
            json!({
                "id": path_id_u32(path.id()),
                "remote": path.remote_address().ok().map(|a| canonical(a).to_string()),
                "local_ip": path.local_ip().ok().flatten().map(|a| a.to_canonical().to_string()),
                "status": match path.status() {
                    Ok(PathStatus::Available) => Some("available"),
                    Ok(PathStatus::Backup) => Some("backup"),
                    Err(_) => None,
                },
                "priority": path.priority().ok(),
                "base_priority": entry.base,
                "demoted": entry.demoted,
                "ranked_loss": entry.loss,
                "rtt_ms": millis(s.rtt),
                "cwnd": s.cwnd,
                "mtu": s.current_mtu,
                "sent_packets": s.sent_packets,
                "lost_packets": s.lost_packets,
                "sent_bytes": s.sent_bytes,
                "lost_bytes": s.lost_bytes,
                "congestion_events": s.congestion_events,
                "udp_tx": udp(&s.udp_tx),
                "udp_rx": udp(&s.udp_rx),
            })
        })
        .collect();
    json!({
        "id": conn.stable_id(),
        "uptime_secs": entry.opened.elapsed().as_secs(),
        "multipath": conn.is_multipath_enabled(),
        "path_ranking": ranking,
        "flows": (entry.flows)(),
        "info": entry.info,
        "sent_packets": stats.sent_packets,
        "lost_packets": stats.lost_packets,
        "datagrams_dropped_delay": stats.datagrams_dropped_delay,
        "datagrams_dropped_overflow": stats.datagrams_dropped_overflow,
        "udp_tx": udp(&stats.udp_tx),
        "udp_rx": udp(&stats.udp_rx),
        "paths": paths,
    })
}

fn udp(s: &noq::UdpStats) -> Value {
    json!({ "datagrams": s.datagrams, "bytes": s.bytes })
}

fn millis(d: Duration) -> f64 {
    (d.as_secs_f64() * 1e6).round() / 1e3
}

/// Bind the stats listener.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding stats listener {addr}"))
}

/// Serve `GET /stats` on `listener` forever.
pub async fn serve(listener: TcpListener, registry: Arc<Registry>) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                tokio::spawn(handle(sock, registry.clone()));
            }
            Err(e) => {
                log::debug!("stats accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle(mut sock: TcpStream, registry: Arc<Registry>) {
    let head = match tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut sock)).await {
        Ok(Ok(head)) => head,
        _ => return,
    };
    let (status, body) = respond(&head, &registry);
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.shutdown().await;
}

/// Read up to the end of the request head.
async fn read_head(sock: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = sock.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "connection closed mid-request");
        buf.extend_from_slice(&chunk[..n]);
        anyhow::ensure!(buf.len() <= MAX_REQUEST, "request too large");
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn respond(head: &str, registry: &Registry) -> (&'static str, String) {
    let mut parts = head.lines().next().unwrap_or_default().split(' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return ("400 Bad Request", error("malformed request"));
    };
    let path = target.split('?').next().unwrap_or_default();
    match (method, path) {
        ("GET", "/" | "/stats") => (
            "200 OK",
            serde_json::to_string_pretty(&registry.snapshot()).unwrap_or_default(),
        ),
        (_, "/" | "/stats") => ("405 Method Not Allowed", error("use GET")),
        _ => ("404 Not Found", error("not found; try /stats")),
    }
}

fn error(message: &str) -> String {
    json!({ "error": message }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_get_stats_only() {
        let registry = Registry::new("server");
        let (status, body) = respond("GET /stats?pretty HTTP/1.1\r\nHost: x\r\n\r\n", &registry);
        assert_eq!(status, "200 OK");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["role"], "server");
        assert_eq!(v["connections"], json!([]));
        assert_eq!(respond("GET / HTTP/1.1\r\n\r\n", &registry).0, "200 OK");
        assert_eq!(
            respond("POST /stats HTTP/1.1\r\n\r\n", &registry).0,
            "405 Method Not Allowed"
        );
        assert_eq!(
            respond("GET /metrics HTTP/1.1\r\n\r\n", &registry).0,
            "404 Not Found"
        );
        assert_eq!(respond("", &registry).0, "400 Bad Request");
    }
}
