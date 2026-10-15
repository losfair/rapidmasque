//! Just enough HTTP/3 (RFC 9114) for Extended CONNECT (RFC 9220) + CONNECT-UDP
//! (RFC 9298) over noq.
//!
//! Each side opens a control stream carrying SETTINGS that enable Extended
//! CONNECT and HTTP Datagrams (RFC 9297) with a zero-capacity QPACK dynamic
//! table. A CONNECT-UDP request is one HEADERS frame on a client bidi stream;
//! the response is one HEADERS frame back. Anything that follows on the request
//! stream (capsules in DATA frames) is drained and ignored, matching
//! zeromasque — UDP payloads ride QUIC DATAGRAMs (`crate::dgram`).
//!
//! Two extensions on the control stream: the client announces its multipath
//! path priorities ([`FRAME_PATH_PRIORITY`]) so the proxy prefers the same
//! paths for the return direction, asks the proxy to rank paths by loss too
//! ([`FRAME_PATH_RANKING`]), and announces paths that send at a fixed rate
//! ([`FRAME_PATH_RATE`]).

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use noq::{Connection, PathId, RecvStream, SendStream, VarInt};
use tokio::sync::Mutex;

use crate::qpack;
use crate::ranking::{self, PathPriorities, RankingConfig};
use crate::varint;

pub const FRAME_DATA: u64 = 0x00;
pub const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;
/// rapidmasque extension frame on the control stream: the sender's scheduling
/// priority for one multipath path (payload: path ID varint, priority varint
/// 0-255), so the peer applies the same priority to what it sends on that path
/// (noq path priorities are local and never on the wire). HTTP/3 peers ignore
/// unknown frame types (RFC 9114 §9), so other servers are unaffected. The type
/// is "rmpp" in ASCII, outside the reserved (grease) range.
pub const FRAME_PATH_PRIORITY: u64 = 0x726d_7070;
/// rapidmasque extension frame on the control stream: rank the paths this
/// peer sends on by their loss (`--path-ranking auto`, see `crate::ranking`).
/// Payload: mode varint, 1 = auto. "rmpr" in ASCII.
pub const FRAME_PATH_RANKING: u64 = 0x726d_7072;
const PATH_RANKING_AUTO: u64 = 1;
/// rapidmasque extension frame on the control stream: send on one multipath
/// path at a fixed rate instead of under congestion control (`/rate=RATE`,
/// `crate::cc::FixedRate`), so the peer does the same for what it sends on the
/// path. Payload: path ID varint, rate varint (bits per second). A proxy only
/// honours it up to its `--max-path-rate`. "rmpf" in ASCII.
pub const FRAME_PATH_RATE: u64 = 0x726d_7066;

const STREAM_CONTROL: u64 = 0x00;
const STREAM_PUSH: u64 = 0x01;
const STREAM_QPACK_ENCODER: u64 = 0x02;
const STREAM_QPACK_DECODER: u64 = 0x03;

const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// HTTP/3 error codes (RFC 9114 §8.1).
pub const H3_STREAM_CREATION_ERROR: u32 = 0x103;

/// Upper bound on a HEADERS (or SETTINGS) frame we are willing to buffer.
const MAX_HEADER_FRAME: usize = 64 * 1024;

/// Build a frame: type, length, payload.
pub fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    varint::encode(ty, &mut out);
    varint::encode(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// A HEADERS frame carrying the QPACK encoding of `fields`.
pub fn headers_frame(fields: &[(&str, &str)]) -> Vec<u8> {
    frame(FRAME_HEADERS, &qpack::encode(fields))
}

/// Our HTTP/3 control stream. It must stay open for the connection's lifetime
/// (closing it is a connection error), so hold a handle until the end.
#[derive(Clone)]
pub struct Control(Arc<Mutex<SendStream>>);

impl Control {
    /// Tell the peer to give `path_id` the scheduling priority `priority`.
    pub async fn send_path_priority(&self, path_id: PathId, priority: u8) -> Result<()> {
        let mut payload = Vec::new();
        varint::encode(u64::from(crate::util::path_id_u32(path_id)), &mut payload);
        varint::encode(u64::from(priority), &mut payload);
        self.0
            .lock()
            .await
            .write_all(&frame(FRAME_PATH_PRIORITY, &payload))
            .await
            .context("writing PATH_PRIORITY")
    }

    /// Tell the peer to send on `path_id` at a fixed `rate` (bits per second).
    pub async fn send_path_rate(&self, path_id: PathId, rate: u64) -> Result<()> {
        let mut payload = Vec::new();
        varint::encode(u64::from(crate::util::path_id_u32(path_id)), &mut payload);
        varint::encode(rate, &mut payload);
        self.0
            .lock()
            .await
            .write_all(&frame(FRAME_PATH_RATE, &payload))
            .await
            .context("writing PATH_RATE")
    }

    /// Ask the peer to rank the paths it sends on by loss.
    pub async fn send_path_ranking(&self) -> Result<()> {
        let mut payload = Vec::new();
        varint::encode(PATH_RANKING_AUTO, &mut payload);
        self.0
            .lock()
            .await
            .write_all(&frame(FRAME_PATH_RANKING, &payload))
            .await
            .context("writing PATH_RANKING")
    }
}

/// Open our control stream and send SETTINGS.
pub async fn open_control(conn: &Connection) -> Result<Control> {
    let mut send = conn.open_uni().await.context("opening control stream")?;
    let mut settings = Vec::new();
    for (id, value) in [
        (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
    ] {
        varint::encode(id, &mut settings);
        varint::encode(value, &mut settings);
    }
    let mut out = Vec::new();
    varint::encode(STREAM_CONTROL, &mut out);
    out.extend_from_slice(&frame(FRAME_SETTINGS, &settings));
    send.write_all(&out)
        .await
        .context("writing control SETTINGS")?;
    Ok(Control(Arc::new(Mutex::new(send))))
}

/// Service the peer's unidirectional streams until the connection closes:
/// read its control stream (logging SETTINGS, applying path priorities and,
/// up to `max_path_rate`, path rates), drain QPACK streams, and refuse push
/// and unknown stream types.
pub async fn serve_uni_streams(
    conn: Connection,
    priorities: Arc<PathPriorities>,
    max_path_rate: Option<u64>,
) {
    while let Ok(recv) = conn.accept_uni().await {
        tokio::spawn(serve_uni_stream(
            conn.clone(),
            priorities.clone(),
            max_path_rate,
            recv,
        ));
    }
}

async fn serve_uni_stream(
    conn: Connection,
    priorities: Arc<PathPriorities>,
    max_path_rate: Option<u64>,
    recv: RecvStream,
) {
    let mut reader = FrameReader::new(recv);
    let ty = match reader.read_varint().await {
        Ok(Some(ty)) => ty,
        _ => return,
    };
    match ty {
        STREAM_CONTROL => {
            match reader.read_frame(MAX_HEADER_FRAME).await {
                Ok(Some((FRAME_SETTINGS, payload))) => log::debug!(
                    "peer HTTP/3 SETTINGS: {:?}",
                    parse_settings(&payload).unwrap_or_default()
                ),
                Ok(other) => log::debug!(
                    "peer control stream did not start with SETTINGS ({:?})",
                    other.map(|(t, _)| t)
                ),
                Err(e) => log::debug!("peer control stream: {e}"),
            }
            // Other later control frames (GOAWAY, ...) need no action here.
            loop {
                match reader.read_frame(MAX_HEADER_FRAME).await {
                    Ok(Some((FRAME_PATH_PRIORITY, payload))) => {
                        apply_path_priority(&conn, &priorities, &payload)
                    }
                    Ok(Some((FRAME_PATH_RATE, payload))) => {
                        apply_path_rate(&conn, &priorities, max_path_rate, &payload)
                    }
                    Ok(Some((FRAME_PATH_RANKING, payload))) => {
                        if varint::decode(&payload).map(|(mode, _)| mode) == Some(PATH_RANKING_AUTO)
                        {
                            ranking::start(
                                conn.clone(),
                                priorities.clone(),
                                RankingConfig::default(),
                            );
                        }
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("peer control stream: {e}");
                        break;
                    }
                }
            }
        }
        STREAM_QPACK_ENCODER | STREAM_QPACK_DECODER => {
            // With a zero-capacity table there is nothing to act on.
            let _ = reader.drain().await;
        }
        STREAM_PUSH => reader.stop(H3_STREAM_CREATION_ERROR),
        _ => reader.stop(H3_STREAM_CREATION_ERROR), // reserved / unknown
    }
}

fn parse_path_priority(payload: &[u8]) -> Option<(PathId, u8)> {
    let (path_id, n) = varint::decode(payload)?;
    let (priority, m) = varint::decode(&payload[n..])?;
    if n + m != payload.len() {
        return None;
    }
    Some((
        PathId::from(u32::try_from(path_id).ok()?),
        u8::try_from(priority).ok()?,
    ))
}

fn apply_path_priority(conn: &Connection, priorities: &PathPriorities, payload: &[u8]) {
    let Some((path_id, priority)) = parse_path_priority(payload) else {
        log::debug!("ignoring malformed PATH_PRIORITY frame");
        return;
    };
    // The peer announces a path once it is established, so it exists here
    // unless it was abandoned meanwhile.
    if conn.path(path_id).is_none() {
        log::debug!("path {path_id}: priority {priority} for a closed path ignored");
        return;
    }
    log::debug!("path {path_id}: peer set priority {priority}");
    priorities.set_base(conn, path_id, priority);
}

fn parse_path_rate(payload: &[u8]) -> Option<(PathId, u64)> {
    let (path_id, n) = varint::decode(payload)?;
    let (rate, m) = varint::decode(&payload[n..])?;
    if n + m != payload.len() || rate == 0 {
        return None;
    }
    Some((PathId::from(u32::try_from(path_id).ok()?), rate))
}

fn apply_path_rate(
    conn: &Connection,
    priorities: &PathPriorities,
    max_path_rate: Option<u64>,
    payload: &[u8],
) {
    let Some((path_id, requested)) = parse_path_rate(payload) else {
        log::debug!("ignoring malformed PATH_RATE frame");
        return;
    };
    let requested_text = crate::cc::format_rate(requested);
    let Some(max) = max_path_rate else {
        log::info!(
            "path {path_id}: peer asked for a fixed rate of {requested_text}bit/s; ignored \
             (no --max-path-rate), the path stays congestion-controlled"
        );
        return;
    };
    let rate = requested.min(max);
    if priorities.set_rate(conn, path_id, rate) {
        log::info!(
            "path {path_id}: fixed rate {}bit/s (peer asked for {requested_text}bit/s)",
            crate::cc::format_rate(rate)
        );
    } else {
        log::debug!("path {path_id}: rate for a closed path ignored");
    }
}

fn parse_settings(mut payload: &[u8]) -> Option<Vec<(u64, u64)>> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (id, n) = varint::decode(payload)?;
        payload = &payload[n..];
        let (value, n) = varint::decode(payload)?;
        payload = &payload[n..];
        out.push((id, value));
    }
    Some(out)
}

/// Value of the `:status` pseudo-header, if present and numeric.
pub fn status_of(fields: &[qpack::Field]) -> Option<u16> {
    header(fields, ":status").and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
}

/// First value of the named header.
pub fn header<'a>(fields: &'a [qpack::Field], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, _)| n == name.as_bytes())
        .map(|(_, v)| v.as_slice())
}

/// Buffered frame reader over a QUIC receive stream.
pub struct FrameReader {
    recv: RecvStream,
    buf: BytesMut,
    eof: bool,
}

impl FrameReader {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buf: BytesMut::new(),
            eof: false,
        }
    }

    /// Pull one more chunk into the buffer. Returns `false` at end of stream.
    async fn fill(&mut self) -> Result<bool> {
        if self.eof {
            return Ok(false);
        }
        match self.recv.read_chunk(64 * 1024).await? {
            Some(chunk) => {
                self.buf.extend_from_slice(&chunk);
                Ok(true)
            }
            None => {
                self.eof = true;
                Ok(false)
            }
        }
    }

    async fn read_varint(&mut self) -> Result<Option<u64>> {
        loop {
            if let Some((v, n)) = varint::decode(&self.buf) {
                self.buf.advance(n);
                return Ok(Some(v));
            }
            if !self.fill().await? {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(anyhow!("stream ended mid-varint"))
                };
            }
        }
    }

    /// Read one whole frame. `Ok(None)` at a clean end of stream.
    pub async fn read_frame(&mut self, max_len: usize) -> Result<Option<(u64, Bytes)>> {
        let Some(ty) = self.read_varint().await? else {
            return Ok(None);
        };
        let len = self
            .read_varint()
            .await?
            .ok_or_else(|| anyhow!("stream ended mid-frame"))? as usize;
        if len > max_len {
            bail!("frame type 0x{ty:x} of {len} bytes exceeds limit {max_len}");
        }
        while self.buf.len() < len {
            if !self.fill().await? {
                bail!("stream ended mid-frame");
            }
        }
        Ok(Some((ty, self.buf.split_to(len).freeze())))
    }

    /// Read frames until a HEADERS frame and decode it, skipping unknown
    /// (e.g. reserved/grease) frame types. `Ok(None)` at end of stream.
    pub async fn read_headers(&mut self) -> Result<Option<Vec<qpack::Field>>> {
        loop {
            match self.read_frame(MAX_HEADER_FRAME).await? {
                None => return Ok(None),
                Some((FRAME_HEADERS, payload)) => return qpack::decode(&payload).map(Some),
                Some((FRAME_DATA, _)) => bail!("DATA frame before HEADERS"),
                Some(_) => continue,
            }
        }
    }

    /// Discard everything until the stream ends. `Err` if it was reset or the
    /// connection was lost. Cancel-safe.
    pub async fn drain(&mut self) -> Result<()> {
        self.buf.clear();
        while self.fill().await? {
            self.buf.clear();
        }
        Ok(())
    }

    /// Ask the peer to stop sending on this stream.
    pub fn stop(&mut self, code: u32) {
        let _ = self.recv.stop(VarInt::from_u32(code));
    }
}
