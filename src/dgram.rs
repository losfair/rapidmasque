//! CONNECT-UDP HTTP/3 datagram framing (RFC 9297 + RFC 9298).
//!
//! The payload handed to / received from quiche's transport-level
//! `dgram_send`/`dgram_recv` is:
//!
//! ```text
//! Quarter-Stream-ID (varint) | Context-ID (varint) | UDP payload
//! ```
//!
//! The quarter-stream-id is `request_stream_id / 4` (RFC 9297 §2.1). Context-ID
//! `0` denotes a raw UDP payload (RFC 9298 §5).
//!
//! rapidmasque extension: context ID [`CONTEXT_ID_SEQUENCED_UDP`] is a UDP
//! payload preceded by a 4-byte big-endian sequence number, per flow and
//! direction, so the receiver can put datagrams that took different paths
//! back in order (`crate::reorder`). A flow uses it only when both ends agreed
//! to on the request (the `rapidmasque-sequence` header); other contexts are
//! dropped.

use crate::varint;

pub const CONTEXT_ID_UDP: u64 = 0;
/// Sequenced UDP payload (rapidmasque extension, client-allocated even ID).
pub const CONTEXT_ID_SEQUENCED_UDP: u64 = 2;
/// Bytes the sequence number adds to a datagram.
pub const SEQUENCE_LEN: usize = 4;
/// Request and response header that turns sequenced datagrams on for a flow:
/// a client that wants them sends it, and a proxy that agrees echoes it in its
/// 2xx response. Each end then numbers what it sends.
pub const SEQUENCE_HEADER: &str = "rapidmasque-sequence";
/// [`SEQUENCE_HEADER`]'s value (a structured-field boolean).
pub const SEQUENCE_HEADER_ON: &str = "?1";

/// Encode a UDP payload as a CONNECT-UDP HTTP datagram for `flow_id`.
pub fn encode(flow_id: u64, udp_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint::encoded_len(flow_id) + 1 + udp_payload.len());
    varint::encode(flow_id, &mut out);
    varint::encode(CONTEXT_ID_UDP, &mut out);
    out.extend_from_slice(udp_payload);
    out
}

/// Encode a UDP payload for `flow_id` with sequence number `seq`
/// ([`CONTEXT_ID_SEQUENCED_UDP`]).
pub fn encode_sequenced(flow_id: u64, seq: u32, udp_payload: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(varint::encoded_len(flow_id) + 1 + SEQUENCE_LEN + udp_payload.len());
    varint::encode(flow_id, &mut out);
    varint::encode(CONTEXT_ID_SEQUENCED_UDP, &mut out);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(udp_payload);
    out
}

/// Encode a UDP payload for `flow_id`, sequenced if `seq` is given.
pub fn encode_udp(flow_id: u64, seq: Option<u32>, udp_payload: &[u8]) -> Vec<u8> {
    match seq {
        Some(seq) => encode_sequenced(flow_id, seq, udp_payload),
        None => encode(flow_id, udp_payload),
    }
}

/// A received UDP payload and its sequence number, if it carried one; `None`
/// for contexts other than UDP and sequenced UDP.
pub fn udp_payload<'a>(parsed: &Parsed<'a>) -> Option<(Option<u32>, &'a [u8])> {
    match parsed.context_id {
        CONTEXT_ID_UDP => Some((None, parsed.payload)),
        CONTEXT_ID_SEQUENCED_UDP => {
            let (seq, payload) = parsed.payload.split_first_chunk::<SEQUENCE_LEN>()?;
            Some((Some(u32::from_be_bytes(*seq)), payload))
        }
        _ => None,
    }
}

/// Parsed view of a received HTTP datagram.
pub struct Parsed<'a> {
    pub flow_id: u64,
    pub context_id: u64,
    pub payload: &'a [u8],
}

/// Decode the flow id, context id and remaining UDP payload from a datagram.
pub fn decode(buf: &[u8]) -> Option<Parsed<'_>> {
    let (flow_id, n1) = varint::decode(buf)?;
    let (context_id, n2) = varint::decode(&buf[n1..])?;
    Some(Parsed {
        flow_id,
        context_id,
        payload: &buf[n1 + n2..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let d = encode(0, b"hello");
        let p = decode(&d).unwrap();
        assert_eq!(p.flow_id, 0);
        assert_eq!(p.context_id, CONTEXT_ID_UDP);
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn sequenced_roundtrip() {
        let d = encode_udp(9, Some(0xdead_beef), b"wg");
        assert_eq!(d.len(), 1 + 1 + SEQUENCE_LEN + 2);
        let p = decode(&d).unwrap();
        assert_eq!(p.flow_id, 9);
        assert_eq!(p.context_id, CONTEXT_ID_SEQUENCED_UDP);
        assert_eq!(udp_payload(&p), Some((Some(0xdead_beef), &b"wg"[..])));
        // Plain UDP has no sequence number.
        let d = encode_udp(9, None, b"wg");
        assert_eq!(udp_payload(&decode(&d).unwrap()), Some((None, &b"wg"[..])));
        // Truncated sequence numbers and unknown contexts are dropped.
        assert_eq!(udp_payload(&decode(&[9, 2, 0, 0]).unwrap()), None);
        assert_eq!(udp_payload(&decode(&[9, 4, 1]).unwrap()), None);
    }

    #[test]
    fn nonzero_flow_and_context() {
        let d = encode(7, b"x");
        let p = decode(&d).unwrap();
        assert_eq!(p.flow_id, 7);
        // context id is always 0 (UDP) in what we encode
        assert_eq!(p.context_id, 0);
        assert_eq!(p.payload, b"x");
    }
}
