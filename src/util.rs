//! Small helpers shared by the proxy server and client.

/// Scratch buffer size for a single UDP datagram read.
pub(crate) const RECV_BUF: usize = 65535;
/// Bound on the local channels shuttling packets between tasks.
pub(crate) const CHANNEL_CAP: usize = 1024;

/// noq keeps `PathId::as_u32` crate-private; recover the value from its public
/// varint wire encoding instead.
pub(crate) fn path_id_u32(path_id: noq::PathId) -> u32 {
    use noq_proto::coding::Encodable;
    if path_id == noq::PathId::ZERO {
        return 0;
    }
    let mut buf = [0u8; 8];
    let mut w = &mut buf[..];
    path_id.encode(&mut w);
    crate::varint::decode(&buf).map_or(0, |(v, _)| v as u32)
}

/// Lower-case hex encoding, for logging fingerprints.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
