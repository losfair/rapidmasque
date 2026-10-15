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

/// `addr` with an IPv4-mapped IPv6 address turned back into IPv4. On a
/// dual-stack socket noq reports IPv4 peers in mapped form
/// (`[::ffff:192.0.2.1]:443`).
pub(crate) fn canonical(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    std::net::SocketAddr::new(addr.ip().to_canonical(), addr.port())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_unmaps_ipv4_mapped_addresses() {
        let mapped: std::net::SocketAddr = "[::ffff:127.0.0.3]:4433".parse().unwrap();
        assert_eq!(canonical(mapped), "127.0.0.3:4433".parse().unwrap());
        let v6: std::net::SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(canonical(v6), v6);
        let v4: std::net::SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(canonical(v4), v4);
    }
}
