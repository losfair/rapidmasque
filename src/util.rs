//! Small helpers shared by the proxy server and client.

/// Scratch buffer size for a single UDP datagram read.
pub(crate) const RECV_BUF: usize = 65535;
/// Bound on the local channels shuttling packets between tasks.
pub(crate) const CHANNEL_CAP: usize = 1024;

/// Lower-case hex encoding, for logging fingerprints.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
