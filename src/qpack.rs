//! Minimal QPACK (RFC 9204) for CONNECT-UDP header blocks.
//!
//! Both ends advertise a zero-capacity dynamic table, so a conforming peer only
//! uses the static table and literals. Decoding supports every static-only
//! representation (indexed, literal with static name reference, literal with
//! literal name) and Huffman-coded strings; any dynamic-table reference is an
//! error. Encoding never uses Huffman: it emits static indexed lines when an
//! exact match exists, a static name reference when only the name matches, and
//! otherwise a literal name.

use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::qpack_tables::{HUFFMAN_CODES, STATIC_TABLE};

/// A decoded header field: lower-cased name bytes and value bytes.
pub type Field = (Vec<u8>, Vec<u8>);

/// Encode a header list into a QPACK field section (no dynamic table).
pub fn encode(fields: &[(&str, &str)]) -> Vec<u8> {
    // Required Insert Count = 0, Sign = 0, Delta Base = 0.
    let mut out = vec![0x00, 0x00];
    for (name, value) in fields {
        let exact = STATIC_TABLE
            .iter()
            .position(|(n, v)| n == name && v == value);
        if let Some(idx) = exact {
            // Indexed field line, static table: 0b11xxxxxx.
            encode_int(&mut out, 0xc0, 6, idx as u64);
            continue;
        }
        match STATIC_TABLE.iter().position(|(n, _)| n == name) {
            Some(idx) => {
                // Literal with static name reference, N=0, T=1: 0b0101xxxx.
                encode_int(&mut out, 0x50, 4, idx as u64);
            }
            None => {
                // Literal with literal name, N=0, H=0: 0b00100xxx.
                encode_int(&mut out, 0x20, 3, name.len() as u64);
                out.extend_from_slice(name.as_bytes());
            }
        }
        encode_int(&mut out, 0x00, 7, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Decode a QPACK field section that references only the static table.
pub fn decode(buf: &[u8]) -> Result<Vec<Field>> {
    let mut pos = 0;
    let ric = decode_int(buf, &mut pos, 8)?;
    if ric != 0 {
        bail!("QPACK field section references the dynamic table (capacity is 0)");
    }
    let _delta_base = decode_int(buf, &mut pos, 7)?;

    let mut fields = Vec::new();
    while pos < buf.len() {
        let b = buf[pos];
        if b & 0x80 != 0 {
            // Indexed field line: 1Txxxxxx.
            if b & 0x40 == 0 {
                bail!("QPACK dynamic-table indexed field line");
            }
            let (n, v) = static_entry(decode_int(buf, &mut pos, 6)?)?;
            fields.push((n.as_bytes().to_vec(), v.as_bytes().to_vec()));
        } else if b & 0x40 != 0 {
            // Literal with name reference: 01NTxxxx.
            if b & 0x10 == 0 {
                bail!("QPACK dynamic-table name reference");
            }
            let (n, _) = static_entry(decode_int(buf, &mut pos, 4)?)?;
            let value = decode_string(buf, &mut pos, 7)?;
            fields.push((n.as_bytes().to_vec(), value));
        } else if b & 0x20 != 0 {
            // Literal with literal name: 001NHxxx.
            let name = decode_string(buf, &mut pos, 3)?;
            let value = decode_string(buf, &mut pos, 7)?;
            fields.push((name.to_ascii_lowercase(), value));
        } else {
            // 0001xxxx / 0000Nxxx: post-base (dynamic) references.
            bail!("QPACK post-base reference (dynamic table)");
        }
    }
    Ok(fields)
}

fn static_entry(idx: u64) -> Result<(&'static str, &'static str)> {
    STATIC_TABLE
        .get(idx as usize)
        .copied()
        .ok_or_else(|| anyhow!("QPACK static index {idx} out of range"))
}

/// RFC 7541 §5.1 prefixed integer, `flags` occupying the bits above the prefix.
fn encode_int(out: &mut Vec<u8>, flags: u8, prefix: u8, mut value: u64) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    value -= max;
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn decode_int(buf: &[u8], pos: &mut usize, prefix: u8) -> Result<u64> {
    let first = *buf
        .get(*pos)
        .ok_or_else(|| anyhow!("QPACK integer truncated"))?;
    *pos += 1;
    let max = (1u64 << prefix) - 1;
    let mut value = u64::from(first) & max;
    if value < max {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let b = *buf
            .get(*pos)
            .ok_or_else(|| anyhow!("QPACK integer truncated"))?;
        *pos += 1;
        if shift > 56 {
            bail!("QPACK integer overflow");
        }
        value += u64::from(b & 0x7f) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// A string literal whose length uses a `prefix`-bit integer; the Huffman flag
/// is the bit just above the prefix.
fn decode_string(buf: &[u8], pos: &mut usize, prefix: u8) -> Result<Vec<u8>> {
    let huffman = buf
        .get(*pos)
        .map(|b| b & (1 << prefix) != 0)
        .ok_or_else(|| anyhow!("QPACK string truncated"))?;
    let len = decode_int(buf, pos, prefix)? as usize;
    let end = pos
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| anyhow!("QPACK string truncated"))?;
    let raw = &buf[*pos..end];
    *pos = end;
    if huffman {
        huffman_decode(raw)
    } else {
        Ok(raw.to_vec())
    }
}

fn huffman_table() -> &'static HashMap<(u8, u32), u8> {
    static TABLE: OnceLock<HashMap<(u8, u32), u8>> = OnceLock::new();
    TABLE.get_or_init(|| {
        HUFFMAN_CODES
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((len, code), sym as u8))
            .collect()
    })
}

/// Decode an HPACK/QPACK Huffman string (RFC 7541 §5.2).
fn huffman_decode(input: &[u8]) -> Result<Vec<u8>> {
    let table = huffman_table();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let (mut code, mut len) = (0u32, 0u8);
    for &byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            len += 1;
            if let Some(&sym) = table.get(&(len, code)) {
                out.push(sym);
                code = 0;
                len = 0;
            } else if len >= 30 {
                bail!("invalid Huffman code");
            }
        }
    }
    // Padding: fewer than 8 bits, all ones (an EOS prefix).
    if len >= 8 || code != (1u32 << len) - 1 {
        bail!("invalid Huffman padding");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(n: &str, v: &str) -> Field {
        (n.as_bytes().to_vec(), v.as_bytes().to_vec())
    }

    #[test]
    fn roundtrip_connect_udp_request() {
        let headers = [
            (":method", "CONNECT"),
            (":protocol", "connect-udp"),
            (":scheme", "https"),
            (":authority", "proxy.example:4433"),
            (":path", "/connect?h=1&p=2"),
            ("capsule-protocol", "?1"),
        ];
        let block = encode(&headers);
        let decoded = decode(&block).unwrap();
        let expected: Vec<Field> = headers.iter().map(|(n, v)| field(n, v)).collect();
        assert_eq!(decoded, expected);
        // `:method CONNECT` is static index 15 -> a single indexed byte.
        assert_eq!(block[2], 0xc0 | 15);
    }

    #[test]
    fn prefixed_integers_roundtrip() {
        for v in [0u64, 1, 6, 7, 30, 31, 127, 128, 1337, 1 << 20] {
            for prefix in [3u8, 4, 6, 7, 8] {
                let mut out = Vec::new();
                encode_int(&mut out, 0, prefix, v);
                let mut pos = 0;
                assert_eq!(decode_int(&out, &mut pos, prefix).unwrap(), v);
                assert_eq!(pos, out.len());
            }
        }
    }

    #[test]
    fn huffman_rfc7541_vectors() {
        // RFC 7541 C.4.1: "www.example.com".
        let enc = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&enc).unwrap(), b"www.example.com");
        // RFC 7541 C.4.2: "no-cache".
        let enc = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(huffman_decode(&enc).unwrap(), b"no-cache");
        // Bad padding (zeros) is rejected.
        assert!(huffman_decode(&[0xf1, 0xe3, 0xc2, 0x00]).is_err());
    }

    #[test]
    fn decodes_huffman_literal_with_static_name_ref() {
        // `:authority` (static 0) = Huffman "www.example.com".
        let mut block = vec![0x00, 0x00, 0x50];
        block.push(0x80 | 12);
        block.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        // `:status 200` indexed (static 25).
        block.push(0xc0 | 25);
        let decoded = decode(&block).unwrap();
        assert_eq!(
            decoded,
            vec![
                field(":authority", "www.example.com"),
                field(":status", "200")
            ]
        );
    }

    #[test]
    fn rejects_dynamic_table_use() {
        assert!(decode(&[0x01, 0x00]).is_err()); // RIC != 0
        assert!(decode(&[0x00, 0x00, 0x80]).is_err()); // dynamic indexed
        assert!(decode(&[0x00, 0x00, 0x10]).is_err()); // post-base indexed
    }
}
