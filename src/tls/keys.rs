//! QUIC packet protection (RFC 9001 §5) on BoringSSL primitives.
//!
//! The handshake hands us raw TLS 1.3 traffic secrets; everything QUIC derives
//! from them lives here: the `quic key` / `quic iv` / `quic hp` expansion, AEAD
//! payload protection with the multipath nonce (draft-ietf-quic-multipath
//! §2.4: the path ID is folded into the IV alongside the packet number), header
//! protection, initial secrets, key updates and Retry integrity tags.

use std::ffi::c_int;
use std::mem::MaybeUninit;

use boring_sys as ffi;
use bytes::BytesMut;
use noq::crypto::{self, CryptoError, KeyPair, Keys};
use noq::{ConnectionId, PathId, Side};

/// QUIC version 1 (RFC 9000), the only version this backend speaks.
pub(crate) const QUIC_V1: u32 = 0x0000_0001;

/// RFC 9001 §5.2 initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// RFC 9001 §5.8 Retry integrity key/nonce for QUIC v1.
const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SAMPLE_LEN: usize = 16;

/// The TLS 1.3 cipher suites QUIC can negotiate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Suite {
    /// Map a TLS cipher suite code point (`SSL_CIPHER_get_protocol_id`).
    pub(crate) fn from_protocol_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::Aes128Gcm),
            0x1302 => Some(Self::Aes256Gcm),
            0x1303 => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }

    fn digest(self) -> *const ffi::EVP_MD {
        unsafe {
            match self {
                Self::Aes256Gcm => ffi::EVP_sha384(),
                Self::Aes128Gcm | Self::Chacha20Poly1305 => ffi::EVP_sha256(),
            }
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 48,
            Self::Aes128Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    fn aead(self) -> *const ffi::EVP_AEAD {
        unsafe {
            match self {
                Self::Aes128Gcm => ffi::EVP_aead_aes_128_gcm(),
                Self::Aes256Gcm => ffi::EVP_aead_aes_256_gcm(),
                Self::Chacha20Poly1305 => ffi::EVP_aead_chacha20_poly1305(),
            }
        }
    }

    /// RFC 9001 §6.6 confidentiality limit.
    fn confidentiality_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 23,
            Self::Chacha20Poly1305 => u64::MAX,
        }
    }

    /// RFC 9001 §6.6 integrity limit.
    fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 52,
            Self::Chacha20Poly1305 => 1 << 36,
        }
    }
}

/// A TLS 1.3 traffic secret together with the suite it belongs to.
#[derive(Clone)]
pub(crate) struct Secret {
    suite: Suite,
    bytes: Vec<u8>,
}

impl Secret {
    pub(crate) fn new(suite: Suite, bytes: &[u8]) -> Self {
        Self {
            suite,
            bytes: bytes.to_vec(),
        }
    }

    fn expand(&self, label: &[u8], len: usize) -> Vec<u8> {
        hkdf_expand_label(self.suite.digest(), &self.bytes, label, len)
    }

    /// The next-generation secret for a key update (RFC 9001 §6.1).
    pub(crate) fn update(&self) -> Self {
        Self {
            suite: self.suite,
            bytes: self.expand(b"quic ku", self.suite.hash_len()),
        }
    }

    pub(crate) fn packet_key(&self) -> Box<dyn crypto::PacketKey> {
        let key = self.expand(b"quic key", self.suite.key_len());
        let iv = self.expand(b"quic iv", NONCE_LEN);
        Box::new(PacketKey::new(self.suite, &key, iv.try_into().unwrap()))
    }

    pub(crate) fn header_key(&self) -> Box<dyn crypto::HeaderKey> {
        let key = self.expand(b"quic hp", self.suite.key_len());
        Box::new(HeaderKey::new(self.suite, &key))
    }
}

/// Build a full key set from the local (encrypt) and remote (decrypt) secrets.
pub(crate) fn keys(local: &Secret, remote: &Secret) -> Keys {
    Keys {
        header: KeyPair {
            local: local.header_key(),
            remote: remote.header_key(),
        },
        packet: KeyPair {
            local: local.packet_key(),
            remote: remote.packet_key(),
        },
    }
}

/// Initial keys (RFC 9001 §5.2), derived from the client's first DCID.
pub(crate) fn initial_keys(dst_cid: &ConnectionId, side: Side) -> Keys {
    let mut initial = [0u8; 32];
    let mut out_len = 0usize;
    let ok = unsafe {
        ffi::HKDF_extract(
            initial.as_mut_ptr(),
            &mut out_len,
            ffi::EVP_sha256(),
            dst_cid.as_ptr(),
            dst_cid.len(),
            INITIAL_SALT_V1.as_ptr(),
            INITIAL_SALT_V1.len(),
        )
    };
    assert!(ok == 1 && out_len == initial.len(), "HKDF_extract failed");
    let suite = Suite::Aes128Gcm;
    let client = Secret::new(
        suite,
        &hkdf_expand_label(suite.digest(), &initial, b"client in", 32),
    );
    let server = Secret::new(
        suite,
        &hkdf_expand_label(suite.digest(), &initial, b"server in", 32),
    );
    match side {
        Side::Client => keys(&client, &server),
        Side::Server => keys(&server, &client),
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context.
fn hkdf_expand_label(md: *const ffi::EVP_MD, secret: &[u8], label: &[u8], len: usize) -> Vec<u8> {
    const PREFIX: &[u8] = b"tls13 ";
    let mut info = Vec::with_capacity(4 + PREFIX.len() + label.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(0); // empty context
    let mut out = vec![0u8; len];
    let ok = unsafe {
        ffi::HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            md,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    assert_eq!(ok, 1, "HKDF_expand failed");
    out
}

/// An initialised BoringSSL AEAD context. `seal`/`open` take a const context and
/// are safe to call concurrently, so this is `Send + Sync`. Boxed so its address
/// is stable (some AEADs keep internal pointers).
struct Aead(Box<ffi::EVP_AEAD_CTX>);

unsafe impl Send for Aead {}
unsafe impl Sync for Aead {}

impl Aead {
    fn new(suite: Suite, key: &[u8]) -> Self {
        let mut ctx: Box<MaybeUninit<ffi::EVP_AEAD_CTX>> = Box::new(MaybeUninit::zeroed());
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_init(
                ctx.as_mut_ptr(),
                suite.aead(),
                key.as_ptr(),
                key.len(),
                TAG_LEN,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(ok, 1, "EVP_AEAD_CTX_init failed");
        // Safety: initialised by EVP_AEAD_CTX_init above.
        Self(unsafe { Box::from_raw(Box::into_raw(ctx).cast()) })
    }

    /// Encrypt `data` in place, writing the tag to `tag`.
    fn seal(&self, nonce: &[u8; NONCE_LEN], ad: &[u8], data: &mut [u8], tag: &mut [u8]) -> bool {
        let mut tag_len = 0usize;
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_seal_scatter(
                &*self.0,
                data.as_mut_ptr(),
                tag.as_mut_ptr(),
                &mut tag_len,
                tag.len(),
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                ad.as_ptr(),
                ad.len(),
            )
        };
        ok == 1 && tag_len == TAG_LEN
    }

    /// Decrypt `data` (ciphertext || tag) in place; returns the plaintext length.
    fn open(&self, nonce: &[u8; NONCE_LEN], ad: &[u8], data: &mut [u8]) -> Option<usize> {
        let mut out_len = 0usize;
        let ok = unsafe {
            ffi::EVP_AEAD_CTX_open(
                &*self.0,
                data.as_mut_ptr(),
                &mut out_len,
                data.len(),
                nonce.as_ptr(),
                nonce.len(),
                data.as_ptr(),
                data.len(),
                ad.as_ptr(),
                ad.len(),
            )
        };
        (ok == 1).then_some(out_len)
    }
}

impl Drop for Aead {
    fn drop(&mut self) {
        unsafe { ffi::EVP_AEAD_CTX_cleanup(&mut *self.0) };
    }
}

struct PacketKey {
    suite: Suite,
    aead: Aead,
    iv: [u8; NONCE_LEN],
}

impl PacketKey {
    fn new(suite: Suite, key: &[u8], iv: [u8; NONCE_LEN]) -> Self {
        Self {
            suite,
            aead: Aead::new(suite, key),
            iv,
        }
    }

    /// Multipath nonce: the IV XORed with `path_id (32 bits) || pn (64 bits)`.
    /// For path 0 this is exactly the RFC 9001 §5.3 nonce.
    fn nonce(&self, path_id: PathId, pn: u64) -> [u8; NONCE_LEN] {
        let mut nonce = self.iv;
        for (n, p) in nonce[..4]
            .iter_mut()
            .zip(path_id_u32(path_id).to_be_bytes())
        {
            *n ^= p;
        }
        for (n, p) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *n ^= p;
        }
        nonce
    }
}

impl crypto::PacketKey for PacketKey {
    fn encrypt(&self, path_id: PathId, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, rest) = buf.split_at_mut(header_len);
        let (payload, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        let nonce = self.nonce(path_id, packet);
        assert!(
            self.aead.seal(&nonce, header, payload, tag),
            "AEAD seal failed"
        );
    }

    fn decrypt(
        &self,
        path_id: PathId,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let nonce = self.nonce(path_id, packet);
        let len = self
            .aead
            .open(&nonce, header, payload.as_mut())
            .ok_or(CryptoError)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.suite.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.suite.integrity_limit()
    }
}

/// noq keeps `PathId::as_u32` crate-private; recover the value from its public
/// varint wire encoding instead.
fn path_id_u32(path_id: PathId) -> u32 {
    use noq_proto::coding::Encodable;
    if path_id == PathId::ZERO {
        return 0;
    }
    let mut buf = [0u8; 8];
    let mut w = &mut buf[..];
    path_id.encode(&mut w);
    crate::varint::decode(&buf).map_or(0, |(v, _)| v as u32)
}

/// Header protection (RFC 9001 §5.4).
enum HeaderKey {
    Aes(Box<ffi::AES_KEY>),
    Chacha([u8; 32]),
}

// The AES key schedule is only read after construction.
unsafe impl Send for HeaderKey {}
unsafe impl Sync for HeaderKey {}

impl HeaderKey {
    fn new(suite: Suite, key: &[u8]) -> Self {
        match suite {
            Suite::Aes128Gcm | Suite::Aes256Gcm => {
                let mut aes: Box<MaybeUninit<ffi::AES_KEY>> = Box::new(MaybeUninit::zeroed());
                let rc = unsafe {
                    ffi::AES_set_encrypt_key(key.as_ptr(), (key.len() * 8) as _, aes.as_mut_ptr())
                };
                assert_eq!(rc, 0, "AES_set_encrypt_key failed");
                Self::Aes(unsafe { Box::from_raw(Box::into_raw(aes).cast()) })
            }
            Suite::Chacha20Poly1305 => Self::Chacha(key.try_into().unwrap()),
        }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let mut mask = [0u8; 5];
        match self {
            Self::Aes(key) => {
                let mut block = [0u8; 16];
                unsafe { ffi::AES_encrypt(sample.as_ptr(), block.as_mut_ptr(), &**key) };
                mask.copy_from_slice(&block[..5]);
            }
            Self::Chacha(key) => {
                let counter = u32::from_le_bytes(sample[..4].try_into().unwrap());
                let zeros = [0u8; 5];
                unsafe {
                    ffi::CRYPTO_chacha_20(
                        mask.as_mut_ptr(),
                        zeros.as_ptr(),
                        zeros.len(),
                        key.as_ptr(),
                        sample[4..16].as_ptr(),
                        counter,
                    )
                };
            }
        }
        mask
    }

    fn apply(&self, pn_offset: usize, packet: &mut [u8], decrypting: bool) {
        let sample_start = pn_offset + 4;
        let mask = self.mask(&packet[sample_start..sample_start + SAMPLE_LEN]);
        let first_mask = if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        if decrypting {
            packet[0] ^= mask[0] & first_mask;
        }
        let pn_len = (packet[0] & 0x03) as usize + 1;
        if !decrypting {
            packet[0] ^= mask[0] & first_mask;
        }
        for (b, m) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *b ^= m;
        }
    }
}

impl crypto::HeaderKey for HeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }

    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

/// Retry integrity tag (RFC 9001 §5.8) over the Retry pseudo-packet.
pub(crate) fn retry_tag(orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; TAG_LEN] {
    let mut pseudo = Vec::with_capacity(1 + orig_dst_cid.len() + packet.len());
    pseudo.push(orig_dst_cid.len() as u8);
    pseudo.extend_from_slice(orig_dst_cid);
    pseudo.extend_from_slice(packet);
    let aead = Aead::new(Suite::Aes128Gcm, &RETRY_KEY_V1);
    let mut tag = [0u8; TAG_LEN];
    assert!(
        aead.seal(&RETRY_NONCE_V1, &pseudo, &mut [], &mut tag),
        "retry tag seal failed"
    );
    tag
}

/// Verify a received Retry packet's integrity tag (`payload` ends with it).
pub(crate) fn is_valid_retry(orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
    let Some(split) = payload.len().checked_sub(TAG_LEN) else {
        return false;
    };
    let mut packet = Vec::with_capacity(header.len() + split);
    packet.extend_from_slice(header);
    packet.extend_from_slice(&payload[..split]);
    let expected = retry_tag(orig_dst_cid, &packet);
    let tag = &payload[split..];
    unsafe {
        ffi::CRYPTO_memcmp(expected.as_ptr().cast(), tag.as_ptr().cast(), TAG_LEN) == 0 as c_int
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9001 Appendix A.1: initial secrets / keys for DCID 0x8394c8f03e515708.
    #[test]
    fn rfc9001_initial_key_derivation() {
        let suite = Suite::Aes128Gcm;
        let dcid = hex("8394c8f03e515708");
        let mut initial = [0u8; 32];
        let mut n = 0;
        unsafe {
            ffi::HKDF_extract(
                initial.as_mut_ptr(),
                &mut n,
                ffi::EVP_sha256(),
                dcid.as_ptr(),
                dcid.len(),
                INITIAL_SALT_V1.as_ptr(),
                INITIAL_SALT_V1.len(),
            );
        }
        assert_eq!(
            initial.to_vec(),
            hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
        let client = Secret::new(
            suite,
            &hkdf_expand_label(suite.digest(), &initial, b"client in", 32),
        );
        assert_eq!(
            client.bytes,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            client.expand(b"quic key", 16),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            client.expand(b"quic iv", 12),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            client.expand(b"quic hp", 16),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
    }

    /// RFC 9001 Appendix A.5: ChaCha20-Poly1305 short header packet.
    #[test]
    fn rfc9001_chacha20_short_header() {
        let secret = Secret::new(
            Suite::Chacha20Poly1305,
            &hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
        );
        let pk = secret.packet_key();
        let hk = secret.header_key();
        // Header 4200bff4, pn 654360564, payload 01 (PING).
        let mut packet = hex("4200bff401");
        packet.extend_from_slice(&[0u8; 16]);
        pk.encrypt(PathId::ZERO, 654_360_564, &mut packet, 4);
        hk.encrypt(1, &mut packet);
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

        // And back.
        hk.decrypt(1, &mut packet);
        assert_eq!(&packet[..4], &hex("4200bff4")[..]);
        let mut payload = BytesMut::from(&packet[4..]);
        pk.decrypt(PathId::ZERO, 654_360_564, &packet[..4], &mut payload)
            .unwrap();
        assert_eq!(&payload[..], &[0x01]);
    }

    /// RFC 9001 Appendix A.4: Retry integrity tag.
    #[test]
    fn rfc9001_retry_tag() {
        let odcid = ConnectionId::new(&hex("8394c8f03e515708"));
        let packet = hex("ff000000010008f067a5502a4262b5746f6b656e");
        let tag = retry_tag(&odcid, &packet);
        assert_eq!(tag.to_vec(), hex("04a265ba2eff4d829058fb3f0f2496ba"));
        let mut payload = hex("746f6b656e");
        payload.extend_from_slice(&tag);
        assert!(is_valid_retry(&odcid, &packet[..15], &payload));
        payload[6] ^= 1;
        assert!(!is_valid_retry(&odcid, &packet[..15], &payload));
    }

    #[test]
    fn multipath_nonce_differs_per_path() {
        let secret = Secret::new(Suite::Aes128Gcm, &[7u8; 32]);
        let pk = secret.packet_key();
        let seal = |path: u32| {
            let mut buf = vec![0xc3, 1, 2, 3, 4, 5, 6, 7];
            buf.extend_from_slice(&[0u8; 16]);
            pk.encrypt(PathId::from(path), 9, &mut buf, 4);
            buf
        };
        let p0 = seal(0);
        let p1 = seal(1);
        assert_ne!(p0, p1);
        // Opening with the wrong path ID fails; the right one succeeds.
        let mut wrong = BytesMut::from(&p1[4..]);
        assert!(pk.decrypt(PathId::ZERO, 9, &p1[..4], &mut wrong).is_err());
        let mut right = BytesMut::from(&p1[4..]);
        pk.decrypt(PathId::from(1u32), 9, &p1[..4], &mut right)
            .unwrap();
        assert_eq!(&right[..], &[4, 5, 6, 7]);
    }
}
