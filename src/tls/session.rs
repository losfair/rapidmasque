//! A noq `crypto::Session` driving BoringSSL's QUIC handshake API
//! (`SSL_set_quic_method`): BoringSSL produces and consumes CRYPTO-frame bytes
//! and hands over traffic secrets per encryption level; [`super::keys`] turns
//! those into packet protection.

use std::any::Any;
use std::ffi::c_int;
use std::sync::OnceLock;

use boring::ssl::{Ssl, SslRef};
use boring_sys as ffi;
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use noq::crypto::{self, ExportKeyingMaterialError, KeyPair, Keys};
use noq::{ConnectionId, Side, TransportErrorCode};
use noq_proto::TransportError;
use noq_proto::transport_parameters::TransportParameters;

use super::HandshakeData;
use super::keys::{self, Secret, Suite};

/// BoringSSL encryption levels, in `ssl_encryption_level_t` order.
const INITIAL: usize = 0;
const EARLY_DATA: usize = 1;
const HANDSHAKE: usize = 2;
const APPLICATION: usize = 3;
const LEVELS: usize = 4;

/// TLS alerts used when BoringSSL fails without reporting one.
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_INTERNAL_ERROR: u8 = 80;

static QUIC_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

/// `SSL` ex-data slot holding a pointer to the session's [`CallbackState`].
fn ex_index() -> c_int {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    *INDEX.get_or_init(|| unsafe {
        ffi::SSL_get_ex_new_index(0, std::ptr::null_mut(), std::ptr::null_mut(), None, None)
    })
}

/// Everything BoringSSL's callbacks write. Only touched through the raw pointer
/// (by callbacks during an FFI call, or by the session between FFI calls), so
/// no Rust reference to it is ever live across a call into BoringSSL.
#[derive(Default)]
struct CallbackState {
    suite: Option<Suite>,
    local: [Option<Secret>; LEVELS],
    remote: [Option<Secret>; LEVELS],
    /// Outbound handshake bytes per level, not yet handed to noq.
    outgoing: [Vec<u8>; LEVELS],
    alert: Option<u8>,
}

pub(crate) struct TlsSession {
    ssl: Ssl,
    cb: *mut CallbackState,
    side: Side,
    handshaking: bool,
    got_handshake_data: bool,
    /// The level noq is currently writing CRYPTO data at.
    write_level: usize,
    /// Application secrets for the next key update.
    next: Option<(Secret, Secret)>,
}

// The raw `CallbackState` pointer is owned by the session and only accessed
// under `&mut self` (or `&self` for reads with no concurrent writer).
unsafe impl Send for TlsSession {}
unsafe impl Sync for TlsSession {}

impl TlsSession {
    /// Wrap a configured `Ssl` (connect or accept state already set) and attach
    /// the QUIC method and our transport parameters.
    pub(crate) fn new(ssl: Ssl, side: Side, params: &TransportParameters) -> Result<Self, String> {
        let cb = Box::into_raw(Box::<CallbackState>::default());
        let session = Self {
            ssl,
            cb,
            side,
            handshaking: true,
            got_handshake_data: false,
            write_level: INITIAL,
            next: None,
        };
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        let ptr = session.ssl.as_ptr();
        unsafe {
            if ffi::SSL_set_ex_data(ptr, ex_index(), cb.cast()) != 1 {
                return Err("SSL_set_ex_data failed".into());
            }
            if ffi::SSL_set_quic_method(ptr, &QUIC_METHOD) != 1 {
                return Err("SSL_set_quic_method failed".into());
            }
            ffi::SSL_set_quic_use_legacy_codepoint(ptr, 0);
            if ffi::SSL_set_quic_transport_params(ptr, encoded.as_ptr(), encoded.len()) != 1 {
                return Err("SSL_set_quic_transport_params failed".into());
            }
        }
        Ok(session)
    }

    fn cb(&self) -> &CallbackState {
        unsafe { &*self.cb }
    }

    fn cb_mut(&mut self) -> &mut CallbackState {
        unsafe { &mut *self.cb }
    }

    /// Run the handshake as far as the data provided so far allows. Clients
    /// call this once up front to produce the ClientHello.
    pub(crate) fn advance(&mut self) -> Result<(), TransportError> {
        let ptr = self.ssl.as_ptr();
        if self.handshaking {
            let rc = unsafe { ffi::SSL_do_handshake(ptr) };
            if rc == 1 {
                self.handshaking = false;
            } else {
                self.check(rc)?;
            }
        } else {
            let rc = unsafe { ffi::SSL_process_quic_post_handshake(ptr) };
            if rc != 1 {
                self.check(rc)?;
            }
        }
        Ok(())
    }

    /// Classify a non-success BoringSSL return code: "needs more input" is fine,
    /// anything else is a fatal handshake error carrying the TLS alert.
    fn check(&mut self, rc: c_int) -> Result<(), TransportError> {
        let err = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), rc) };
        match err {
            ffi::SSL_ERROR_WANT_READ
            | ffi::SSL_ERROR_WANT_WRITE
            | ffi::SSL_ERROR_PENDING_SESSION
            | ffi::SSL_ERROR_PENDING_CERTIFICATE
            | ffi::SSL_ERROR_PENDING_TICKET
            | ffi::SSL_ERROR_WANT_X509_LOOKUP
            | ffi::SSL_ERROR_WANT_PRIVATE_KEY_OPERATION
            | ffi::SSL_ERROR_WANT_CERTIFICATE_VERIFY => Ok(()),
            _ => {
                let stack = boring::error::ErrorStack::get();
                let alert = self.cb().alert.unwrap_or(if err == ffi::SSL_ERROR_SSL {
                    ALERT_HANDSHAKE_FAILURE
                } else {
                    ALERT_INTERNAL_ERROR
                });
                Err(TransportError::new(
                    TransportErrorCode::crypto(alert),
                    format!("TLS handshake failed: {stack}"),
                ))
            }
        }
    }

    fn handshake_info_ready(&self) -> bool {
        if !self.handshaking {
            return true;
        }
        let ssl: &SslRef = &self.ssl;
        ssl.selected_alpn_protocol().is_some()
            || (self.side == Side::Server
                && ssl.servername(boring::ssl::NameType::HOST_NAME).is_some())
    }
}

impl Drop for TlsSession {
    fn drop(&mut self) {
        unsafe {
            ffi::SSL_set_ex_data(self.ssl.as_ptr(), ex_index(), std::ptr::null_mut());
            drop(Box::from_raw(self.cb));
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: ConnectionId, side: Side) -> Keys {
        keys::initial_keys(&dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.got_handshake_data {
            return None;
        }
        let ssl: &SslRef = &self.ssl;
        Some(Box::new(HandshakeData {
            protocol: ssl.selected_alpn_protocol().map(<[u8]>::to_vec),
            server_name: match self.side {
                Side::Server => ssl
                    .servername(boring::ssl::NameType::HOST_NAME)
                    .map(str::to_owned),
                Side::Client => None,
            },
            ech_accepted: unsafe { ffi::SSL_ech_accepted(ssl.as_ptr()) == 1 },
        }))
    }

    /// The peer's leaf certificate in DER, as `Vec<u8>`.
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        let cert = self.ssl.peer_certificate()?;
        cert.to_der().ok().map(|der| Box::new(der) as Box<dyn Any>)
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None // 0-RTT is not offered or accepted.
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.side {
            Side::Client => Some(false),
            Side::Server => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        let ptr = self.ssl.as_ptr();
        let rc = unsafe {
            let level = ffi::SSL_quic_read_level(ptr);
            ffi::SSL_provide_quic_data(ptr, level, buf.as_ptr(), buf.len())
        };
        if rc != 1 {
            self.check(rc)?;
        }
        self.advance()?;
        if !self.got_handshake_data && self.handshake_info_ready() {
            self.got_handshake_data = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let mut ptr: *const u8 = std::ptr::null();
        let mut len = 0usize;
        unsafe { ffi::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut ptr, &mut len) };
        if len == 0 {
            return Ok(None);
        }
        let mut buf = unsafe { std::slice::from_raw_parts(ptr, len) };
        Ok(Some(TransportParameters::read(self.side, &mut buf)?))
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let level = self.write_level;
        buf.append(&mut self.cb_mut().outgoing[level]);

        // Move to the next level once both directions' secrets exist for it.
        let next = match level {
            INITIAL => HANDSHAKE,
            HANDSHAKE => APPLICATION,
            _ => return None,
        };
        let cb = self.cb();
        let (Some(local), Some(remote)) = (cb.local[next].clone(), cb.remote[next].clone()) else {
            return None;
        };
        self.write_level = next;
        if next == APPLICATION {
            self.next = Some((local.update(), remote.update()));
        }
        Some(keys::keys(&local, &remote))
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let (local, remote) = self.next.as_mut()?;
        let pair = KeyPair {
            local: local.packet_key(),
            remote: remote.packet_key(),
        };
        *local = local.update();
        *remote = remote.update();
        Some(pair)
    }

    fn is_valid_retry(&self, orig_dst_cid: ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        keys::is_valid_retry(&orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let ok = unsafe {
            ffi::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr().cast(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if ok == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}

/// The callback state attached to `ssl`, if it is one of our sessions.
unsafe fn state<'a>(ssl: *const ffi::SSL) -> Option<&'a mut CallbackState> {
    unsafe {
        let p = ffi::SSL_get_ex_data(ssl, ex_index()) as *mut CallbackState;
        p.as_mut()
    }
}

fn record_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
    local: bool,
) -> c_int {
    let Some(st) = (unsafe { state(ssl) }) else {
        return 0;
    };
    let id = unsafe { ffi::SSL_CIPHER_get_protocol_id(cipher) };
    let Some(suite) = Suite::from_protocol_id(id) else {
        log::warn!("unsupported TLS cipher suite 0x{id:04x}");
        return 0;
    };
    let level = level.0 as usize;
    if level >= LEVELS || level == EARLY_DATA {
        return 1; // 0-RTT keys are never used.
    }
    st.suite = Some(suite);
    let secret = Secret::new(suite, unsafe { std::slice::from_raw_parts(secret, len) });
    if local {
        st.local[level] = Some(secret);
    } else {
        st.remote[level] = Some(secret);
    }
    1
}

extern "C" fn set_read_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
) -> c_int {
    record_secret(ssl, level, cipher, secret, len, false)
}

extern "C" fn set_write_secret(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    len: usize,
) -> c_int {
    record_secret(ssl, level, cipher, secret, len, true)
}

extern "C" fn add_handshake_data(
    ssl: *mut ffi::SSL,
    level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(st) = (unsafe { state(ssl) }) else {
        return 0;
    };
    let level = level.0 as usize;
    if level >= LEVELS {
        return 0;
    }
    st.outgoing[level].extend_from_slice(unsafe { std::slice::from_raw_parts(data, len) });
    1
}

extern "C" fn flush_flight(_ssl: *mut ffi::SSL) -> c_int {
    1
}

extern "C" fn send_alert(
    ssl: *mut ffi::SSL,
    _level: ffi::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    if let Some(st) = unsafe { state(ssl) } {
        st.alert = Some(alert);
    }
    1
}

/// Keylog hook installed on server contexts. BoringSSL only installs the
/// server's 1-RTT *read* secret after the client Finished arrives, but noq
/// needs both 1-RTT directions as soon as the server flight is written. The
/// client application secret is already derived (and keylogged) at that point,
/// so capture it here.
pub(crate) fn capture_client_app_secret(ssl: &SslRef, line: &str) {
    let mut parts = line.split_ascii_whitespace();
    if parts.next() != Some("CLIENT_TRAFFIC_SECRET_0") {
        return;
    }
    let (Some(_random), Some(hex)) = (parts.next(), parts.next()) else {
        return;
    };
    let Some(st) = (unsafe { state(ssl.as_ptr()) }) else {
        return;
    };
    let (Some(suite), Some(bytes)) = (st.suite, decode_hex(hex)) else {
        return;
    };
    st.remote[APPLICATION] = Some(Secret::new(suite, &bytes));
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
