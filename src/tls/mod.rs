//! BoringSSL as noq's TLS provider.
//!
//! noq ships a rustls backend, but rustls cannot terminate ECH on the server.
//! zeromasque gets ECH (and its SNI guard) from BoringSSL, so we keep BoringSSL
//! and plug it into noq through its `crypto::{ServerConfig, ClientConfig,
//! Session}` traits. Callers build a `boring::ssl::SslContextBuilder` exactly as
//! zeromasque did for quiche (certificates, ECH keys, SNI guard, trust roots)
//! and hand it to [`ServerTls::new`] / [`ClientTls::new`], which add the
//! QUIC-specific bits (ALPN `h3`, no session tickets, the 1-RTT key hook).

mod keys;
mod session;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use boring::ssl::{AlpnError, Ssl, SslContext, SslContextBuilder, SslOptions};
use foreign_types_shared::ForeignType;
use noq::crypto::{self, Keys, UnsupportedVersion};
use noq::{ConnectError, ConnectionId};
use noq_proto::transport_parameters::TransportParameters;

pub(crate) use keys::QUIC_V1;
use session::TlsSession;

/// ALPN wire list: HTTP/3 only.
const ALPN_H3_WIRE: &[u8] = b"\x02h3";

/// What the handshake negotiated, available from
/// `noq::Connection::handshake_data()` (downcast to this type).
#[derive(Debug, Clone)]
pub struct HandshakeData {
    /// The negotiated ALPN protocol (always `h3` once established).
    #[allow(dead_code)]
    pub protocol: Option<Vec<u8>>,
    /// The SNI the client sent (server side only). With ECH accepted this is
    /// the protected inner name.
    pub server_name: Option<String>,
    /// Whether Encrypted Client Hello was accepted on this connection.
    pub ech_accepted: bool,
}

/// Server-side TLS configuration for noq.
pub struct ServerTls {
    ctx: SslContext,
}

impl ServerTls {
    pub fn new(mut builder: SslContextBuilder) -> Result<Arc<Self>> {
        builder.set_alpn_select_callback(|_, client| {
            boring::ssl::select_next_proto(ALPN_H3_WIRE, client).ok_or(AlpnError::ALERT_FATAL)
        });
        // See `session::capture_client_app_secret`.
        builder.set_keylog_callback(session::capture_client_app_secret);
        // No resumption: tickets are pure overhead for a long-lived tunnel.
        builder.set_options(SslOptions::NO_TICKET);
        Ok(Arc::new(Self {
            ctx: builder.build(),
        }))
    }
}

impl crypto::ServerConfig for ServerTls {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        if version != QUIC_V1 {
            return Err(UnsupportedVersion);
        }
        Ok(keys::initial_keys(&dst_cid, noq::Side::Server))
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        keys::retry_tag(&orig_dst_cid, packet)
    }

    fn start_session(
        &self,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let ssl = Ssl::new(&self.ctx).expect("SSL_new failed");
        unsafe { boring_sys::SSL_set_accept_state(ssl.as_ptr()) };
        Box::new(TlsSession::new(ssl, noq::Side::Server, params).expect("QUIC TLS session setup"))
    }
}

/// Client-side TLS configuration for noq.
pub struct ClientTls {
    ctx: SslContext,
    verify_peer: bool,
    ech_config_list: Option<Vec<u8>>,
}

impl ClientTls {
    /// `verify_peer` additionally pins verification to the server name passed
    /// to `connect` (the context's verify mode decides whether a failure is
    /// fatal). `ech_config_list` offers Encrypted Client Hello.
    pub fn new(
        mut builder: SslContextBuilder,
        verify_peer: bool,
        ech_config_list: Option<Vec<u8>>,
    ) -> Result<Arc<Self>> {
        builder
            .set_alpn_protos(ALPN_H3_WIRE)
            .context("setting ALPN h3")?;
        Ok(Arc::new(Self {
            ctx: builder.build(),
            verify_peer,
            ech_config_list,
        }))
    }
}

impl crypto::ClientConfig for ClientTls {
    fn start_session(
        &self,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }
        let invalid =
            |what: &str| ConnectError::InvalidServerName(format!("{server_name}: {what}"));
        let mut ssl = Ssl::new(&self.ctx).map_err(|_| invalid("SSL_new failed"))?;
        unsafe { boring_sys::SSL_set_connect_state(ssl.as_ptr()) };
        match server_name.parse::<IpAddr>() {
            // IP literals are not valid SNI; verify the certificate's IP SAN.
            Ok(ip) => {
                if self.verify_peer {
                    ssl.param_mut().set_ip(ip).map_err(|_| invalid("bad IP"))?;
                }
            }
            Err(_) => {
                ssl.set_hostname(server_name)
                    .map_err(|_| invalid("bad SNI"))?;
                if self.verify_peer {
                    ssl.param_mut()
                        .set_host(server_name)
                        .map_err(|_| invalid("bad host name"))?;
                }
            }
        }
        if let Some(list) = &self.ech_config_list {
            offer_ech(&mut ssl, list).map_err(|e| invalid(&format!("ECH config: {e}")))?;
        }
        let mut session =
            TlsSession::new(ssl, noq::Side::Client, params).map_err(|e| invalid(&e))?;
        // Produce the ClientHello now; noq collects it via `write_handshake`.
        session
            .advance()
            .map_err(|e| invalid(&format!("ClientHello: {e}")))?;
        Ok(Box::new(session))
    }
}

/// Offer ECH on a client `SSL` with the given ECHConfigList.
pub(crate) fn offer_ech(ssl: &mut boring::ssl::SslRef, list: &[u8]) -> Result<()> {
    ssl.set_ech_config_list(list)
        .map_err(|e| anyhow::anyhow!("SSL_set1_ech_config_list failed: {e}"))
}
