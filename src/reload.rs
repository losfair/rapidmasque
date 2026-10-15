//! Certificate / ECH / rule-table hot reload, triggered by `SIGHUP`.
//!
//! tokio's signal driver turns SIGHUP into an async stream on every Unix
//! (Linux and macOS/BSD alike), so the reload runs on the runtime rather than
//! in an async-signal-unsafe handler. On each signal the TLS config and the
//! rule table are rebuilt from their files and swapped in together: the
//! endpoint's server config is replaced (new connections pick up rotated
//! material; live ones keep theirs) and new requests see the new rules. A failed
//! rebuild keeps the whole previous configuration.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use noq::Endpoint;
use tokio::signal::unix::{SignalKind, signal};

use crate::ech::key::EchKeySet;
use crate::quic;
use crate::rules::RuleTable;
use crate::server::ServerState;

/// Paths needed to rebuild the server config (TLS/ECH) and rule table on reload.
#[derive(Clone)]
pub struct ReloadPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ech_key: Option<PathBuf>,
    pub rules: PathBuf,
    /// Not a path, but part of what a rebuild needs.
    pub transport: quic::TransportOptions,
}

/// Install the SIGHUP handler and spawn the reload task. Returns once the
/// handler is installed, so a SIGHUP after this point never kills the process.
pub fn spawn_reload(endpoint: Endpoint, state: Arc<ServerState>, paths: ReloadPaths) -> Result<()> {
    let mut hup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            match rebuild(&paths) {
                Ok((config, rules)) => {
                    let n = rules.len();
                    endpoint.set_server_config(Some(config));
                    state.rules.store(Arc::new(rules));
                    log::info!("reloaded TLS/ECH configuration and {n} rule(s)");
                }
                Err(e) => log::error!("reload failed, keeping previous config: {e:?}"),
            }
        }
    });
    Ok(())
}

/// Rebuild both the TLS/ECH config and the rule table before swapping, so a
/// failure in either keeps the whole previous configuration.
fn rebuild(paths: &ReloadPaths) -> Result<(noq::ServerConfig, RuleTable)> {
    let ech = match &paths.ech_key {
        Some(path) => Some(
            EchKeySet::load(path)
                .with_context(|| format!("loading ECH keys from {}", path.display()))?,
        ),
        None => None,
    };
    let rules = RuleTable::load(&paths.rules)?;
    let config = quic::build_server_config(
        &paths.cert,
        &paths.key,
        ech.as_ref(),
        rules.allowed_sni_hosts(),
        paths.transport,
    )?;
    Ok((config, rules))
}
