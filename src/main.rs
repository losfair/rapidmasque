mod cc;
mod cli;
mod client;
mod dgram;
#[cfg(test)]
mod e2e_test;
mod ech;
#[cfg(test)]
mod ech_test;
mod endpoint;
mod h3;
#[cfg(all(target_os = "openbsd", target_arch = "aarch64"))]
mod openbsd_arm64;
mod qpack;
mod qpack_tables;
mod quic;
mod reload;
mod rules;
mod server;
mod tls;
mod util;
mod varint;

use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use noq::{Endpoint, TokioRuntime};

use crate::cli::{Cli, ClientArgs, Command, GenEchArgs, ServeArgs};
use crate::ech::key::EchKeySet;
use crate::endpoint::Endpoint as ProxyEndpoint;
use crate::quic::Verify;
use crate::reload::{ReloadPaths, spawn_reload};
use crate::server::ServerState;

fn main() -> Result<()> {
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => serve(args),
        Command::Client(args) => client(args),
        Command::GenEchKey(args) => gen_ech_key(args),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
}

fn serve(args: ServeArgs) -> Result<()> {
    let rule_table = rules::RuleTable::load(&args.rules)
        .with_context(|| format!("loading rule table {}", args.rules.display()))?;
    eprintln!("loaded {} forwarding rule(s)", rule_table.len());
    let privileged = rule_table.privileged_count();
    if privileged > 0 {
        eprintln!(
            "{privileged} rule(s) use transparent forwarding and/or fwmark; these need \
             CAP_NET_ADMIN (transparent also requires routing the target's replies back)"
        );
    }

    // Build the initial config eagerly so config errors fail fast (before the
    // runtime is up). ECH keys are loaded here too.
    let ech = match &args.ech_key {
        Some(path) => {
            let set = EchKeySet::load(path)
                .with_context(|| format!("loading ECH keys from {}", path.display()))?;
            use base64ct::{Base64, Encoding};
            let list_b64 = Base64::encode_string(&set.config_list_bytes());
            eprintln!(
                "ECH enabled: {} key(s). On ECH acceptance only the inner SNI is \
                 authenticated; the public name needs a valid cert for the rejection fallback.",
                set.pairs.len()
            );
            eprintln!("Publish in the DNS HTTPS record: ech=\"{list_b64}\"");
            Some(set)
        }
        None => None,
    };

    let config = quic::build_server_config(
        &args.cert,
        &args.key,
        ech.as_ref(),
        rule_table.allowed_sni_hosts(),
        args.congestion_control,
    )?;
    let state = Arc::new(ServerState {
        rules: ArcSwap::from_pointee(rule_table),
    });
    let reload_paths = ReloadPaths {
        cert: args.cert.clone(),
        key: args.key.clone(),
        ech_key: args.ech_key.clone(),
        rules: args.rules.clone(),
        congestion_control: args.congestion_control,
    };

    runtime().block_on(async move {
        let socket = quic::bind_endpoint_socket(args.addr)
            .with_context(|| format!("binding QUIC listener {}", args.addr))?;
        let endpoint = Endpoint::new(
            quic::endpoint_config(),
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )
        .context("creating QUIC endpoint")?;
        eprintln!("rapidmasque proxy listening on {} (udp)", args.addr);

        spawn_reload(endpoint.clone(), state.clone(), reload_paths)?;
        server::run(endpoint, state).await
    })
}

fn client(args: ClientArgs) -> Result<()> {
    let endpoint = ProxyEndpoint::parse(&args.endpoint)?;

    let verify = if args.insecure {
        Verify::Insecure
    } else {
        Verify::Roots {
            ca_file: args.ca.clone(),
        }
    };

    let opts = client::ProxyOptions {
        conn: client::ConnectParams {
            endpoint,
            proxy_addr: args.proxy_addr,
            verify,
            ech_config_list: load_ech_config(&args)?,
            paths: args.paths.clone(),
            congestion_control: args.congestion_control,
        },
        listen: args.listen,
    };

    runtime().block_on(client::run_proxy(opts))
}

fn gen_ech_key(args: GenEchArgs) -> Result<()> {
    ech::keygen::run(&args.public_name)
}

fn load_ech_config(args: &ClientArgs) -> Result<Option<Vec<u8>>> {
    use base64ct::{Base64, Encoding};
    // `--ech-config` and `--ech-config-file` are mutually exclusive (clap).
    let b64 = match (&args.ech_config, &args.ech_config_file) {
        (Some(s), _) => s.trim().to_string(),
        (_, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading ECH config file {}", path.display()))?
            .trim()
            .to_string(),
        (None, None) => return Ok(None),
    };
    Base64::decode_vec(&b64)
        .map(Some)
        .map_err(|e| anyhow::anyhow!("invalid base64 ECHConfigList: {e}"))
}

fn init_logging() {
    // Minimal stderr logger; honour RUST_LOG=off/error/warn/info/debug/trace.
    // Dependencies (noq, ...) are capped at `warn` unless RUST_LOG=trace.
    let level = std::env::var("RUST_LOG").ok();
    let filter = match level.as_deref() {
        Some("off") => log::LevelFilter::Off,
        Some("error") => log::LevelFilter::Error,
        Some("warn") => log::LevelFilter::Warn,
        Some("debug") => log::LevelFilter::Debug,
        Some("trace") => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    log::set_logger(&LOGGER).ok();
    log::set_max_level(filter);
}

struct StderrLogger;
static LOGGER: StderrLogger = StderrLogger;
impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with(env!("CARGO_CRATE_NAME"))
            || metadata.level() <= log::Level::Warn
            || log::max_level() == log::LevelFilter::Trace
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("[{}] {}", record.level(), record.args());
        }
    }
    fn flush(&self) {}
}
