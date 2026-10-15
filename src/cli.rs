use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::cc::CongestionControl;
use crate::client::PathSpec;
use crate::quic::DEFAULT_PATH_SPILL_THRESHOLD;
use crate::ranking::PathRanking;

#[derive(Parser, Debug)]
#[command(author, version, about = "Multipath MASQUE (CONNECT-UDP) proxy and client", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the CONNECT-UDP proxy server.
    Serve(ServeArgs),
    /// Run the CONNECT-UDP client (a local UDP proxy).
    Client(ClientArgs),
    /// Generate an ECH (Encrypted Client Hello) keypair + ECHConfig.
    GenEchKey(GenEchArgs),
}

#[derive(Parser, Debug)]
pub struct ServeArgs {
    /// UDP address to bind the QUIC listener to. Bind an unspecified address
    /// (e.g. `[::]:4433`) to accept multipath paths on every local address.
    #[arg(long, default_value = "0.0.0.0:4433")]
    pub addr: SocketAddr,

    /// JSON rule table mapping endpoints to pinned targets, e.g.
    /// `[{"endpoint":"https://a.example.com/masque","target":"127.0.0.1:1234"}]`.
    /// Requests are matched on `:authority` + path (query ignored); the matching
    /// rule's target is the pinned destination. Hot-reloadable via SIGHUP.
    #[arg(long, value_name = "FILE")]
    pub rules: PathBuf,

    /// TLS certificate chain (PEM).
    #[arg(long)]
    pub cert: PathBuf,

    /// TLS private key (PEM).
    #[arg(long)]
    pub key: PathBuf,

    /// Path to an ECH key file or directory (enables server-side ECH).
    #[arg(long, value_name = "PATH")]
    pub ech_key: Option<PathBuf>,

    /// Congestion control for what this side sends (proxy -> client).
    /// `bbr3` (default) runs BBRv3 per path; `none` never holds datagrams
    /// back, leaving rate control to the tunnelled protocol (e.g. TCP inside
    /// WireGuard) to avoid double congestion control.
    #[arg(long, value_enum, default_value_t = CongestionControl::Bbr3)]
    pub congestion_control: CongestionControl,

    /// Queueing delay (milliseconds) accepted on a preferred path before
    /// traffic spills onto less preferred ones (paths with a higher
    /// `/priority=N`). While the preferred path can send everything queued
    /// within this time at its current BBRv3 rate, lower-priority paths carry
    /// no data. `0` spills whenever the preferred path is momentarily paced,
    /// which spreads even light traffic over all paths. Has no effect while
    /// all paths share one priority.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PATH_SPILL_THRESHOLD.as_millis() as u64)]
    pub path_spill_threshold_ms: u64,
}

#[derive(Parser, Debug)]
pub struct ClientArgs {
    /// Proxy endpoint URI, e.g. `https://proxy.example:4433/connect`; must match
    /// a server rule's endpoint (authority + path).
    #[arg(long)]
    pub endpoint: String,

    /// Local UDP address to bind. Every datagram received here is tunnelled
    /// through the proxy (one CONNECT-UDP flow per local source address), with
    /// replies relayed back. The destination is whatever the server pins.
    #[arg(long, value_name = "IP:PORT")]
    pub listen: SocketAddr,

    /// Override the proxy UDP address to connect to (`ip:port`). The template
    /// host is still used for SNI and `:authority`; this only changes where
    /// packets are sent. Useful when the template host resolves to an address
    /// the proxy isn't listening on (e.g. `localhost` -> `::1`).
    #[arg(long, value_name = "IP:PORT")]
    pub proxy_addr: Option<SocketAddr>,

    /// Open an additional QUIC multipath path, as
    /// `REMOTE_IP:PORT[@LOCAL_IP][/backup][/priority=N]`. `REMOTE` is a proxy
    /// address (it may differ from the primary one), `LOCAL_IP` pins the
    /// path's source address (e.g. a second uplink's address), and `/backup`
    /// makes it a standby path used only when no primary path works.
    /// `/priority=N` (0-255, default 0, lower is preferred) orders usable
    /// paths in both directions: traffic fills the preferred path first and
    /// spills onto the next ones (see `--path-spill-threshold-ms`); equal
    /// priorities share traffic. Repeatable. Paths that fail are retried while
    /// the tunnel is up.
    #[arg(long = "path", value_name = "SPEC")]
    pub paths: Vec<PathSpec>,

    /// Priority of the primary path (the one to `--proxy-addr`), in the same
    /// terms as `--path .../priority=N`. Only meaningful with `--path`.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub primary_priority: u8,

    /// Rank paths by measured loss: `auto` demotes a path whose loss is
    /// clearly worse than the best path with the same priority (at least 5%,
    /// and 3 points above the best, for 3 samples in a row), so traffic moves
    /// to the better paths of that priority; it is promoted again once its
    /// loss recovers. The proxy does the same for what it sends. Paths never
    /// move across configured priorities, which must then be at most 127.
    /// Only meaningful with `--path`.
    #[arg(long, value_enum, default_value_t = PathRanking::Off)]
    pub path_ranking: PathRanking,

    /// Skip TLS certificate verification (testing only).
    #[arg(long)]
    pub insecure: bool,

    /// Extra CA certificate (PEM) to trust when verifying the proxy.
    #[arg(long, value_name = "FILE")]
    pub ca: Option<PathBuf>,

    /// Offer Encrypted Client Hello using this base64 ECHConfigList (the DNS
    /// `ech=` value).
    #[arg(long, value_name = "BASE64")]
    pub ech_config: Option<String>,

    /// Read the ECHConfigList (base64) from a file instead of the argument.
    #[arg(long, value_name = "FILE", conflicts_with = "ech_config")]
    pub ech_config_file: Option<PathBuf>,

    /// Congestion control for what this side sends (client -> proxy).
    /// `bbr3` (default) runs BBRv3 per path; `none` never holds datagrams
    /// back, leaving rate control to the tunnelled protocol (e.g. TCP inside
    /// WireGuard) to avoid double congestion control.
    #[arg(long, value_enum, default_value_t = CongestionControl::Bbr3)]
    pub congestion_control: CongestionControl,

    /// Queueing delay (milliseconds) accepted on a preferred path before
    /// traffic spills onto less preferred ones (paths with a higher
    /// `/priority=N`). While the preferred path can send everything queued
    /// within this time at its current BBRv3 rate, lower-priority paths carry
    /// no data. `0` spills whenever the preferred path is momentarily paced,
    /// which spreads even light traffic over all paths. Has no effect while
    /// all paths share one priority.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PATH_SPILL_THRESHOLD.as_millis() as u64)]
    pub path_spill_threshold_ms: u64,
}

#[derive(Parser, Debug)]
pub struct GenEchArgs {
    /// Public name (cleartext cover identity) embedded in the ECHConfig. The
    /// server should be able to present a valid cert for it for the ECH-rejection
    /// fallback; on ECH acceptance only the inner SNI is authenticated.
    #[arg(long, value_name = "NAME")]
    pub public_name: String,
}
