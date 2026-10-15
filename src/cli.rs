use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::cc::CongestionControl;
use crate::client::PathSpec;
use crate::quic::{
    DATAGRAM_CODEL, DEFAULT_BBR3_INITIAL_WINDOW, DEFAULT_PATH_SPILL_THRESHOLD, TransportOptions,
};
use crate::ranking::PathRanking;

/// Smallest `--bbr3-initial-window`: two QUIC minimum-size (1200-byte)
/// packets.
const MIN_BBR3_INITIAL_WINDOW: u64 = 2 * 1200;

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

    #[command(flatten)]
    pub transport: TransportArgs,

    /// Serve a JSON stats snapshot (connections, multipath paths, priorities,
    /// ranking, RTT, loss, traffic) over plain HTTP at `http://ADDR/stats`.
    /// Off by default. No TLS or authentication and it reveals peer
    /// addresses: bind it to loopback or a management network.
    #[arg(long, value_name = "IP:PORT")]
    pub stats_listen: Option<SocketAddr>,
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
    /// `REMOTE_IP:PORT[@LOCAL_IP][/backup][/priority=N][/rtable=N]`. `REMOTE` is a proxy
    /// address (it may differ from the primary one), `LOCAL_IP` pins the
    /// path's source address (e.g. a second uplink's address), and `/backup`
    /// makes it a standby path used only when no primary path works.
    /// `/priority=N` (0-255, default 0, lower is preferred) orders usable
    /// paths in both directions: traffic fills the preferred path first and
    /// spills onto the next ones (see `--path-spill-threshold-ms`); equal
    /// priorities share traffic. `/rtable=N` (OpenBSD) sends the path through
    /// routing table N (rtable(4)); such a path needs a remote, or remote and
    /// `@LOCAL_IP`, that no other path uses. Repeatable. Paths that fail are
    /// retried while the tunnel is up.
    #[arg(long = "path", value_name = "SPEC")]
    pub paths: Vec<PathSpec>,

    /// Priority of the primary path (the one to `--proxy-addr`), in the same
    /// terms as `--path .../priority=N`. Only meaningful with `--path`.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub primary_priority: u8,

    /// OpenBSD routing table (rtable(4)) for the primary path and every
    /// `--path` without its own `/rtable=N`. Defaults to the process's table
    /// (see `route -T N exec`).
    #[arg(long, value_name = "N")]
    pub rtable: Option<u32>,

    /// Rank paths by measured loss: `auto` (default) demotes a path whose
    /// loss is clearly worse than the best path with the same priority (at
    /// least 5%, and 3 points above the best, for 3 samples in a row), so
    /// traffic moves to the better paths of that priority; it is promoted
    /// again once its loss recovers. The proxy does the same for what it
    /// sends. Paths never move across configured priorities, which must then
    /// be at most 127. `off` keeps the configured priorities as they are.
    /// Only meaningful with `--path`.
    #[arg(long, value_enum, default_value_t = PathRanking::Auto)]
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

    #[command(flatten)]
    pub transport: TransportArgs,

    /// Serve a JSON stats snapshot (connections, multipath paths, priorities,
    /// ranking, RTT, loss, traffic) over plain HTTP at `http://ADDR/stats`.
    /// Off by default. No TLS or authentication and it reveals peer
    /// addresses: bind it to loopback or a management network.
    #[arg(long, value_name = "IP:PORT")]
    pub stats_listen: Option<SocketAddr>,
}

/// QUIC transport settings for what this side sends, shared by `serve` and
/// `client`.
#[derive(Args, Debug)]
pub struct TransportArgs {
    /// Congestion control for what this side sends. `bbr3` (default) runs
    /// BBRv3 per path; `none` never holds datagrams back, leaving rate control
    /// to the tunnelled protocol (e.g. TCP inside WireGuard) to avoid double
    /// congestion control.
    #[arg(long, value_enum, default_value_t = CongestionControl::Bbr3)]
    pub congestion_control: CongestionControl,

    /// BBRv3 initial congestion window in bytes, for every path this side
    /// sends on [default: 65536, ~48 full-size packets; noq's own is 12000].
    /// A larger window lets a new path ramp up faster on a high
    /// bandwidth-delay path (BBRv3 paces it out rather than bursting), at
    /// the cost of overshooting slow low-RTT links at path start. At least
    /// 2400. Only with `--congestion-control bbr3`.
    #[arg(long, value_name = "BYTES", value_parser = clap::value_parser!(u64).range(MIN_BBR3_INITIAL_WINDOW..))]
    pub bbr3_initial_window: Option<u64>,

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

impl TransportArgs {
    /// The transport options these flags select.
    pub fn options(&self) -> Result<TransportOptions> {
        if self.bbr3_initial_window.is_some() && self.congestion_control != CongestionControl::Bbr3
        {
            bail!("--bbr3-initial-window needs --congestion-control bbr3");
        }
        Ok(TransportOptions {
            congestion_control: self.congestion_control,
            bbr3_initial_window: self
                .bbr3_initial_window
                .unwrap_or(DEFAULT_BBR3_INITIAL_WINDOW),
            path_spill_threshold: (self.path_spill_threshold_ms > 0)
                .then(|| Duration::from_millis(self.path_spill_threshold_ms)),
            datagram_codel: Some(DATAGRAM_CODEL),
        })
    }
}

#[derive(Parser, Debug)]
pub struct GenEchArgs {
    /// Public name (cleartext cover identity) embedded in the ECHConfig. The
    /// server should be able to present a valid cert for it for the ECH-rejection
    /// fallback; on ECH acceptance only the inner SNI is authenticated.
    #[arg(long, value_name = "NAME")]
    pub public_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_defaults() {
        let cli = Cli::try_parse_from([
            "rapidmasque",
            "client",
            "--endpoint",
            "https://proxy.example/connect",
            "--listen",
            "127.0.0.1:5353",
        ])
        .unwrap();
        let Command::Client(args) = cli.command else {
            panic!("expected the client subcommand");
        };
        assert_eq!(args.path_ranking, PathRanking::Auto);
        assert_eq!(args.rtable, None);
        let options = args.transport.options().unwrap();
        assert_eq!(options.congestion_control, CongestionControl::Bbr3);
        assert_eq!(options.bbr3_initial_window, DEFAULT_BBR3_INITIAL_WINDOW);
        assert_eq!(
            options.path_spill_threshold,
            Some(Duration::from_millis(10))
        );
        assert_eq!(options.datagram_codel, Some(DATAGRAM_CODEL));
        let parse = |flags: &[&str]| {
            let mut argv = vec![
                "rapidmasque",
                "serve",
                "--rules",
                "r.json",
                "--cert",
                "c.pem",
                "--key",
                "k.pem",
            ];
            argv.extend_from_slice(flags);
            Cli::try_parse_from(argv).map(|cli| match cli.command {
                Command::Serve(args) => args,
                _ => panic!("expected the serve subcommand"),
            })
        };
        let args = parse(&["--bbr3-initial-window", "65536"]).unwrap();
        assert_eq!(args.transport.options().unwrap().bbr3_initial_window, 65536);
        assert_eq!(args.stats_listen, None);
        assert!(parse(&["--bbr3-initial-window", "1200"]).is_err());
        assert!(
            parse(&[
                "--bbr3-initial-window",
                "65536",
                "--congestion-control",
                "none"
            ])
            .unwrap()
            .transport
            .options()
            .is_err()
        );
        let args = parse(&["--path-spill-threshold-ms", "0"]).unwrap();
        let options = args.transport.options().unwrap();
        assert_eq!(options.path_spill_threshold, None);
    }
}
