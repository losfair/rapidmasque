//! Outer congestion control selection.
//!
//! BBRv3 (one instance per multipath path) is the default. When the tunnel
//! carries traffic that is already congestion-controlled end to end (e.g. TCP
//! inside WireGuard inside the tunnel), a second, outer controller stacked on
//! top ("double CC") fights the inner one: it queues and delays datagrams when
//! its window is full, inflating the inner RTT, and its reaction to loss
//! compounds the inner protocol's. `--congestion-control none` selects
//! [`NoCongestionControl`] for that case: it reports an unbounded window and no
//! pacing rate, so noq sends whatever is queued as fast as the socket takes it
//! and leaves rate control to the tunnelled protocol.
//!
//! noq applies its window per packet, not per frame, so `none` also covers the
//! (tiny) HTTP/3 control and request-stream traffic; that is still reliable via
//! loss detection and retransmission, just not rate-limited. Loss detection,
//! RTT estimation, ACKs and MTU discovery are unaffected.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use noq::congestion::{Bbr3Config, Controller, ControllerFactory, ControllerMetrics};

/// Window reported by [`NoCongestionControl`]. Above `u32::MAX`, noq's pacer
/// never delays; kept well below `u64::MAX` so `in_flight + n` cannot overflow.
const UNBOUNDED_WINDOW: u64 = u64::MAX >> 2;

/// Which congestion controller the sending side of a connection uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum CongestionControl {
    /// BBRv3, one instance per multipath path (default).
    #[default]
    Bbr3,
    /// No outer congestion control: datagrams are never held back by a
    /// congestion window or pacer.
    None,
}

impl CongestionControl {
    /// The controller factory. `bbr3_initial_window` (bytes) is BBRv3's
    /// initial congestion window, per path.
    pub(crate) fn factory(
        self,
        bbr3_initial_window: u64,
    ) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            Self::None => Arc::new(NoCongestionControl),
            Self::Bbr3 => {
                let mut config = Bbr3Config::default();
                config.initial_window(bbr3_initial_window);
                Arc::new(config)
            }
        }
    }
}

/// A controller that never limits sending.
#[derive(Clone, Debug, Default)]
pub struct NoCongestionControl;

impl Controller for NoCongestionControl {
    /// Loss is the tunnelled protocol's signal to act on, not ours.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
        _largest_lost_pn: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        UNBOUNDED_WINDOW
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        UNBOUNDED_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for NoCongestionControl {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoCongestionControl)
    }
}

/// A fixed-rate controller for a path of known, dedicated capacity
/// (`--path .../rate=RATE`, `--primary-rate`).
///
/// It paces at the configured rate and never probes for more or backs off on
/// loss, so on a link that is not shared the path runs at a steady rate, and
/// the multipath scheduler knows exactly what the path can take: once more
/// than that is queued, traffic spills onto less preferred paths. Its window
/// still bounds what is in flight to about two round trips at that rate
/// (`WINDOW_RTTS`), so when the link goes down and acknowledgements stop, the
/// path fills its window within a round trip and the scheduler moves traffic
/// to the other paths, as it would for a congestion-controlled path. After
/// persistent congestion (every packet over several round trips lost) the
/// window drops to its minimum until something is acknowledged again.
#[derive(Clone, Debug)]
pub struct FixedRate {
    /// Pacing rate, bytes per second of QUIC packets (UDP payload).
    rate: u64,
    mtu: u16,
    min_rtt: Option<Duration>,
    collapsed: bool,
}

/// In-flight bound, in round trips at the fixed rate.
const WINDOW_RTTS: u32 = 2;
/// Round-trip time assumed for the window until the path has a sample.
const FIXED_RATE_INITIAL_RTT: Duration = Duration::from_millis(100);
/// The window is never smaller than the fixed rate times this...
const FIXED_RATE_MIN_WINDOW_TIME: Duration = Duration::from_millis(20);
/// ...or this many full-size packets.
const FIXED_RATE_MIN_WINDOW_PACKETS: u64 = 4;

impl FixedRate {
    /// A controller pacing at `bits_per_second` (of UDP payload).
    pub fn new(bits_per_second: u64, mtu: u16) -> Self {
        Self {
            rate: (bits_per_second / 8).max(1),
            mtu,
            min_rtt: None,
            collapsed: false,
        }
    }

    fn min_window(&self) -> u64 {
        FIXED_RATE_MIN_WINDOW_PACKETS * u64::from(self.mtu)
    }
}

impl Controller for FixedRate {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _pn: u64,
        _app_limited: bool,
        rtt: &noq_proto::RttEstimator,
    ) {
        self.min_rtt = Some(rtt.min());
        self.collapsed = false;
    }

    /// Loss on a dedicated link is not a congestion signal; only persistent
    /// congestion (the link is gone) shrinks the window.
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
        _largest_lost_pn: u64,
    ) {
        if is_persistent_congestion {
            self.collapsed = true;
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        if self.collapsed {
            return self.min_window();
        }
        let rtt = self.min_rtt.unwrap_or(FIXED_RATE_INITIAL_RTT) * WINDOW_RTTS;
        let bytes_in = |d: Duration| (self.rate as f64 * d.as_secs_f64()) as u64;
        bytes_in(rtt)
            .max(bytes_in(FIXED_RATE_MIN_WINDOW_TIME))
            .max(self.min_window())
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.rate);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Builds [`FixedRate`] controllers for one path.
#[derive(Clone, Copy, Debug)]
pub struct FixedRateFactory {
    /// Bits per second.
    pub rate: u64,
}

impl ControllerFactory for FixedRateFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(FixedRate::new(self.rate, current_mtu))
    }
}

/// Parse a rate in bits per second: a number with an optional decimal
/// `k`/`M`/`G` suffix (`50M` = 50,000,000), optionally followed by `bit/s` or
/// `bps`.
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_suffix("bit/s")
        .or_else(|| t.strip_suffix("bps"))
        .unwrap_or(t);
    let (number, scale) = match t.char_indices().last() {
        Some((i, 'k' | 'K')) => (&t[..i], 1e3),
        Some((i, 'm' | 'M')) => (&t[..i], 1e6),
        Some((i, 'g' | 'G')) => (&t[..i], 1e9),
        _ => (t, 1.0),
    };
    let value: f64 = number
        .parse()
        .map_err(|_| format!("invalid rate {s:?} (e.g. 48M, 500k, 1.5G)"))?;
    let bits = value * scale;
    if !(1000.0..1e15).contains(&bits) {
        return Err(format!("rate {s:?} out of range (1k to 999T bit/s)"));
    }
    Ok(bits as u64)
}

/// Format a rate in bits per second the way [`parse_rate`] reads it.
pub fn format_rate(bits: u64) -> String {
    let (value, suffix) = if bits >= 1_000_000_000 && bits.is_multiple_of(1_000_000) {
        (bits as f64 / 1e9, "G")
    } else if bits >= 1_000_000 && bits.is_multiple_of(1_000) {
        (bits as f64 / 1e6, "M")
    } else if bits >= 1_000 {
        (bits as f64 / 1e3, "k")
    } else {
        (bits as f64, "")
    };
    format!("{value}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_parse_and_format() {
        assert_eq!(parse_rate("48M"), Ok(48_000_000));
        assert_eq!(parse_rate("1.5G"), Ok(1_500_000_000));
        assert_eq!(parse_rate("500k"), Ok(500_000));
        assert_eq!(parse_rate("50Mbit/s"), Ok(50_000_000));
        assert_eq!(parse_rate("2000000"), Ok(2_000_000));
        assert!(parse_rate("fast").is_err());
        assert!(parse_rate("0").is_err());
        assert!(parse_rate("-5M").is_err());
        for bits in [48_000_000, 1_500_000_000, 500_000, 2_500, 1_000_000_000] {
            assert_eq!(parse_rate(&format_rate(bits)), Ok(bits));
        }
        assert_eq!(format_rate(48_000_000), "48M");
    }

    #[test]
    fn fixed_rate_paces_and_bounds_the_window() {
        let now = Instant::now();
        // 48 Mbit/s = 6 MB/s.
        let mut cc = Arc::new(FixedRateFactory { rate: 48_000_000 }).build(now, 1400);
        assert_eq!(cc.metrics().pacing_rate, Some(6_000_000));
        // Before an RTT sample: two 100 ms round trips.
        assert_eq!(cc.window(), 1_200_000);
        // Loss does not shrink it...
        cc.on_congestion_event(now, now, false, false, 1400, 1);
        assert_eq!(cc.window(), 1_200_000);
        // ...persistent congestion does, until an acknowledgement.
        cc.on_congestion_event(now, now, true, false, 1400, 2);
        assert_eq!(cc.window(), 4 * 1400);
    }

    #[test]
    fn bbr3_initial_window_is_configurable() {
        let now = Instant::now();
        let custom = CongestionControl::Bbr3.factory(100_000).build(now, 1200);
        assert_eq!(custom.initial_window(), 100_000);
        assert_eq!(custom.window(), 100_000);
    }
}
