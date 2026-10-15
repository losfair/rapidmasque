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
use std::time::Instant;

use noq::congestion::{Bbr3Config, Controller, ControllerFactory};

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
    pub(crate) fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            Self::None => Arc::new(NoCongestionControl),
            Self::Bbr3 => Arc::new(Bbr3Config::default()),
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
