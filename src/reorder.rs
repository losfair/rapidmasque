//! In-order delivery of a flow's datagrams (`--in-order-delivery`).
//!
//! When the tunnel's preferred path is full, part of a flow spills onto a
//! slower path, and the far end receives its datagrams out of order. For TCP
//! inside the tunnel (e.g. inside WireGuard, which passes reordering through)
//! a datagram that arrives after its successors looks like loss: duplicate
//! ACKs, spurious retransmissions and a reduced sending rate. So the sender
//! numbers each flow's datagrams (`crate::dgram::encode_sequenced`) and the
//! receiver holds early arrivals until the gap before them fills, or gives up
//! on the gap after a hold time and releases what it has.
//!
//! The hold time tunes itself: it follows how late gap-filling datagrams
//! actually arrive (a quarter more, up to [`MAX_HOLD`]), and decays while
//! nothing arrives out of order, so a flow on one path, or a genuinely lost
//! datagram on a path that never reorders, delays its successors only
//! briefly.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

/// Hold time before any reordering has been seen.
const INITIAL_HOLD: Duration = Duration::from_millis(10);
/// The hold time never decays below this.
const MIN_HOLD: Duration = Duration::from_millis(2);
/// Nor grows above this: a datagram later than this is delivered when it
/// comes, out of order.
pub const MAX_HOLD: Duration = Duration::from_millis(250);
/// Without reordering for this long, the hold time halves.
const DECAY_AFTER: Duration = Duration::from_secs(10);
/// Datagrams buffered ahead of a gap, at most. A datagram further ahead than
/// this releases everything and restarts the sequence there.
const MAX_WINDOW: usize = 4096;

/// Per-flow, per-direction reordering state.
#[derive(Debug)]
pub struct Reorder {
    /// The sequence number delivered next (`None` before the first datagram).
    next: Option<u32>,
    /// Datagrams `next`, `next + 1`, ... that have arrived early; slot 0 is
    /// always empty while anything is buffered.
    window: VecDeque<Option<Bytes>>,
    /// When the current gap opened.
    gap_since: Option<Instant>,
    hold: Duration,
    last_reorder: Instant,
    /// The last range given up on, `[start, end)`, and when its gap opened,
    /// to learn from datagrams that arrive after it was skipped.
    skipped: Option<(u32, u32, Instant)>,
}

impl Reorder {
    pub fn new(now: Instant) -> Self {
        Self {
            next: None,
            window: VecDeque::new(),
            gap_since: None,
            hold: INITIAL_HOLD,
            last_reorder: now,
            skipped: None,
        }
    }

    /// Take in datagram `seq`; datagrams now deliverable, in order, are
    /// appended to `out`.
    pub fn push(&mut self, seq: u32, data: Bytes, now: Instant, out: &mut Vec<Bytes>) {
        self.decay(now);
        let next = *self.next.get_or_insert(seq);
        let ahead = seq.wrapping_sub(next) as i32;
        if ahead < 0 {
            // Late: its gap was given up on already. Deliver it anyway (the
            // tunnelled protocol handles duplicates and reordering), and wait
            // longer next time.
            if let Some((start, end, since)) = self.skipped
                && seq.wrapping_sub(start) < end.wrapping_sub(start)
            {
                self.learn(now.saturating_duration_since(since), now);
            }
            out.push(data);
            return;
        }
        let ahead = ahead as usize;
        if ahead >= MAX_WINDOW {
            // Far ahead (a long outage, or the peer restarted the flow):
            // release everything and continue from here.
            self.release_all(out);
            out.push(data);
            self.next = Some(seq.wrapping_add(1));
            return;
        }
        if ahead > 0 {
            if self.window.len() <= ahead {
                self.window.resize(ahead + 1, None);
            }
            if self.window[ahead].is_none() {
                self.window[ahead] = Some(data);
            } // else a duplicate
            self.gap_since.get_or_insert(now);
            return;
        }
        // The next datagram in order.
        out.push(data);
        self.window.pop_front();
        let mut next = next.wrapping_add(1);
        while let Some(Some(_)) = self.window.front() {
            out.push(self.window.pop_front().flatten().expect("checked"));
            next = next.wrapping_add(1);
        }
        self.next = Some(next);
        if let Some(since) = self.gap_since.take() {
            self.learn(now.saturating_duration_since(since), now);
            if !self.window.is_empty() {
                // Another gap further on, opened no later than now.
                self.gap_since = Some(now);
            }
        }
    }

    /// When the current gap is given up on, if there is one.
    pub fn deadline(&self) -> Option<Instant> {
        self.gap_since.map(|since| since + self.hold)
    }

    /// Give up on the current gap if its hold time has passed: release every
    /// buffered datagram, in order, to `out`.
    pub fn on_timeout(&mut self, now: Instant, out: &mut Vec<Bytes>) {
        if self.deadline().is_some_and(|deadline| deadline <= now) {
            let since = self.gap_since.expect("deadline implies a gap");
            let start = self.next.expect("a gap implies a datagram");
            let end = start.wrapping_add(self.window.len() as u32);
            self.skipped = Some((start, end, since));
            self.release_all(out);
        }
    }

    /// Current hold time.
    #[cfg(test)]
    pub fn hold(&self) -> Duration {
        self.hold
    }

    fn release_all(&mut self, out: &mut Vec<Bytes>) {
        if let Some(next) = self.next.as_mut() {
            *next = next.wrapping_add(self.window.len() as u32);
        }
        out.extend(self.window.drain(..).flatten());
        self.gap_since = None;
    }

    /// A datagram arrived `delay` after its gap opened.
    fn learn(&mut self, delay: Duration, now: Instant) {
        self.hold = self.hold.max(delay * 5 / 4).min(MAX_HOLD);
        self.last_reorder = now;
    }

    fn decay(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_reorder) >= DECAY_AFTER {
            self.hold = (self.hold / 2).max(MIN_HOLD);
            self.last_reorder = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u32) -> Bytes {
        Bytes::from(n.to_be_bytes().to_vec())
    }

    fn seqs(out: &[Bytes]) -> Vec<u32> {
        out.iter()
            .map(|d| u32::from_be_bytes(d[..].try_into().unwrap()))
            .collect()
    }

    /// Feed `order` at 1 ms intervals; returns delivered sequence numbers.
    fn feed(r: &mut Reorder, start: Instant, order: &[u32]) -> Vec<u32> {
        let mut out = Vec::new();
        for (i, &seq) in order.iter().enumerate() {
            r.push(
                seq,
                b(seq),
                start + Duration::from_millis(i as u64),
                &mut out,
            );
        }
        seqs(&out)
    }

    #[test]
    fn in_order_passes_through() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        assert_eq!(feed(&mut r, t, &[5, 6, 7, 8]), vec![5, 6, 7, 8]);
        assert_eq!(r.deadline(), None);
    }

    #[test]
    fn reordered_datagrams_come_out_in_order() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        // 3 and 4 overtake 2, which arrives 2 ms after its gap opened.
        assert_eq!(feed(&mut r, t, &[0, 1, 3, 4, 2, 5]), vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(r.deadline(), None);
        // Learned: hold at least 1.25 x 2 ms (but stays at the initial 10).
        assert_eq!(r.hold(), INITIAL_HOLD);
    }

    #[test]
    fn hold_follows_observed_lateness() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        let mut out = Vec::new();
        r.push(0, b(0), t, &mut out);
        r.push(2, b(2), t, &mut out);
        // 1 arrives 40 ms late, within the hold? No: hold is 10 ms, so time
        // out first...
        r.on_timeout(t + Duration::from_millis(10), &mut out);
        assert_eq!(seqs(&out), vec![0, 2]);
        // ...then 1 turns up 40 ms after its gap opened: delivered late, and
        // the hold grows to 50 ms.
        r.push(1, b(1), t + Duration::from_millis(40), &mut out);
        assert_eq!(seqs(&out), vec![0, 2, 1]);
        assert_eq!(r.hold(), Duration::from_millis(50));

        // Next time the same lateness is absorbed.
        let t2 = t + Duration::from_millis(100);
        r.push(4, b(4), t2, &mut out);
        assert_eq!(r.deadline(), Some(t2 + Duration::from_millis(50)));
        r.on_timeout(t2 + Duration::from_millis(40), &mut out);
        r.push(3, b(3), t2 + Duration::from_millis(40), &mut out);
        assert_eq!(seqs(&out), vec![0, 2, 1, 3, 4]);
    }

    #[test]
    fn lost_datagram_released_after_hold() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        let mut out = Vec::new();
        for seq in [0, 2, 3] {
            r.push(seq, b(seq), t, &mut out);
        }
        assert_eq!(seqs(&out), vec![0]);
        r.on_timeout(t + Duration::from_millis(9), &mut out);
        assert_eq!(seqs(&out), vec![0], "not yet");
        r.on_timeout(t + INITIAL_HOLD, &mut out);
        assert_eq!(seqs(&out), vec![0, 2, 3]);
        r.push(4, b(4), t + INITIAL_HOLD, &mut out);
        assert_eq!(seqs(&out), vec![0, 2, 3, 4]);
    }

    #[test]
    fn hold_is_capped_and_decays() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        let mut out = Vec::new();
        r.push(0, b(0), t, &mut out);
        r.push(2, b(2), t, &mut out);
        r.push(1, b(1), t + Duration::from_secs(1), &mut out);
        assert_eq!(r.hold(), MAX_HOLD);
        // Quiet for a while: halves on the next datagram.
        r.push(3, b(3), t + Duration::from_secs(12), &mut out);
        assert_eq!(r.hold(), MAX_HOLD / 2);
    }

    #[test]
    fn wraps_around() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        let order = [u32::MAX - 1, u32::MAX, 1, 0, 2];
        assert_eq!(
            feed(&mut r, t, &order),
            vec![u32::MAX - 1, u32::MAX, 0, 1, 2]
        );
    }

    #[test]
    fn duplicates_and_far_jumps() {
        let t = Instant::now();
        let mut r = Reorder::new(t);
        // A duplicate of a buffered datagram is dropped.
        assert_eq!(feed(&mut r, t, &[0, 2, 2, 1]), vec![0, 1, 2]);
        // Far ahead: release and restart there.
        let mut out = Vec::new();
        r.push(5, b(5), t, &mut out);
        r.push(100_000, b(100_000), t, &mut out);
        r.push(100_001, b(100_001), t, &mut out);
        assert_eq!(seqs(&out), vec![5, 100_000, 100_001]);
    }
}
