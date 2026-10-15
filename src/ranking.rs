//! Multipath path priorities and automatic path ranking.
//!
//! Every connection has a [`PathPriorities`] table: the configured ("base")
//! priority of each path (client `--path .../priority=N`, announced to the
//! server over the HTTP/3 control stream), plus whether automatic ranking has
//! demoted it. The effective noq priority is derived from both.
//!
//! With `--path-ranking auto` (the default), each end runs a [`Ranker`] over the paths it
//! sends on: it samples each path's loss rate from noq's path statistics and
//! demotes a path whose loss is clearly worse than the best path with the same
//! base priority, so traffic moves to the better paths of that group. The
//! client asks the server to do the same for the return direction, so each
//! direction is ranked on its own sender's loss. Ranking never reorders paths
//! across base priorities: a demoted path only falls behind its own group.
//!
//! A demoted path carries little traffic, so it would yield loss samples only
//! slowly (keepalives are 1/s); the ranker PINGs demoted paths every
//! [`RankingConfig::probe_interval`] to notice a recovery within seconds.
//!
//! RTT is not used: smoothed RTT includes the queueing delay of whatever
//! traffic the path carries, so ranking on it would push traffic away from
//! whichever path is in use and flap.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use noq::{Connection, PathId};

use crate::quic::PathScan;

/// Whether to rank paths automatically by measured loss.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum PathRanking {
    /// Paths keep their configured priority.
    Off,
    /// Demote paths with clearly worse loss than the best path of the same
    /// priority, on both ends (default).
    #[default]
    Auto,
}

/// Highest base priority usable with automatic ranking: the effective
/// priority is `2 * base + demoted`, which must fit a `u8`.
pub const MAX_RANKED_PRIORITY: u8 = 127;

/// Tuning for the [`Ranker`].
#[derive(Debug, Clone, Copy)]
pub struct RankingConfig {
    /// How often path statistics are sampled.
    pub interval: Duration,
    /// How often demoted paths are PINGed to keep measuring their loss.
    pub probe_interval: Duration,
    /// Packets sent on a path that make one loss sample.
    pub min_sample_packets: u64,
    /// A path that sends little (e.g. only keepalives) is sampled after this
    /// long instead, if it sent at least `min_idle_sample_packets`.
    pub max_sample_age: Duration,
    pub min_idle_sample_packets: u64,
    /// Weight of a new sample in the smoothed loss rate.
    pub sample_weight: f64,
    /// A path is demoted when its loss is at least this...
    pub loss_threshold: f64,
    /// ...and at least this much above the best path of its group.
    pub loss_margin: f64,
    /// Consecutive samples that must agree before a path is demoted or
    /// promoted again.
    pub demote_after: u32,
    pub promote_after: u32,
    /// Minimum time between two changes of the same path.
    pub min_change_interval: Duration,
}

impl Default for RankingConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            probe_interval: Duration::from_millis(100),
            min_sample_packets: 40,
            max_sample_age: Duration::from_secs(30),
            min_idle_sample_packets: 10,
            sample_weight: 0.5,
            // BBRv3 itself causes up to ~2% loss while probing for bandwidth.
            loss_threshold: 0.05,
            loss_margin: 0.03,
            demote_after: 3,
            promote_after: 3,
            min_change_interval: Duration::from_secs(10),
        }
    }
}

/// Per-path priority state of one connection, shared by the code that learns
/// base priorities (path maintainers, control stream) and the ranker.
#[derive(Default)]
pub struct PathPriorities {
    inner: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    ranking: bool,
    paths: HashMap<PathId, PathEntry>,
}

/// What is known about one path's priority.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PathEntry {
    /// Configured priority (lower is preferred).
    pub base: u8,
    /// Demoted by automatic ranking.
    pub demoted: bool,
    /// Smoothed loss rate of what this end sends on the path, once sampled.
    pub loss: Option<f64>,
}

impl PathEntry {
    /// The noq priority to apply.
    fn effective(&self, ranking: bool) -> u8 {
        if ranking {
            self.base
                .saturating_mul(2)
                .saturating_add(u8::from(self.demoted))
        } else {
            self.base
        }
    }
}

impl PathPriorities {
    /// Set a path's configured priority and apply the result to noq.
    pub fn set_base(&self, conn: &Connection, path_id: PathId, base: u8) {
        self.update(conn, path_id, |e| e.base = base);
    }

    /// Whether automatic ranking runs on this connection.
    pub fn ranking(&self) -> bool {
        self.inner.lock().unwrap().ranking
    }

    /// A snapshot of every path's entry.
    pub fn snapshot(&self) -> HashMap<PathId, PathEntry> {
        self.inner.lock().unwrap().paths.clone()
    }

    fn base(&self, path_id: PathId) -> u8 {
        let table = self.inner.lock().unwrap();
        table.paths.get(&path_id).map_or(0, |e| e.base)
    }

    fn update(&self, conn: &Connection, path_id: PathId, f: impl FnOnce(&mut PathEntry)) {
        let mut table = self.inner.lock().unwrap();
        let ranking = table.ranking;
        let entry = table.paths.entry(path_id).or_default();
        let before = entry.effective(ranking);
        f(entry);
        let after = entry.effective(ranking);
        drop(table);
        // A new entry starts at noq's default priority, 0.
        if before != after {
            apply(conn, path_id, after);
        }
    }

    fn forget(&self, path_id: PathId) {
        self.inner.lock().unwrap().paths.remove(&path_id);
    }

    /// Switch to ranked priorities. Returns `false` if already enabled.
    fn enable_ranking(&self, conn: &Connection) -> bool {
        let mut table = self.inner.lock().unwrap();
        if table.ranking {
            return false;
        }
        table.ranking = true;
        let effective: Vec<_> = table
            .paths
            .iter()
            .map(|(id, e)| (*id, e.effective(true)))
            .collect();
        drop(table);
        for (path_id, priority) in effective {
            apply(conn, path_id, priority);
        }
        true
    }
}

fn apply(conn: &Connection, path_id: PathId, priority: u8) {
    if let Some(Err(e)) = conn.path(path_id).map(|path| path.set_priority(priority)) {
        log::debug!("path {path_id}: setting priority {priority}: {e}");
    }
}

/// Enable automatic ranking on `conn` and spawn its ranker, unless it already
/// runs.
pub fn start(conn: Connection, priorities: Arc<PathPriorities>, config: RankingConfig) {
    if priorities.enable_ranking(&conn) {
        log::info!(
            "connection {}: automatic path ranking enabled",
            conn.stable_id()
        );
        tokio::spawn(run(conn, priorities, config));
    }
}

async fn run(conn: Connection, priorities: Arc<PathPriorities>, config: RankingConfig) {
    let mut ranker = Ranker::new(config);
    let mut tick = tokio::time::interval(config.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut probe = tokio::time::interval(config.probe_interval);
    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut scan = PathScan::default();
    while conn.close_reason().is_none() {
        tokio::select! {
            _ = tick.tick() => {}
            _ = probe.tick() => {
                for path_id in ranker.demoted() {
                    if let Some(path) = conn.path(path_id) {
                        let _ = path.ping();
                    }
                }
                continue;
            }
            _ = conn.closed() => return,
        }
        let observations: Vec<Observation> = scan
            .scan(&conn)
            .into_iter()
            .map(|path| {
                let stats = path.stats();
                Observation {
                    id: path.id(),
                    base: priorities.base(path.id()),
                    sent: stats.sent_packets.saturating_sub(stats.sent_plpmtud_probes),
                    lost: stats.lost_packets.saturating_sub(stats.lost_plpmtud_probes),
                }
            })
            .collect();
        let gone: Vec<PathId> = ranker
            .paths
            .keys()
            .filter(|id| !observations.iter().any(|o| o.id == **id))
            .copied()
            .collect();
        for path_id in gone {
            priorities.forget(path_id);
        }
        for change in ranker.observe(Instant::now(), &observations) {
            let verb = if change.demoted {
                "demoted"
            } else {
                "promoted"
            };
            log::info!(
                "connection {}: path {} {verb} (loss {:.1}%, best in priority group {}: {:.1}%)",
                conn.stable_id(),
                change.id,
                change.loss * 100.0,
                change.base,
                change.best * 100.0
            );
        }
        for (path_id, state) in &ranker.paths {
            let (demoted, loss) = (state.demoted, state.loss);
            priorities.update(&conn, *path_id, |e| {
                e.demoted = demoted;
                e.loss = loss;
            });
        }
    }
}

/// Cumulative counters of one path at one point in time.
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub id: PathId,
    pub base: u8,
    /// Packets sent / declared lost so far, excluding MTU probes (which are
    /// expected to be lost).
    pub sent: u64,
    pub lost: u64,
}

/// A path whose ranking changed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Change {
    pub id: PathId,
    pub base: u8,
    pub demoted: bool,
    pub loss: f64,
    /// Best loss in the path's priority group.
    pub best: f64,
}

#[derive(Debug)]
struct RankedPath {
    base: u8,
    last_sent: u64,
    last_lost: u64,
    window_start: Instant,
    window_sent: u64,
    window_lost: u64,
    loss: Option<f64>,
    /// The sample taken by the latest observation, if any.
    sample: Option<f64>,
    demoted: bool,
    /// Consecutive samples that called for flipping `demoted`.
    streak: u32,
    last_change: Option<Instant>,
}

/// Ranks paths by loss. Pure state machine, driven by [`Ranker::observe`].
pub struct Ranker {
    config: RankingConfig,
    paths: BTreeMap<PathId, RankedPath>,
}

impl Ranker {
    pub fn new(config: RankingConfig) -> Self {
        Self {
            config,
            paths: BTreeMap::new(),
        }
    }

    /// Paths currently demoted.
    pub fn demoted(&self) -> Vec<PathId> {
        self.paths
            .iter()
            .filter(|(_, p)| p.demoted)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Feed the current counters of every live path (paths missing from
    /// `observations` are forgotten) and return the paths whose ranking
    /// changed.
    pub fn observe(&mut self, now: Instant, observations: &[Observation]) -> Vec<Change> {
        let c = self.config;
        self.paths
            .retain(|id, _| observations.iter().any(|o| o.id == *id));
        for o in observations {
            let path = self.paths.entry(o.id).or_insert(RankedPath {
                base: o.base,
                // Measure from now on, not the path's history.
                last_sent: o.sent,
                last_lost: o.lost,
                window_start: now,
                window_sent: 0,
                window_lost: 0,
                loss: None,
                sample: None,
                demoted: false,
                streak: 0,
                last_change: None,
            });
            path.base = o.base;
            path.sample = None;
            path.window_sent += o.sent.saturating_sub(path.last_sent);
            path.window_lost += o.lost.saturating_sub(path.last_lost);
            path.last_sent = o.sent;
            path.last_lost = o.lost;
            let full = path.window_sent >= c.min_sample_packets;
            let aged = now.duration_since(path.window_start) >= c.max_sample_age
                && path.window_sent >= c.min_idle_sample_packets;
            if full || aged {
                let sample = (path.window_lost as f64 / path.window_sent as f64).min(1.0);
                path.loss = Some(match path.loss {
                    Some(loss) => loss + c.sample_weight * (sample - loss),
                    None => sample,
                });
                path.sample = Some(sample);
                path.window_start = now;
                path.window_sent = 0;
                path.window_lost = 0;
            }
        }

        // Best (lowest) loss per base-priority group.
        let mut best: HashMap<u8, f64> = HashMap::new();
        for path in self.paths.values() {
            if let Some(loss) = path.loss {
                let b = best.entry(path.base).or_insert(loss);
                *b = b.min(loss);
            }
        }

        let mut changes = Vec::new();
        for (id, path) in &mut self.paths {
            let (Some(loss), Some(sample)) = (path.loss, path.sample) else {
                continue;
            };
            let best = best[&path.base];
            // Both the new sample and the smoothed loss must call for a change,
            // so neither a short blip nor a lingering average flips a path.
            // The group's best path never reaches `best + margin`, so a group
            // always keeps at least one path in its top tier.
            let flip = if path.demoted {
                let level = (c.loss_threshold / 2.0).max(best + c.loss_margin / 2.0);
                loss <= level && sample <= level
            } else {
                let level = c.loss_threshold.max(best + c.loss_margin);
                loss >= level && sample >= level
            };
            path.streak = if flip { path.streak + 1 } else { 0 };
            let needed = if path.demoted {
                c.promote_after
            } else {
                c.demote_after
            };
            let settled = path
                .last_change
                .is_none_or(|t| now.duration_since(t) >= c.min_change_interval);
            if path.streak >= needed && settled {
                path.demoted = !path.demoted;
                path.streak = 0;
                path.last_change = Some(now);
                changes.push(Change {
                    id: *id,
                    base: path.base,
                    demoted: path.demoted,
                    loss,
                    best,
                });
            }
        }
        changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: PathId = PathId::ZERO;

    fn bad() -> PathId {
        PathId::from(1u32)
    }

    fn config() -> RankingConfig {
        RankingConfig {
            min_change_interval: Duration::ZERO,
            ..Default::default()
        }
    }

    /// Drives a ranker one sample at a time: each step, every path sends 100
    /// packets and loses `loss[i]` percent of them.
    struct Sim {
        ranker: Ranker,
        now: Instant,
        sent: Vec<u64>,
        lost: Vec<u64>,
        bases: Vec<u8>,
    }

    impl Sim {
        fn new(config: RankingConfig, bases: &[u8]) -> Self {
            let mut sim = Self {
                ranker: Ranker::new(config),
                now: Instant::now(),
                sent: vec![0; bases.len()],
                lost: vec![0; bases.len()],
                bases: bases.to_vec(),
            };
            sim.step(&vec![0; bases.len()]);
            sim
        }

        fn step(&mut self, loss_percent: &[u64]) -> Vec<Change> {
            self.now += Duration::from_secs(1);
            for (i, loss) in loss_percent.iter().enumerate() {
                self.sent[i] += 100;
                self.lost[i] += loss;
            }
            let observations: Vec<_> = (0..self.bases.len())
                .map(|i| Observation {
                    id: PathId::from(i as u32),
                    base: self.bases[i],
                    sent: self.sent[i],
                    lost: self.lost[i],
                })
                .collect();
            self.ranker.observe(self.now, &observations)
        }

        fn demoted(&self, id: PathId) -> bool {
            self.ranker.paths[&id].demoted
        }
    }

    #[test]
    fn lossy_path_is_demoted_after_consecutive_samples_and_recovers() {
        let mut sim = Sim::new(config(), &[0, 0]);
        assert!(sim.step(&[0, 20]).is_empty());
        assert!(sim.step(&[0, 20]).is_empty());
        let changes = sim.step(&[0, 20]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, bad());
        assert!(changes[0].demoted);
        assert!(!sim.demoted(GOOD));

        // Promotion waits for the smoothed loss to drop and three good samples.
        let mut promoted_after = None;
        for step in 1..=10 {
            if !sim.step(&[0, 0]).is_empty() {
                promoted_after = Some(step);
                break;
            }
        }
        assert!(!sim.demoted(bad()));
        assert!(promoted_after.unwrap() >= 3);
    }

    #[test]
    fn best_path_of_a_group_is_never_demoted() {
        let mut sim = Sim::new(config(), &[0, 0]);
        for _ in 0..10 {
            sim.step(&[30, 31]);
        }
        assert!(!sim.demoted(GOOD));
        assert!(!sim.demoted(bad()));

        let mut sim = Sim::new(config(), &[0]);
        for _ in 0..10 {
            sim.step(&[50]);
        }
        assert!(!sim.demoted(GOOD));
    }

    #[test]
    fn loss_below_threshold_is_tolerated() {
        // BBRv3 probing loss: 2% vs 0% stays below the 5% threshold.
        let mut sim = Sim::new(config(), &[0, 0]);
        for _ in 0..10 {
            assert!(sim.step(&[0, 2]).is_empty());
        }
    }

    #[test]
    fn groups_are_ranked_separately() {
        // Path 1 is lossy but alone in priority group 1: nothing to prefer.
        let mut sim = Sim::new(config(), &[0, 1]);
        for _ in 0..10 {
            assert!(sim.step(&[0, 20]).is_empty());
        }
    }

    #[test]
    fn a_blip_does_not_demote() {
        let mut sim = Sim::new(config(), &[0, 0]);
        sim.step(&[0, 20]);
        sim.step(&[0, 20]);
        for _ in 0..10 {
            assert!(sim.step(&[0, 0]).is_empty());
        }
        assert!(!sim.demoted(bad()));
    }

    #[test]
    fn changes_respect_the_minimum_interval() {
        let mut sim = Sim::new(
            RankingConfig {
                min_change_interval: Duration::from_secs(20),
                ..Default::default()
            },
            &[0, 0],
        );
        for _ in 0..3 {
            sim.step(&[0, 20]);
        }
        assert!(sim.demoted(bad()));
        // Good samples from now on: promotion must wait out the 20 s.
        for _ in 0..19 {
            sim.step(&[0, 0]);
            assert!(sim.demoted(bad()));
        }
        sim.step(&[0, 0]);
        assert!(!sim.demoted(bad()));
    }

    #[test]
    fn small_windows_wait_for_enough_packets() {
        let mut ranker = Ranker::new(config());
        let start = Instant::now();
        let observe = |ranker: &mut Ranker, secs: u64, sent: u64, lost: u64| {
            ranker.observe(
                start + Duration::from_secs(secs),
                &[Observation {
                    id: GOOD,
                    base: 0,
                    sent,
                    lost,
                }],
            )
        };
        observe(&mut ranker, 0, 0, 0);
        // 5 packets in 10 s: neither a full nor an idle sample yet.
        observe(&mut ranker, 10, 5, 1);
        assert_eq!(ranker.paths[&GOOD].loss, None);
        // 12 packets after 30 s: an idle sample.
        observe(&mut ranker, 30, 12, 3);
        assert_eq!(ranker.paths[&GOOD].loss, Some(0.25));
    }

    #[test]
    fn effective_priority_keeps_groups_ordered() {
        let entry = |base, demoted| PathEntry {
            base,
            demoted,
            loss: None,
        };
        assert_eq!(entry(3, true).effective(false), 3);
        assert_eq!(entry(0, false).effective(true), 0);
        assert_eq!(entry(0, true).effective(true), 1);
        assert_eq!(entry(1, false).effective(true), 2);
        assert_eq!(entry(MAX_RANKED_PRIORITY, true).effective(true), 255);
    }
}
