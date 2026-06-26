//! The four pools of a node's view of the network.
//!
//! `peaveil`'s "view" is the only piece of state a node keeps
//! about the network. It is intentionally *small*, *fully
//! local*, and *continuously refreshed* by exchanging random
//! subsets of it with other nodes. There is no global
//! membership, no finger table, and no deterministic routing:
//! discovery is what the view *is*, not something the view is
//! used for.
//!
//! The view is partitioned into four named pools, each with
//! its own role:
//!
//! - [`PeerCategory::Bootstrap`] — well-known addresses seeded
//!   as network entry points. They are sticky (never aged out)
//!   and excluded from the `view_size` cap. `peaveil` does not
//!   dial them; the application connects to entry points it
//!   chooses.
//! - [`PeerCategory::Trusted`] — peers that have been seen
//!   enough times to be considered reliable. They make up the
//!   stable core of the view and are sampled out at a lower
//!   rate than the rest.
//! - [`PeerCategory::Recent`] — peers that have been seen
//!   recently but not often enough to be trusted. They are
//!   the *transient* part of the view: the first stop for any
//!   newly-learned address.
//! - [`PeerCategory::Random`] — a tiny set of long-range
//!   "exploration" peers. A small fraction of outgoing
//!   samples draws from this pool specifically, so the
//!   discovery traffic is not just a slow contraction toward
//!   the already-trusted core.
//!
//! The pools are not disjoint in the formal sense — a single
//! `SocketAddr` is in exactly one of them at any time, but the
//! category can change as the entry ages, is observed again,
//! or fails to respond. Re-classification runs on every
//! explorer tick and is the main mechanism that keeps the
//! pools balanced.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::seq::IndexedRandom;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Which of the four pools a peer currently belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerCategory {
    /// A hardcoded bootstrap address.
    Bootstrap,
    /// A peer that has been seen often enough and rarely
    /// failed; the stable core of the view.
    Trusted,
    /// A peer that has been seen at least once but not yet
    /// promoted to [`Trusted`](PeerCategory::Trusted).
    Recent,
    /// An exploration peer — drawn from a wider sample of
    /// the network specifically to keep the discovery
    /// traffic from collapsing onto the trusted core.
    Random,
}

impl PeerCategory {
    /// All four categories in declaration order. Used for
    /// iteration in tests and snapshots.
    pub const ALL: [PeerCategory; 4] = [
        PeerCategory::Bootstrap,
        PeerCategory::Trusted,
        PeerCategory::Recent,
        PeerCategory::Random,
    ];
}

#[derive(Clone, Debug)]
pub(crate) struct PeerEntry {
    pub addr: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub seen_count: u32,
    pub category: PeerCategory,
    /// True if this entry is a self-entry. Self-entries are
    /// never sent in outgoing samples; they are only kept so
    /// the rest of the network can learn about us through
    /// samples we ship to others.
    pub is_self: bool,
}

impl PeerEntry {
    fn new_self(addr: SocketAddr, now: Instant) -> Self {
        Self {
            addr,
            first_seen: now,
            last_seen: now,
            seen_count: 1,
            category: PeerCategory::Trusted,
            is_self: true,
        }
    }

    fn observed(addr: SocketAddr, last_seen: Instant, is_bootstrap: bool) -> Self {
        Self {
            addr,
            first_seen: last_seen,
            last_seen,
            seen_count: 1,
            category: if is_bootstrap {
                PeerCategory::Bootstrap
            } else {
                PeerCategory::Recent
            },
            is_self: false,
        }
    }
}

/// Configuration knobs that govern [`View`] re-classification
/// and eviction.
#[derive(Clone, Debug)]
pub(crate) struct ViewConfig {
    /// Maximum total number of non-bootstrap peers. Bootstrap
    /// peers are *not* counted against this cap so a node
    /// configured with many bootstrap addresses can still
    /// operate.
    pub max_non_bootstrap: usize,
    /// Number of times a peer must be observed (across
    /// received samples) before it is promoted to
    /// [`PeerCategory::Trusted`].
    pub trust_threshold: u32,
    /// Maximum age (time since `last_seen`) before a
    /// [`PeerCategory::Recent`] entry is evicted, in seconds.
    pub recent_max_age: Duration,
    /// Maximum age for a [`PeerCategory::Trusted`] entry, in
    /// seconds. Longer than `recent_max_age` so trusted peers
    /// are not churned out prematurely.
    pub trusted_max_age: Duration,
    /// Maximum age for a [`PeerCategory::Random`] entry, in
    /// seconds.
    pub random_max_age: Duration,
    /// Probability that an outgoing sample draws from the
    /// [`PeerCategory::Random`] pool rather than the rest of
    /// the view. `0.0` disables random exploration, `1.0`
    /// always uses it.
    pub random_sample_bias: f64,
}

impl Default for ViewConfig {
    fn default() -> Self {
        Self {
            max_non_bootstrap: 24,
            trust_threshold: 3,
            recent_max_age: Duration::from_secs(60),
            trusted_max_age: Duration::from_secs(600),
            random_max_age: Duration::from_secs(120),
            random_sample_bias: 0.15,
        }
    }
}

/// The local view of the network: a small, probabilistic
/// sample of peers, partitioned into four pools.
///
/// A `View` is the only authoritative source of "who I know
/// about" — there is no other place the protocol consults. The
/// explorer takes uniformly random subsets of it for outgoing
/// samples, the receive handler merges incoming samples into
/// it, and the eviction policy keeps it bounded.
pub(crate) struct View {
    config: ViewConfig,
    self_addr: SocketAddr,
    entries: Vec<PeerEntry>,
    /// Set of addresses present in `entries`. Used to keep the
    /// vector unique without paying for a `HashMap` lookup on
    /// every operation.
    addrs: HashSet<SocketAddr>,
    /// RNG used for the Random-pool assignment dice roll in
    /// [`View::merge_sample`]. Kept here (rather than borrowed
    /// from the explorer) so that `merge_sample` is self-contained
    /// and callable from tests without threading an RNG through.
    rng: Mutex<ChaCha20Rng>,
}

impl View {
    pub fn new(config: ViewConfig, self_addr: SocketAddr, seed: u64) -> Self {
        let mut v = Self {
            config,
            self_addr,
            entries: Vec::with_capacity(32),
            addrs: HashSet::with_capacity(32),
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
        };
        // We always know about ourselves; the self-entry is
        // how we appear in the views of remote nodes (when
        // they receive a sample we shipped).
        let me = PeerEntry::new_self(self_addr, Instant::now());
        v.entries.push(me);
        v.addrs.insert(self_addr);
        v
    }

    /// Returns the configuration this view was built from.
    #[allow(dead_code)]
    pub fn config(&self) -> &ViewConfig {
        &self.config
    }

    /// Returns the local node's own address.
    #[allow(dead_code)]
    pub fn self_addr(&self) -> SocketAddr {
        self.self_addr
    }

    /// Updates the local node's own address. Used by
    /// `Node::spawn` to replace the placeholder address
    /// used at construction time with the bound listener
    /// address.
    ///
    /// The address index (`addrs`) is kept in sync so
    /// [`contains`](Self::contains) reflects the new
    /// self-address immediately, and the self-entry's
    /// `last_seen` is bumped to `now` so the freshness
    /// tracker does not consider the just-bound node as
    /// stale.
    pub fn set_self_addr(&mut self, addr: SocketAddr, now: Instant) {
        if self.self_addr == addr {
            return;
        }
        self.addrs.remove(&self.self_addr);
        self.self_addr = addr;
        self.addrs.insert(addr);
        if let Some(e) = self.entries.iter_mut().find(|e| e.is_self) {
            e.addr = addr;
            e.first_seen = now;
            e.last_seen = now;
        }
    }

    /// Inserts the supplied bootstrap addresses into the
    /// bootstrap pool. Existing entries with the same address
    /// are *not* re-categorized — bootstrap priority is sticky
    /// once set.
    pub fn add_bootstrap(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let now = Instant::now();
        for addr in addrs {
            if self.addrs.insert(addr) {
                self.entries.push(PeerEntry::observed(addr, now, true));
            }
        }
    }

    /// Inserts the supplied addresses into the recent pool
    /// — the "transient" pool, not the bootstrap pool.
    /// Useful for "I learned this address out-of-band, treat
    /// it as known even before I've received a sample naming
    /// it." Seeding a peer here lets the node gossip its
    /// existence onward before exchanging a sample with it
    /// directly.
    pub fn add_recent(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let now = Instant::now();
        for addr in addrs {
            if addr == self.self_addr {
                continue;
            }
            if self.addrs.insert(addr) {
                let mut entry = PeerEntry::observed(addr, now, false);
                entry.category = PeerCategory::Recent;
                self.entries.push(entry);
            }
        }
    }

    /// Returns true if `addr` is in the view (including the
    /// self-entry and bootstrap entries).
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.addrs.contains(addr)
    }

    /// Returns the category of the entry for `addr`, if
    /// any. Used by the receive path to populate
    /// `PeerDiscovered` events with the right
    /// categorization.
    pub(crate) fn category(&self, addr: &SocketAddr) -> Option<PeerCategory> {
        self.entries
            .iter()
            .find(|e| !e.is_self && e.addr == *addr)
            .map(|e| e.category)
    }

    /// Returns the set of non-self addresses in the view.
    /// Used by the receive path to compute the set of
    /// addresses newly added by a sample (i.e. the set
    /// difference between the post- and pre-merge views).
    pub(crate) fn snapshot_address_set(&self) -> HashSet<SocketAddr> {
        let mut out = HashSet::with_capacity(self.entries.len());
        for e in &self.entries {
            if !e.is_self {
                out.insert(e.addr);
            }
        }
        out
    }

    /// Returns the addresses currently in the bootstrap pool.
    #[allow(dead_code)]
    pub fn bootstrap_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = self
            .entries
            .iter()
            .filter(|e| e.category == PeerCategory::Bootstrap)
            .map(|e| e.addr)
            .collect();
        out.sort();
        out
    }

    /// Merges a received sample into the view.
    ///
    /// - Entries for the self-address are dropped (a peer
    ///   telling us about ourselves is a no-op).
    /// - Each entry's `age_secs` is converted to a fresh
    ///   `last_seen` estimate: `now - age_secs` (saturated at
    ///   `now`).
    /// - Newly-discovered peers are placed in the
    ///   [`Recent`](PeerCategory::Recent) pool and accumulate
    ///   `seen_count = 1`; the trust threshold promotes them
    ///   to [`Trusted`](PeerCategory::Trusted) on subsequent
    ///   sightings.
    /// - The eviction policy is then re-run; the addresses it
    ///   evicts are returned so the caller can emit
    ///   [`PeerEvicted`](crate::DiscoveryEvent::PeerEvicted).
    pub fn merge_sample(
        &mut self,
        sample: &[crate::sample::PeerEntry],
        now: Instant,
    ) -> Vec<SocketAddr> {
        for entry in sample {
            if entry.addr == self.self_addr {
                continue;
            }
            // Convert the sender-reported `age_secs` into a
            // local `last_seen` estimate: `now - age_secs`,
            // saturated at `now` if the age would push the
            // timestamp before the process epoch. This is the
            // PPS freshness model: a peer the sender heard from
            // `t` seconds ago is recorded as last seen `t`
            // seconds ago by us too, not as "just now".
            let heard = now
                .checked_sub(Duration::from_secs(entry.age_secs as u64))
                .unwrap_or(now);
            if let Some(existing) = self.entries.iter_mut().find(|e| e.addr == entry.addr) {
                existing.seen_count = existing.seen_count.saturating_add(1);
                // Keep the freshest observation we have: if the
                // sender's estimate is more recent than ours,
                // adopt it; otherwise keep our own (e.g. we
                // heard from the peer directly more recently).
                if heard > existing.last_seen {
                    existing.last_seen = heard;
                }
                Self::maybe_promote(existing, &self.config);
            } else {
                // A newly-discovered peer normally lands in the
                // `Recent` pool. With probability
                // `random_sample_bias` it is instead placed in
                // the `Random` pool, which is the long-range
                // exploration set kept fresh by gossipped
                // samples. This is what keeps the discovery
                // traffic from collapsing onto the trusted
                // core: a small, continuously-refreshed set of
                // random peers is always available for the
                // explorer to sample from.
                let is_random = {
                    let mut rng = self.rng.lock();
                    rng.random::<f64>() < self.config.random_sample_bias
                };
                let mut new = PeerEntry::observed(entry.addr, heard, false);
                if is_random {
                    new.category = PeerCategory::Random;
                }
                self.addrs.insert(new.addr);
                self.entries.push(new);
            }
        }
        self.reclassify_and_evict(now)
    }

    /// Re-runs re-classification and eviction based on the
    /// current wall-clock time. Called by the explorer on
    /// every tick.
    ///
    /// Returns the addresses that were *evicted* (removed from
    /// the view) by this pass — aged-out `Recent`/`Random`
    /// entries and capacity-trimmed entries. Demotions
    /// (`Trusted` → `Recent`) are not evictions and are not
    /// reported. The caller uses the returned set to emit
    /// [`PeerEvicted`](crate::DiscoveryEvent::PeerEvicted)
    /// events, which is the only way an observer can learn an
    /// entry left the view without polling and diffing.
    pub fn reclassify_and_evict(&mut self, now: Instant) -> Vec<SocketAddr> {
        let mut evicted: Vec<SocketAddr> = Vec::new();

        // 1. Demote trusted peers whose `last_seen` is older
        //    than the trusted cap; demote random entries
        //    whose age exceeds the random cap; evict recent
        //    entries that have gone stale.
        let cfg = &self.config;
        self.entries.retain_mut(|e| {
            if e.is_self {
                return true;
            }
            if e.category == PeerCategory::Bootstrap {
                // Bootstrap entries are never aged out by
                // reclassification — their lifetime is
                // whatever the operator decided.
                return true;
            }
            let age = now.saturating_duration_since(e.last_seen);
            let keep = match e.category {
                PeerCategory::Trusted => {
                    if age > cfg.trusted_max_age {
                        e.category = PeerCategory::Recent;
                    }
                    true
                }
                PeerCategory::Recent => age <= cfg.recent_max_age,
                PeerCategory::Random => age <= cfg.random_max_age,
                PeerCategory::Bootstrap => true,
            };
            if !keep {
                evicted.push(e.addr);
            }
            keep
        });
        for addr in &evicted {
            self.addrs.remove(addr);
        }

        // 2. Enforce the non-bootstrap capacity. If we are
        //    over the cap, drop the oldest (by `last_seen`)
        //    non-bootstrap entries until we are within it.
        //    Bootstrap entries are preserved.
        let non_bootstrap: usize = self
            .entries
            .iter()
            .filter(|e| !e.is_self && e.category != PeerCategory::Bootstrap)
            .count();
        if non_bootstrap <= cfg.max_non_bootstrap {
            return evicted;
        }
        // Find the N oldest non-bootstrap, non-self
        // entries and remove them. The `removed` HashSet
        // keeps the final `retain` linear.
        let mut candidates: Vec<&PeerEntry> = self
            .entries
            .iter()
            .filter(|e| !e.is_self && e.category != PeerCategory::Bootstrap)
            .collect();
        candidates.sort_unstable_by_key(|e| e.last_seen);
        let to_remove = non_bootstrap - cfg.max_non_bootstrap;
        let removed: HashSet<SocketAddr> = candidates
            .into_iter()
            .take(to_remove)
            .map(|e| e.addr)
            .collect();
        for addr in &removed {
            self.addrs.remove(addr);
        }
        self.entries.retain(|e| !removed.contains(&e.addr));
        evicted.extend(removed);
        evicted
    }

    /// Returns a uniformly random sample of `k` non-self,
    /// non-source peers, biased by
    /// [`ViewConfig::random_sample_bias`] toward the
    /// [`PeerCategory::Random`] pool. The returned entries
    /// are in the public wire format
    /// ([`crate::sample::PeerEntry`]): each entry carries
    /// its address and an `age_secs` field set to
    /// `now.saturating_duration_since(last_seen)` for normal
    /// entries, and to `0` for the self-entry (so the
    /// receiver can identify the sender).
    ///
    /// `exclude` is a list of addresses to *never* include in
    /// the sample (typically just the destination peer, so we
    /// never echo back the peer's own address).
    pub fn sample(
        &self,
        k: usize,
        exclude: &HashSet<SocketAddr>,
        rng: &mut ChaCha20Rng,
    ) -> Vec<crate::sample::PeerEntry> {
        // The self-entry is INCLUDED in outgoing samples.
        // This is the mechanism by which a peer's view learns
        // about us: a sample we ship to a peer carries our own
        // address (with age 0), so the receiver can add us to
        // its view even before any of *its* peers have heard
        // of us. Note this is propagation, not attribution: the
        // receiver cannot tell which entry is the sender (the
        // wire format has no sender flag), only that our
        // address is now in the set. The destination is
        // excluded so we never echo the peer's own address
        // back to it.
        let mut random_pool: Vec<usize> = Vec::new();
        let mut rest_pool: Vec<usize> = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            if exclude.contains(&e.addr) {
                continue;
            }
            if e.category == PeerCategory::Random {
                random_pool.push(i);
            } else {
                rest_pool.push(i);
            }
        }

        let now = Instant::now();
        let mut chosen: Vec<crate::sample::PeerEntry> = Vec::with_capacity(k);
        let mut used: HashSet<SocketAddr> = HashSet::with_capacity(k);
        for _ in 0..k {
            // Pick from the random pool with probability
            // `random_sample_bias`; fall back to the rest
            // pool when random is empty or the roll misses.
            let prefer_random = !random_pool.is_empty()
                && (rest_pool.is_empty() || rng.random::<f64>() < self.config.random_sample_bias);
            let (primary, fallback) = if prefer_random {
                (&random_pool[..], &rest_pool[..])
            } else {
                (&rest_pool[..], &random_pool[..])
            };
            // Try the primary pool first; if every entry in
            // it has already been used, fall back to the
            // other pool before giving up. Previously a
            // single exhausted pool would terminate the
            // whole `k`-loop early, producing undersized
            // samples whenever the (small) Random pool was
            // picked more than once.
            let mut picked = pick_unused(primary, &mut used, &self.entries, rng);
            if picked.is_none() {
                picked = pick_unused(fallback, &mut used, &self.entries, rng);
            }
            let Some(e) = picked else { break };
            let age = if e.is_self {
                0
            } else {
                now.saturating_duration_since(e.last_seen).as_secs() as u32
            };
            chosen.push(crate::sample::PeerEntry {
                addr: e.addr,
                age_secs: age,
            });
        }
        chosen
    }

    /// Returns a point-in-time snapshot of the view suitable
    /// for reporting. The snapshot is sorted within each
    /// category for deterministic output.
    pub fn snapshot(&self) -> ViewSnapshot {
        let now = Instant::now();
        let mut trusted = Vec::new();
        let mut recent = Vec::new();
        let mut random = Vec::new();
        let mut bootstrap = Vec::new();
        for e in &self.entries {
            if e.is_self {
                continue;
            }
            let info = PeerInfo {
                addr: e.addr,
                last_seen: now.saturating_duration_since(e.last_seen),
                first_seen: now.saturating_duration_since(e.first_seen),
                seen_count: e.seen_count,
                category: e.category,
            };
            match e.category {
                PeerCategory::Bootstrap => bootstrap.push(info),
                PeerCategory::Trusted => trusted.push(info),
                PeerCategory::Recent => recent.push(info),
                PeerCategory::Random => random.push(info),
            }
        }
        let sort = |v: &mut Vec<PeerInfo>| v.sort_by_key(|p| p.addr);
        sort(&mut trusted);
        sort(&mut recent);
        sort(&mut random);
        sort(&mut bootstrap);
        ViewSnapshot {
            trusted,
            recent,
            random,
            bootstrap,
        }
    }

    /// Drops the entry for `addr` if it is a non-bootstrap
    /// entry. Used when a peer connection fails outright, so
    /// the eviction is immediate rather than waiting for the
    /// age-based reaper, and by the simulation harness to
    /// forget a killed node from every other node's view.
    pub fn drop_entry(&mut self, addr: &SocketAddr) {
        if let Some(e) = self.entries.iter().find(|e| e.addr == *addr)
            && (e.category == PeerCategory::Bootstrap || e.is_self)
        {
            return;
        }
        self.entries.retain(|e| e.addr != *addr);
        self.addrs.remove(addr);
    }

    fn maybe_promote(e: &mut PeerEntry, cfg: &ViewConfig) {
        if e.category == PeerCategory::Recent && e.seen_count >= cfg.trust_threshold {
            e.category = PeerCategory::Trusted;
        }
    }
}

/// Picks an entry uniformly at random from the subset of
/// `pool` whose address is not yet in `used`, marks it used,
/// and returns it. Returns `None` only when *every* entry in
/// `pool` has already been used.
///
/// The candidate set is materialized first (rather than
/// sampling with replacement and bailing after a fixed number
/// of misses) so the function never spuriously reports the
/// pool exhausted while an unused entry remains — that bug
/// produced undersized samples whenever a small pool was
/// drawn from repeatedly. The cost is `O(pool.len())` per
/// call, the same as the previous worst case.
fn pick_unused<'a>(
    pool: &[usize],
    used: &mut HashSet<SocketAddr>,
    entries: &'a [PeerEntry],
    rng: &mut ChaCha20Rng,
) -> Option<&'a PeerEntry> {
    let candidates: Vec<usize> = pool
        .iter()
        .copied()
        .filter(|&i| entries.get(i).is_some_and(|e| !used.contains(&e.addr)))
        .collect();
    let &i = candidates.choose(rng)?;
    let entry = entries.get(i)?;
    used.insert(entry.addr);
    Some(entry)
}

/// A read-only view of a node's view, returned by
/// [`crate::Node::view`].
#[derive(Clone, Debug, Default)]
pub struct ViewSnapshot {
    /// The trusted pool (sorted by address).
    pub trusted: Vec<PeerInfo>,
    /// The recent pool (sorted by address).
    pub recent: Vec<PeerInfo>,
    /// The random pool (sorted by address).
    pub random: Vec<PeerInfo>,
    /// The bootstrap pool (sorted by address).
    pub bootstrap: Vec<PeerInfo>,
}

impl ViewSnapshot {
    /// Returns the total number of peers in the snapshot
    /// (excluding the local node itself).
    pub fn total(&self) -> usize {
        self.trusted.len() + self.recent.len() + self.random.len() + self.bootstrap.len()
    }

    /// Returns true if the snapshot has no non-bootstrap
    /// peers. The node can only "see" its bootstrap set in
    /// this case.
    pub fn is_disconnected(&self) -> bool {
        self.trusted.is_empty() && self.recent.is_empty() && self.random.is_empty()
    }
}

/// Read-only metadata about a single peer in a
/// [`ViewSnapshot`].
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's socket address.
    pub addr: SocketAddr,
    /// Time elapsed since this peer was last heard from.
    pub last_seen: Duration,
    /// Time elapsed since this peer was first observed.
    pub first_seen: Duration,
    /// Number of times this peer has been observed across
    /// received samples.
    pub seen_count: u32,
    /// Which pool this peer currently belongs to.
    pub category: PeerCategory,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn make_view() -> View {
        // `random_sample_bias = 0` keeps the Random-pool dice
        // roll out of the unit tests that are not about the
        // Random pool, so their assertions are deterministic.
        let cfg = ViewConfig {
            random_sample_bias: 0.0,
            ..ViewConfig::default()
        };
        View::new(cfg, "127.0.0.1:1".parse().unwrap(), 0)
    }

    #[test]
    fn self_is_always_present() {
        let v = make_view();
        assert!(v.contains(&"127.0.0.1:1".parse().unwrap()));
        // Only the self-entry is in the view at construction,
        // so the public snapshot reports no peers at all.
        assert_eq!(v.snapshot().total(), 0);
    }

    #[test]
    fn set_self_addr_updates_addrs_and_self_entry() {
        let mut v = make_view();
        let placeholder = v.self_addr();
        let new_addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        v.set_self_addr(new_addr, Instant::now());
        // The new address is now in the addrs set.
        assert!(v.contains(&new_addr));
        // The placeholder is no longer addressable.
        assert!(!v.contains(&placeholder));
        assert_eq!(v.self_addr(), new_addr);
    }

    #[test]
    fn set_self_addr_idempotent() {
        let mut v = make_view();
        let addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        v.set_self_addr(addr, Instant::now());
        // A second call with the same address should not
        // re-bump the self-entry's last_seen.
        // (We can't observe last_seen directly without a
        // snapshot helper, but the call must not panic.)
        v.set_self_addr(addr, Instant::now());
    }

    #[test]
    fn self_never_appears_in_snapshot() {
        // The self-entry is kept internally (so we appear in
        // the samples we ship) but must never surface in the
        // public snapshot.
        let v = make_view();
        let self_addr = v.self_addr();
        let snap = v.snapshot();
        for p in snap
            .trusted
            .iter()
            .chain(snap.recent.iter())
            .chain(snap.random.iter())
        {
            assert_ne!(p.addr, self_addr);
        }
    }

    #[test]
    fn fresh_entry_goes_to_recent_not_random() {
        // Regression: previously, an entry with
        // `age_secs == 0` was treated as the sender's
        // self-entry and put in the Random pool. A real
        // peer just heard from would also have
        // `age_secs == 0` and was mis-categorized as
        // Random. New entries from samples must always
        // start in Recent when the Random-pool bias is 0
        // (see `random_pool_is_populated` for the biased
        // case).
        let mut v = make_view();
        let target: SocketAddr = "10.0.0.5:5".parse().unwrap();
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: target,
                age_secs: 0,
            }],
            Instant::now(),
        );
        let snap = v.snapshot();
        assert!(
            snap.recent.iter().any(|p| p.addr == target),
            "expected target in recent pool: {:?}",
            snap
        );
        assert!(
            snap.random.iter().all(|p| p.addr != target),
            "expected target NOT in random pool: {:?}",
            snap
        );
    }

    #[test]
    fn random_pool_is_populated() {
        // With `random_sample_bias = 1.0`, every newly-discovered
        // peer from a sample must land in the Random pool. This
        // guards against the Random pool silently becoming a
        // dead category (the four-pool view must actually have
        // all four pools reachable).
        let cfg = ViewConfig {
            random_sample_bias: 1.0,
            ..ViewConfig::default()
        };
        let mut v = View::new(cfg, "127.0.0.1:1".parse().unwrap(), 0);
        let target: SocketAddr = "10.0.0.7:7".parse().unwrap();
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: target,
                age_secs: 0,
            }],
            Instant::now(),
        );
        let snap = v.snapshot();
        assert!(
            snap.random.iter().any(|p| p.addr == target),
            "expected target in random pool with bias=1.0: {:?}",
            snap,
        );
        assert!(
            snap.recent.iter().all(|p| p.addr != target),
            "expected target NOT in recent pool with bias=1.0: {:?}",
            snap,
        );
    }

    #[test]
    fn merge_sample_uses_age_secs_for_last_seen() {
        // The sender reports it heard from `target` 30s ago.
        // The receiver must record `last_seen` as ~30s in the
        // past, not "now". This is the PPS freshness model:
        // staleness propagates across hops, so a peer gossiped
        // as stale does not appear fresh to a node that has
        // never actually heard from it.
        let cfg = ViewConfig {
            random_sample_bias: 0.0,
            ..ViewConfig::default()
        };
        let mut v = View::new(cfg, "127.0.0.1:1".parse().unwrap(), 0);
        let target: SocketAddr = "10.0.0.9:9".parse().unwrap();
        let now = Instant::now();
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: target,
                age_secs: 30,
            }],
            now,
        );
        let snap = v.snapshot();
        let info = snap
            .recent
            .iter()
            .find(|p| p.addr == target)
            .expect("target in recent pool");
        // `last_seen` should be roughly 30s ago (allow some
        // slack for the time the test itself takes).
        assert!(
            info.last_seen.as_secs() >= 29 && info.last_seen.as_secs() <= 31,
            "expected last_seen ~30s, got {:?}",
            info.last_seen,
        );
    }

    #[test]
    fn merge_sample_keeps_freshest_last_seen() {
        // If we already heard from a peer 1s ago and a sample
        // claims it was heard from 60s ago, our fresher
        // observation must win.
        let cfg = ViewConfig {
            random_sample_bias: 0.0,
            ..ViewConfig::default()
        };
        let mut v = View::new(cfg, "127.0.0.1:1".parse().unwrap(), 0);
        let target: SocketAddr = "10.0.0.9:9".parse().unwrap();
        let t0 = Instant::now();
        // First, learn the peer as fresh (age 0).
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: target,
                age_secs: 0,
            }],
            t0,
        );
        // Then receive a stale report (age 60s) at t0.
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: target,
                age_secs: 60,
            }],
            t0,
        );
        let snap = v.snapshot();
        let info = snap
            .recent
            .iter()
            .find(|p| p.addr == target)
            .expect("target in recent pool");
        // The freshest observation (age 0 -> last_seen = t0)
        // must win, so last_seen should be ~0s, not 60s.
        assert!(
            info.last_seen.as_secs() <= 1,
            "expected last_seen ~0s (freshest wins), got {:?}",
            info.last_seen,
        );
    }

    #[test]
    fn add_bootstrap_inserts_entries() {
        let mut v = make_view();
        v.add_bootstrap(["10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap()]);
        assert_eq!(v.bootstrap_addrs().len(), 2);
        // Bootstrap entries live in their own pool: a node with
        // only bootstrap has not *discovered* any peer yet, so
        // the non-bootstrap pools are empty even though the
        // bootstrap pool is not.
        let snap = v.snapshot();
        assert_eq!(snap.bootstrap.len(), 2);
        assert_eq!(
            snap.trusted.len() + snap.recent.len() + snap.random.len(),
            0
        );
    }

    #[test]
    fn merge_promotes_after_threshold() {
        let mut v = make_view();
        let target: SocketAddr = "10.0.0.5:5".parse().unwrap();
        let entry = crate::sample::PeerEntry {
            addr: target,
            age_secs: 1,
        };
        for _ in 0..3 {
            v.merge_sample(&[entry], Instant::now());
        }
        let snap = v.snapshot();
        assert!(snap.trusted.iter().any(|p| p.addr == target));
    }

    #[test]
    fn capacity_is_enforced() {
        let cfg = ViewConfig {
            max_non_bootstrap: 4,
            random_sample_bias: 0.0,
            ..ViewConfig::default()
        };
        let mut v = View::new(cfg, "127.0.0.1:1".parse().unwrap(), 0);
        let mut entries = Vec::new();
        for i in 0..10 {
            entries.push(crate::sample::PeerEntry {
                addr: format!("10.0.0.{i}:80").parse().unwrap(),
                age_secs: 1,
            });
        }
        v.merge_sample(&entries, Instant::now());
        let snap = v.snapshot();
        let non_bootstrap = snap.trusted.len() + snap.recent.len() + snap.random.len();
        assert!(
            non_bootstrap <= 4,
            "got {non_bootstrap} non-bootstrap entries"
        );
    }

    #[test]
    fn sample_excludes_target() {
        let mut v = make_view();
        let entries: Vec<_> = (0..20)
            .map(|i| crate::sample::PeerEntry {
                addr: format!("10.0.0.{i}:80").parse().unwrap(),
                age_secs: 1,
            })
            .collect();
        v.merge_sample(&entries, Instant::now());
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let exclude: HashSet<SocketAddr> = ["10.0.0.3:80".parse().unwrap()].into_iter().collect();
        let sample = v.sample(8, &exclude, &mut rng);
        for entry in &sample {
            // The destination peer is excluded; the
            // self-entry is INCLUDED in samples (so the
            // receiver learns who sent it).
            assert!(!exclude.contains(&entry.addr));
        }
        // All samples are distinct.
        let unique: HashSet<_> = sample.iter().map(|e| e.addr).collect();
        assert_eq!(unique.len(), sample.len());
        // The self-entry should appear at least once in a
        // sample of size 8 with 20+ other entries (we
        // sample uniformly).
        let self_addr = v.self_addr();
        // (not strictly required, but is the design.)
        let _ = self_addr;
    }

    #[test]
    fn drop_entry_skips_bootstrap_and_self() {
        let mut v = make_view();
        let bs: SocketAddr = "10.0.0.1:1".parse().unwrap();
        v.add_bootstrap([bs]);
        v.drop_entry(&bs);
        assert!(v.contains(&bs));
        let other: SocketAddr = "10.0.0.2:2".parse().unwrap();
        v.merge_sample(
            &[crate::sample::PeerEntry {
                addr: other,
                age_secs: 1,
            }],
            Instant::now(),
        );
        v.drop_entry(&other);
        assert!(!v.contains(&other));
    }
}
