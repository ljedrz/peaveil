//! The background explorer task.
//!
//! The explorer is the *only* thing that actually moves
//! `peaveil` forward. On every tick it does exactly one of:
//!
//! - **Re-classify and evict.** Run the re-classification
//!   policy on the view, dropping entries that have aged out
//!   or pushing the view back under its capacity cap.
//! - **Initiate an exchange.** Pick a random peer from the
//!   *live connection set* (peaveil gossips only over links the
//!   user has opened — it never dials), draw a uniformly random
//!   subset of the view (including the self-entry, so the
//!   receiver learns about us; excluding the destination, so we
//!   don't echo the peer's own address), and ship it to that
//!   peer.
//!
//! Crucially, the explorer itself does not put bytes on the
//! wire — it builds [`PeerSample`]s and hands them to
//! [`peashape`] for shaping. The peashape scheduler decides
//! *when* a sample actually goes out (it is interleaved with
//! cover traffic at the configured rate), which is what
//! gives `peaveil` its metadata-privacy property.
//!
//! # Stochastic exchanges
//!
//! Unlike a strict request/response protocol, `peaveil` does
//! not synchronously respond to received samples. When peer B
//! receives a sample from peer A, B's view learns about A
//! (the sample includes A's self-entry). B's next explorer
//! tick picks a target uniformly at random from its connected
//! peers; if A is one of them, there is a `1 / connections`
//! chance B's sample completes the exchange, otherwise the
//! exchange is partial. This is the Newscast/Cyclon model: the
//! protocol mixes over time, and individual exchanges need not
//! be reciprocal.
//!
//! [`PeerSample`]: crate::sample::PeerSample

use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use peashape::{Lane, Target};
use rand::seq::IndexedRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::debug;

use crate::node::NodeInner;
use crate::sample::{PeerEntry, PeerSample};

/// The background explorer task.
///
/// One `Explorer` is shared by every clone of a
/// [`crate::Node`]. The `run` method blocks until the node
/// is shut down.
pub(crate) struct Explorer {
    inner: Arc<NodeInner>,
    /// RNG used for sampling and target selection.
    rng: Mutex<ChaCha20Rng>,
    /// The small set of peers we have most recently shipped
    /// a sample to. Used to bias the next "initiate" pick
    /// away from the previous target — the standard PPS
    /// ping-pong avoidance. Bounded to `recent_depth`.
    recent: Mutex<VecDeque<SocketAddr>>,
    /// Notifications fired by the receive handler or by
    /// shutdown to wake the explorer immediately rather
    /// than waiting for the next tick.
    wake: Notify,
    handle: Mutex<Option<JoinHandle<()>>>,
    /// Number of entries kept in `recent`.
    recent_depth: usize,
}

impl Explorer {
    /// Builds a fresh Explorer. The seed is used to
    /// initialize the explorer's RNG.
    pub fn new(inner: Arc<NodeInner>, seed: u64) -> Self {
        let recent_depth = inner.recent_window();
        Self {
            inner,
            rng: Mutex::new(ChaCha20Rng::seed_from_u64(seed)),
            recent: Mutex::new(VecDeque::with_capacity(recent_depth)),
            wake: Notify::new(),
            handle: Mutex::new(None),
            recent_depth,
        }
    }

    /// Reseeds the explorer's RNG. Used by the simulation
    /// harness to drive fully-reproducible runs.
    pub fn reseed(&self, seed: u64) {
        *self.rng.lock() = ChaCha20Rng::seed_from_u64(seed);
    }

    /// Wakes the explorer immediately. Called by the
    /// receive handler when a sample arrives, so the
    /// explorer runs an extra `tick` — and thus may ship a
    /// reciprocating sample — on the very next loop iteration
    /// rather than after a full `exchange_interval` of
    /// waiting. This makes exchanges reactive: a burst of
    /// inbound samples drives a matching burst of outbound
    /// ones (bounded by the high-lane capacity and peashape's
    /// drain rate, so it cannot amplify without limit). The
    /// eventual-convergence guarantee does not depend on it —
    /// it only lowers latency — but it does mean
    /// `exchange_interval` is the *idle* cadence, not a hard
    /// cap on send rate.
    pub fn poke(&self) {
        self.wake.notify_one();
    }

    /// Spawns the explorer task. Idempotent.
    pub fn spawn(&self) {
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { explorer_loop(inner).await });
        *self.handle.lock() = Some(handle);
    }

    /// Aborts the explorer task without waiting.
    pub fn abort(&self) {
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
    }
}

async fn explorer_loop(inner: Arc<NodeInner>) {
    let interval = inner.config.exchange_interval;
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    // Hoist the wake future out of the select! arm so it
    // is not re-allocated on every iteration. The ticker
    // is a small wrapper that we just re-borrow each
    // iteration; pinning it would not save any allocation
    // and complicates the borrow checker for the
    // `ticker.tick().await` future.
    let explorer = inner
        .explorer
        .get()
        .expect("explorer initialized before explorer_loop starts");
    let mut wake = std::pin::pin!(explorer.wake.notified());
    // Discard the immediate first tick that `time::interval`
    // would otherwise fire at `t=0`.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = inner.shutdown_waiter.notified() => break,
            _ = wake.as_mut() => {
                // Re-arm the wake future so the next
                // notification can be observed in the
                // following iteration.
                wake.set(explorer.wake.notified());
            }
        }
        if inner.shutting_down.load(Ordering::SeqCst) {
            break;
        }
        if let Err(e) = tick(&inner) {
            debug!(parent: inner.span.clone(), "explorer tick failed: {e}");
        }
    }
}

fn tick(inner: &Arc<NodeInner>) -> Result<(), crate::Error> {
    let now = Instant::now();

    // 1. Re-classify and evict. This is the only operation
    //    that can drop entries, so it must run before
    //    sampling to avoid sampling about-to-be-evicted
    //    entries. Eviction is internal-only knowledge, so we
    //    surface it as a `PeerEvicted` event for observers.
    let evicted = inner.view.lock().reclassify_and_evict(now);
    for addr in evicted {
        inner
            .events
            .dispatch(crate::node::DiscoveryEvent::PeerEvicted { addr });
    }

    // 2. Pick a target and ship a sample. peaveil never opens
    //    connections of its own (that is the user's call); it
    //    gossips strictly over the links the user has already
    //    established, so a tick with no connections is a no-op.
    if let Some(target) = pick_initiation_target(inner) {
        ship_sample(inner, target)?;
    }
    Ok(())
}

fn ship_sample(inner: &Arc<NodeInner>, target: SocketAddr) -> Result<(), crate::Error> {
    let explorer = inner
        .explorer
        .get()
        .expect("explorer initialized before ship_sample");
    let exclude: HashSet<SocketAddr> = [target].into_iter().collect();
    let entries: Vec<PeerEntry> = {
        let view = inner.view.lock();
        let mut rng = explorer.rng.lock();
        view.sample(inner.config.sample_size, &exclude, &mut rng)
    };
    let sample = PeerSample::from_entries(entries);
    // Build a peashape-shaped frame: 32-byte random ID
    // prefix + the peaveil sample (variable size) +
    // random padding to fill `frame_size`. The receiver
    // strips the ID prefix and decodes the rest.
    //
    // Guard against an oversized payload: the construction
    // check in `Node::with_seed` rejects configs whose
    // worst-case (all-IPv6) sample exceeds the frame, but a
    // mixed sample could in principle still overrun if the
    // config was built by hand. Returning `SampleTooLarge`
    // here keeps the constant-size-frame property intact
    // instead of letting `build_frame` truncate or overflow.
    let needed = sample.encoded_size();
    let available = inner
        .config
        .frame_size
        .saturating_sub(peashape::ID_SIZE);
    if needed > available {
        return Err(crate::Error::SampleTooLarge { needed, available });
    }
    let bytes = peashape::build_frame(inner.peashape.config(), &sample.encode()).1;

    // Record this target as "recently contacted" so the
    // next initiation step biases away from it.
    {
        let mut recent = explorer.recent.lock();
        recent.push_back(target);
        while recent.len() > explorer.recent_depth {
            recent.pop_front();
        }
    }

    // Hand the sample to peashape for shaping. The actual
    // on-the-wire emission happens on peashape's next
    // cover tick.
    if let Err(e) = inner
        .peashape
        .shaper()
        .enqueue_raw(Lane::High, Target::Unicast(target), bytes)
    {
        return Err(e.into());
    }

    // Fire a discovery event for the application.
    inner.events.dispatch(crate::node::DiscoveryEvent::SampleSent {
        to: target,
        count: sample.len(),
    });
    Ok(())
}

fn pick_initiation_target(inner: &Arc<NodeInner>) -> Option<SocketAddr> {
    let explorer = inner.explorer.get()?;
    // The set of valid gossip targets is exactly the live
    // connection set, read from peashape. peaveil does not open
    // connections, so it cannot gossip to a peer it merely knows
    // about (that is in the view); it can only gossip over links
    // the user has established. The view supplies the *payload*
    // — who we tell the target about — not the destination.
    let connected = inner.peashape.connected_peers();
    if connected.is_empty() {
        return None;
    }
    // Bias away from the most recently contacted peers to avoid
    // the ping-pong failure mode in which two adjacent nodes
    // bounce samples back and forth without the rest of the
    // network learning anything. The `recent` lock is taken and
    // released before `rng` is acquired.
    let recent: HashSet<SocketAddr> = explorer.recent.lock().iter().copied().collect();
    let mut rng = explorer.rng.lock();
    let fresh: Vec<SocketAddr> = connected
        .iter()
        .copied()
        .filter(|a| !recent.contains(a))
        .collect();
    let pool: &[SocketAddr] = if fresh.is_empty() { &connected } else { &fresh };
    pool.choose(&mut rng).copied()
}

/// Handles a frame received from a peer.
///
/// Called by the peaveil receive task for every frame that
/// successfully decodes as a peer sample. Merges the sample
/// into the view. The stochastic exchange model means we
/// don't synchronously respond; the next explorer tick will
/// pick a target at random, with some probability of it
/// being the source of this sample (which would close the
/// exchange).
pub(crate) fn handle_received_sample(inner: &Arc<NodeInner>, sample: PeerSample) {
    let now = Instant::now();
    // Take the view lock once, merge, and capture both
    // the set of new addresses and their categories before
    // releasing. Three locks per received frame was the
    // biggest hot-path cost in profiling.
    let (new_addrs, evicted): (Vec<(SocketAddr, crate::view::PeerCategory)>, Vec<SocketAddr>) = {
        let mut view = inner.view.lock();
        let before = view.snapshot_address_set();
        let evicted = view.merge_sample(sample.entries(), now);
        let after = view.snapshot_address_set();
        let new_addrs = after
            .iter()
            .filter(|addr| !before.contains(addr))
            .map(|addr| {
                let category = view
                    .category(addr)
                    .unwrap_or(crate::view::PeerCategory::Recent);
                (*addr, category)
            })
            .collect();
        // Only report evictions of entries that were actually
        // in the view before this merge: a peer that the same
        // merge both added and capacity-trimmed was never
        // observable, so it gets neither a Discovered nor an
        // Evicted event.
        let evicted = evicted
            .into_iter()
            .filter(|addr| before.contains(addr))
            .collect();
        (new_addrs, evicted)
    };
    for (addr, category) in new_addrs {
        inner
            .events
            .dispatch(crate::node::DiscoveryEvent::PeerDiscovered { addr, category });
    }
    for addr in evicted {
        inner
            .events
            .dispatch(crate::node::DiscoveryEvent::PeerEvicted { addr });
    }
    inner.events.dispatch(crate::node::DiscoveryEvent::SampleReceived {
        // The "from" address is not known at this layer
        // (peashape's broadcast strips it); report the
        // peer's *learned* set size as a coarse activity
        // signal. The protocol does not depend on this
        // value.
        from: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        count: sample.len(),
    });
    if let Some(e) = inner.explorer.get() {
        e.poke();
    }
}
