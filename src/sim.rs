//! Deterministic local simulations for `peaveil`.
//!
//! The [`Simulation`] type is a self-contained harness that
//! spawns a configured number of [`Node`]s, wires them into a
//! desired topology, drives the network forward in time, and
//! exposes metrics: peer-coverage, view sizes, churn recovery,
//! partition recovery, bootstrap latency, and total bytes
//! emitted on the wire.
//!
//! # Determinism
//!
//! All random choices (sample target selection, bootstrap order,
//! churn victim selection) are drawn from a single seeded
//! `rand_chacha::ChaCha20Rng`, so re-running the simulation
//! with the same seed and configuration produces metrics in
//! the same bands.
//!
//! Exact bit-for-bit equality across runs is *not* guaranteed
//! because the explorer ticks on real wall-clock time; the
//! OS scheduler is allowed to interleave per-node
//! background tasks differently across runs. To get
//! bit-exact determinism, swap the explorer's `tokio::time::interval`
//! for a virtual-clock ticker (e.g. behind `tokio::time::pause()`).
//!
//! # Topology
//!
//! The simulation starts with every node bound on loopback.
//! Use [`connect_mesh`](Simulation::connect_mesh) or
//! [`connect_ring`](Simulation::connect_ring) to wire them up.
//! For partitioned experiments, [`partition`](Simulation::partition)
//! and [`heal_partition`](Simulation::heal_partition) are the
//! relevant knobs.
//!
//! # Churn
//!
//! [`kill`](Simulation::kill) is the low-level churn primitive.
//! [`inject_churn`](Simulation::inject_churn) drives it randomly
//! with the simulation's RNG, so "scenario = (seed,
//! view_size, sample_size, churn_rate)" fully describes an
//! experiment.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::seq::IndexedRandom;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::time;

use crate::config::NodeConfig;
use crate::node::Node;

/// Default per-node configuration for a simulation. Tuned for
/// a fast mix on a 20–200-node overlay: a small view (16),
/// a small sample (6), a quick exchange (200 ms), a
/// constant cover rate of 50 ms, and a 256-byte frame that
/// comfortably holds both.
pub fn sim_config() -> NodeConfig {
    NodeConfig {
        view_size: 16,
        sample_size: 6,
        exchange_interval: Duration::from_millis(200),
        cover: crate::config::CoverStrategy::Constant {
            interval: Duration::from_millis(50),
        },
        frame_size: 256,
        max_connections: 64,
        ..Default::default()
    }
}

/// The simulation harness.
pub struct Simulation {
    rng: ChaCha20Rng,
    /// The nodes under test, in spawn order.
    nodes: Vec<Node>,
    /// Their listening addresses, captured at spawn time.
    addrs: Vec<SocketAddr>,
    /// Tracks which nodes are currently alive. Built
    /// eagerly in `new` (every spawned node is alive) and
    /// pruned by `kill`.
    alive_set: HashSet<usize>,
    /// Wall-clock at construction; used to report elapsed
    /// time relative to "now" (e.g. for bootstrap latency).
    started_at: Instant,
    /// The set of (group_a, group_b) indices that are
    /// currently partitioned. The TCP connections across the
    /// boundary are torn down when a partition is created
    /// and re-established when it heals.
    partition: Option<(Vec<usize>, Vec<usize>)>,
}

/// The metrics reported by [`Simulation::metrics`]. All
/// fields are in the units documented in the field
/// docstrings.
#[derive(Clone, Debug, Default)]
pub struct Metrics {
    /// Wall-clock seconds since the simulation was built.
    pub elapsed_secs: f64,
    /// Number of nodes currently alive (i.e. not killed).
    pub alive: usize,
    /// Total number of nodes the simulation was built with.
    pub total: usize,
    /// Average view size, taken across all alive nodes
    /// (bootstrap entries and the self-entry are not
    /// counted).
    pub avg_view_size: f64,
    /// Average number of trusted peers per alive node.
    pub avg_trusted: f64,
    /// Average number of recent peers per alive node.
    pub avg_recent: f64,
    /// Average number of random peers per alive node.
    pub avg_random: f64,
    /// Average number of bootstrap peers per alive node.
    pub avg_bootstrap: f64,
    /// "Coverage" — the fraction of alive nodes that are
    /// known by an average node. A coverage of 0.0 means
    /// the average node knows nobody; 1.0 means it knows
    /// every other alive node.
    pub coverage: f64,
}

impl Simulation {
    /// Builds a new simulation with `n` nodes, each using
    /// the supplied configuration, all seeded from `seed`
    /// (so the per-node explorer RNGs and the simulation
    /// harness's churn RNG are all reproducible from the
    /// same source).
    pub async fn new(n: usize, seed: u64, config: NodeConfig) -> Self {
        let rng = ChaCha20Rng::seed_from_u64(seed);
        let mut nodes = Vec::with_capacity(n);
        let mut addrs = Vec::with_capacity(n);
        let mut alive_set = HashSet::with_capacity(n);
        for i in 0..n {
            let cfg = NodeConfig {
                name: Some(format!("sim-{i:03}")),
                listener_addr: Some("127.0.0.1:0".parse().unwrap()),
                ..config.clone()
            };
            // Per-node seed is a deterministic function of
            // the simulation seed and the index.
            let node_seed = seed
                .wrapping_add(i as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let node = Node::with_seed(cfg, node_seed);
            let addr = node.spawn().await.expect("spawn");
            let addr = addr.expect("listener bound");
            nodes.push(node);
            addrs.push(addr);
            alive_set.insert(i);
        }
        Self {
            rng,
            nodes,
            addrs,
            alive_set,
            started_at: Instant::now(),
            partition: None,
        }
    }

    /// Returns the number of nodes in the simulation.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the simulation has no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns a reference to a node by index.
    pub fn node(&self, i: usize) -> &Node {
        &self.nodes[i]
    }

    /// Returns a slice of all nodes.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns the listening address of node `i`.
    pub fn addr(&self, i: usize) -> SocketAddr {
        self.addrs[i]
    }

    /// Returns the indices of currently-alive nodes, in
    /// ascending order.
    pub fn alive(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.alive_set.iter().copied().collect();
        v.sort();
        v
    }

    /// Returns the index of an alive node uniformly at
    /// random. Returns `None` if no nodes are alive.
    pub fn random_alive(&mut self) -> Option<usize> {
        let alive: Vec<usize> = self.alive_set.iter().copied().collect();
        alive.choose(&mut self.rng).copied()
    }

    /// Returns a point-in-time snapshot of the current
    /// [`Metrics`].
    pub fn metrics(&self) -> Metrics {
        let mut m = Metrics {
            elapsed_secs: self.started_at.elapsed().as_secs_f64(),
            ..Metrics::default()
        };
        let alive: Vec<usize> = self.alive();
        m.alive = alive.len();
        m.total = self.nodes.len();
        if alive.is_empty() {
            return m;
        }
        let mut total_view = 0.0;
        let mut total_trusted = 0.0;
        let mut total_recent = 0.0;
        let mut total_random = 0.0;
        let mut total_bootstrap = 0.0;
        let mut total_coverage_n = 0.0;
        let total = alive.len();
        let alive_set: HashSet<SocketAddr> = alive.iter().map(|&i| self.addrs[i]).collect();
        for &i in &alive {
            let snap = self.nodes[i].view();
            total_trusted += snap.trusted.len() as f64;
            total_recent += snap.recent.len() as f64;
            total_random += snap.random.len() as f64;
            total_bootstrap += snap.bootstrap.len() as f64;
            total_view += (snap.trusted.len() + snap.recent.len() + snap.random.len()) as f64;
            // Coverage counts the fraction of *other* alive
            // nodes that this node has heard of. The view
            // snapshot never contains the node's own address
            // (the self-entry is filtered by `snapshot`, and a
            // peer can never enter its own view), so the
            // intersection already counts only *other* alive
            // nodes — no self-subtraction is needed.
            let known: HashSet<SocketAddr> = snap
                .trusted
                .iter()
                .chain(snap.recent.iter())
                .chain(snap.random.iter())
                .chain(snap.bootstrap.iter())
                .map(|p| p.addr)
                .collect();
            let known_alive: usize = known.intersection(&alive_set).count();
            total_coverage_n += known_alive as f64 / (total as f64 - 1.0).max(1.0);
        }
        let denom = alive.len() as f64;
        m.avg_view_size = total_view / denom;
        m.avg_trusted = total_trusted / denom;
        m.avg_recent = total_recent / denom;
        m.avg_random = total_random / denom;
        m.avg_bootstrap = total_bootstrap / denom;
        m.coverage = total_coverage_n / denom;
        m
    }

    /// Connects every node to every other node. The
    /// resulting overlay is a complete graph: `n*(n-1)/2`
    /// connections per node. This is the most expensive
    /// topology but the one that gives the fastest
    /// convergence.
    pub async fn connect_mesh(&self) {
        for i in 0..self.nodes.len() {
            for j in 0..self.nodes.len() {
                if i == j {
                    continue;
                }
                if self.crosses_partition(i, j) {
                    continue;
                }
                let _ = self.nodes[i].connect(self.addrs[j]).await;
            }
        }
    }

    /// Connects the nodes in a ring: node `i` connects to
    /// `i+1` and `i-1` (modulo `n`). A ring is the
    /// cheapest PPS-friendly topology and is what most
    /// research papers evaluate.
    pub async fn connect_ring(&self) {
        let n = self.nodes.len();
        for i in 0..n {
            for &j in &[(i + 1) % n, (i + n - 1) % n] {
                if self.crosses_partition(i, j) {
                    continue;
                }
                let _ = self.nodes[i].connect(self.addrs[j]).await;
            }
        }
    }

    /// Kills a node: tears down its connections, marks it
    /// "dead" for the harness's bookkeeping, and forgets
    /// it from every other node's view (which will be
    /// re-learned on the next sample exchange).
    pub async fn kill(&mut self, i: usize) {
        if !self.alive_set.contains(&i) {
            return;
        }
        let dead_addr = self.addrs[i];
        for peer in self.nodes[i].connected_peers() {
            let _ = self.nodes[i].disconnect(peer).await;
        }
        self.nodes[i].shutdown().await;
        self.alive_set.remove(&i);
        // Forget the dead peer from every other alive node's
        // view. The dead node will not re-announce itself, so
        // holding on to a stale entry would inflate `coverage`
        // and bias churn-resilience measurements. The entry is
        // re-learned only if some other node re-gossips it,
        // which for a truly dead node never happens.
        for &j in self.alive_set.iter() {
            self.nodes[j].drop_peer(&dead_addr);
        }
    }

    /// Creates a partition: connections across the boundary
    /// between `group_a` and `group_b` are torn down, and
    /// no new connections are accepted across it until
    /// [`heal_partition`](Self::heal_partition) is called.
    pub async fn partition(&mut self, group_a: Vec<usize>, group_b: Vec<usize>) {
        self.partition = Some((group_a.clone(), group_b.clone()));
        // Tear down cross-group connections.
        for &i in &group_a {
            for &j in &group_b {
                if self.nodes[i].connected_peers().contains(&self.addrs[j]) {
                    let _ = self.nodes[i].disconnect(self.addrs[j]).await;
                }
            }
        }
    }

    /// Heals the most recent partition. Re-creates the
    /// cross-group connections that were torn down.
    pub async fn heal_partition(&mut self) {
        let Some((a, b)) = self.partition.take() else {
            return;
        };
        for &i in &a {
            for &j in &b {
                if !self.nodes[i].connected_peers().contains(&self.addrs[j]) {
                    let _ = self.nodes[i].connect(self.addrs[j]).await;
                }
            }
        }
    }

    /// Injects random churn: each tick, every node has a
    /// `p` chance of being killed (terminal, for the
    /// prototype). Useful for resilience experiments.
    pub async fn inject_churn(&mut self, p: f64) {
        let to_kill: Vec<usize> = {
            let alive: Vec<usize> = self.alive_set.iter().copied().collect();
            alive
                .into_iter()
                .filter(|_| self.rng.random::<f64>() < p)
                .collect()
        };
        for i in to_kill {
            self.kill(i).await;
        }
    }

    /// Sleeps for `dur`, allowing the simulation's
    /// background tasks to make progress. Equivalent to
    /// `tokio::time::sleep(dur)` for the simulation's
    /// purposes, but routed through a method on
    /// `Simulation` so it can be substituted with a
    /// virtual-clock helper in the future.
    pub async fn step(&self, dur: Duration) {
        time::sleep(dur).await;
    }

    /// Gracefully shuts every node down. After this call
    /// the simulation is unusable; callers should drop it.
    pub async fn shutdown(self) {
        let alive = self.alive();
        for i in alive {
            self.nodes[i].shutdown().await;
        }
    }

    fn crosses_partition(&self, i: usize, j: usize) -> bool {
        if let Some((a, b)) = &self.partition {
            (a.contains(&i) && b.contains(&j)) || (a.contains(&j) && b.contains(&i))
        } else {
            false
        }
    }
}
