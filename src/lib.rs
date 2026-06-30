//! `peaveil` — a privacy-first peer discovery protocol.
//!
//! # What it does
//!
//! `peaveil` is a continuous, background peer discovery
//! service. It does not answer "find node X"; it answers
//! "give me enough good peers, all the time." The protocol
//! is built on three ideas:
//!
//! 1. **Probabilistic peer sampling.** Every node keeps a
//!    small, locally-known view of the network. On every
//!    tick the node picks a random peer from its view and
//!    ships a uniformly-random subset of the view (including
//!    the local self-entry) to that peer. The peer merges
//!    the received sample into its own view. The process
//!    repeats forever. This is the Newscast / Cyclon / PPS
//!    family of protocols; `peaveil` is a privacy-oriented
//!    re-implementation on top of `peashape`.
//! 2. **Continuous exploration.** There is no "done" state
//!    for discovery. Idle or busy, the node keeps sampling,
//!    re-classifying, and rotating its view. The protocol
//!    *never* pauses because there is nothing to look up —
//!    there is always something to look up, namely "more
//!    peers, to keep the view fresh."
//! 3. **Metadata resistance via `peashape`.** Every outbound
//!    `peaveil` frame is shaped by `peashape`'s cover-traffic
//!    scheduler: constant-size, constant-rate (or
//!    Poisson-distributed) emission interleaved with cover
//!    frames. An observer of the wire cannot tell when a
//!    node is actively exchanging peer samples from when it
//!    is doing nothing at all.
//!
//! # What it deliberately is not
//!
//! - Not a DHT. There is no deterministic key lookup, no XOR
//!   metric, no finger table, no logarithmic routing. The
//!   view is a *probabilistic sample* of the network, not a
//!   routing table.
//! - Not a content-discovery protocol. `peaveil` discovers
//!   *peers*; if you want content addressing, build a DHT
//!   on top.
//! - Not a global-coverage guarantee. The view is bounded
//!   and randomly sampled, so the probability of *any
//!   particular* peer being in your view at *any particular*
//!   moment is a function of the view size and the network
//!   size, not a guarantee.
//!
//! # The four pools
//!
//! The view is partitioned into four named pools:
//!
//! - **Bootstrap** — well-known addresses seeded as network
//!   entry points. They are sticky (never aged out) and do not
//!   count against `view_size`, so the node always remembers
//!   where to re-enter. `peaveil` does not dial them — see
//!   "Who opens connections?" below.
//! - **Trusted** — peers that have been seen often enough in
//!   gossip; the stable core of the view.
//! - **Recent** — peers that have been seen recently but
//!   not yet promoted to `Trusted`; the transient part of
//!   the view.
//! - **Random** — a tiny set of long-range "exploration"
//!   peers. A small fraction of outgoing samples draws from
//!   this pool specifically, so the discovery traffic does
//!   not collapse onto the trusted core.
//!
//! Re-classification between pools runs on every explorer
//! tick: trusted peers that have not been heard from in a
//! while are demoted to `Recent`; recent peers that have
//! been seen often enough are promoted to `Trusted`; and
//! any pool's entries that exceed the configured age limit
//! are evicted.
//!
//! # Who opens connections?
//!
//! The application does — never `peaveil`. `peaveil`'s scope
//! is *discoverability*: it maintains the view and gossips
//! peer samples over the connections that already exist. It
//! reads the live connection set to know which links it can
//! gossip over, but it never opens or closes one, and it never
//! probes a peer for liveness. Deciding *who* and *when* to
//! connect to — bootstrap entry points and discovered peers
//! alike — is the caller's job, using [`Node::view`] /
//! [`Node::known_peers`] as the input and [`Node::connect`] /
//! [`Node::disconnect`] (re-exported from `peashape`) to act.
//! This is the *pea*-stack philosophy: a library does strictly
//! what the caller cannot do for itself, and opening a socket
//! is something the caller can already do.
//!
//! # Composition
//!
//! `peaveil` is a building block. The most common
//! composition is to wrap it in front of a higher-level
//! protocol: the higher-level layer is in charge of the
//! application semantics (pub/sub, RPC, file chunking), and
//! uses [`Node::known_peers`] / [`Node::view`] to ask
//! `peaveil` for the current best guess of "who else is
//! out there" whenever it needs to dial a new connection.
//!
//! Because every byte `peaveil` puts on the wire goes
//! through `peashape`'s scheduler, the discovery traffic
//! inherits `peashape`'s metadata-privacy property for
//! free: the on-the-wire timing distribution and size
//! distribution are independent of whether the explorer is
//! actively sampling or has nothing to do.
//!
//! # Threat model
//!
//! `peaveil` is designed to defeat a *passive global
//! network observer* who can:
//!
//! - observe every byte sent between every pair of nodes;
//! - observe the timing of every byte;
//! - but cannot break the cryptographic primitives
//!   protecting the link (e.g. TLS via a `pea2pea`
//!   `Handshake`).
//!
//! Against such an observer, the cover-traffic schedule
//! provided by `peashape` ensures that the *timing
//! distribution* and *size distribution* of a node's
//! outbound traffic are independent of whether the
//! explorer is sampling or idle. The observer learns
//! nothing about the existence, frequency, or destination
//! of `peaveil`'s discovery activity beyond the cover rate
//! the node has been configured for.
//!
//! `peaveil` does **not** attempt to defeat:
//!
//! - an observer that can compromise the node itself;
//! - an observer that controls a non-trivial fraction of
//!   the network's nodes and can correlate views across
//!   them (the "Sybil" attack against any sampling
//!   protocol);
//! - traffic *content* analysis: `peaveil` does not
//!   encrypt the contents of a peer sample. A passive
//!   observer who can read the wire learns the full list of
//!   peers this node has been talking to. End-to-end
//!   confidentiality of the sample is the application's
//!   responsibility; layer it via a `pea2pea`
//!   [`Handshake`] (e.g. Noise / TLS), by configuring
//!   `peashape` with a custom [`peashape::CoverGenerator`]
//!   that produces encrypted-looking cover, or by
//!   encrypting the payload before submitting it to
//!   `peashape`. The constant size, constant timing, and
//!   per-tick cover that `peashape` provides still defeat
//!   the "is this node exchanging samples right now?"
//!   question regardless of whether the payload is
//!   encrypted.
//!
//! The recommended path for transport-level encryption is
//! to register a custom `Handshake` via
//! [`Node::p2p`], which exposes the underlying
//! `pea2pea::Node` so a `Handshake` can be wired in
//! *before* the listener comes up. See `examples/encrypted.rs`
//! for a minimal pre-shared-key handshake that wraps the
//! TCP stream in ChaCha20-Poly1305.
//!
//! # Measurements
//!
//! Every claim about `peaveil`'s behaviour is measurable in
//! a local simulation. The [`sim::Simulation`] type is a
//! self-contained harness that spawns a configured number
//! of nodes, wires them into a topology, drives the
//! network forward in time, and exposes:
//!
//! - **convergence time** — how long it takes for every
//!   node to learn about every other node (or for a
//!   configured coverage threshold to be reached);
//! - **peer diversity** — the average number of distinct
//!   peers in each view, broken down by pool;
//! - **resilience to churn** — coverage recovery after a
//!   fraction of the nodes is killed;
//! - **bootstrap latency** — how long it takes a node with
//!   only bootstrap peers to reach a non-trivial view
//!   size;
//! - **partition recovery** — coverage recovery after a
//!   two-group network partition is healed;
//! - **bandwidth overhead** — total bytes emitted on the
//!   wire, dominated by `peashape`'s cover traffic;
//! - **discovery stability** — the variance of view size
//!   and category distribution over time once the network
//!   has reached steady state.
//!
//! All random choices in the simulation are driven by a
//! seeded RNG, so re-running the simulation with the same
//! seed and configuration produces metrics in the same
//! bands. Exact bit-for-bit equality is not guaranteed
//! because the explorer ticks on real wall-clock time;
//! pin the clock with `tokio::time::pause()` to get
//! bit-exact determinism.
//!
//! # Quick start
//!
//! ```no_run
//! use std::time::Duration;
//! use peaveil::{CoverStrategy, Node, NodeConfig};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let alice = Node::new(NodeConfig {
//!     name: Some("alice".into()),
//!     listener_addr: Some("127.0.0.1:0".parse()?),
//!     bootstrap: vec!["127.0.0.1:9001".parse()?],
//!     cover: CoverStrategy::Constant {
//!         interval: Duration::from_millis(100),
//!     },
//!     ..Default::default()
//! });
//! alice.spawn().await?;
//!
//! // ask peaveil what it knows
//! let view = alice.view();
//! for p in view.trusted.iter().chain(view.recent.iter()).chain(view.random.iter()) {
//!     println!("{}:{} (seen {} times, last seen {:?} ago)",
//!         p.addr.ip(), p.addr.port(), p.seen_count, p.last_seen);
//! }
//!
//! alice.shutdown().await;
//! # Ok(()) }
//! ```
//!
//! [`Node::known_peers`]: crate::Node::known_peers
//! [`Node::view`]: crate::Node::view

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

mod config;
mod config_bridge;
mod error;
mod events;
mod explorer;
mod node;
mod sample;
mod view;

pub mod sim;

pub use crate::config::{CoverStrategy, NodeConfig};
pub use crate::error::Error;
pub use crate::node::{DiscoveryEvent, EVENT_CHANNEL_CAPACITY, Node};
pub use crate::sample::{DecodeError, PEAVEIL_MAGIC, PEAVEIL_VERSION, PeerEntry, PeerSample};
pub use crate::view::{PeerCategory, PeerInfo, ViewSnapshot};

/// Re-export of the `pea2pea` transport primitives that
/// `peaveil` builds on. `Node::p2p` returns the underlying
/// `pea2pea::Node`, and the `protocols` module re-exports
/// the [`Handshake`], [`Pea2Pea`], and [`Connection`]
/// types needed to wire a custom `Handshake` on top.
///
/// [`Handshake`]: pea2pea::protocols::Handshake
/// [`Pea2Pea`]: pea2pea::Pea2Pea
/// [`Connection`]: pea2pea::Connection
pub use pea2pea::{
    self, Connection, ConnectionSide, Pea2Pea, Topology, connect_nodes,
    protocols::Handshake,
};
