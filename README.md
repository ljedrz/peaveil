# peaveil

A privacy-first peer-discovery protocol based on
probabilistic peer sampling, gossip, and metadata-resistant
discovery.

`peaveil` does not answer *"find node X"*. It answers
*"give me enough good peers, all the time."* Discovery is
not an operation; it is a permanent background activity.

## What it is not

- Not a DHT. There is no deterministic key lookup, no XOR
  metric, no finger table, no logarithmic routing.
- Not a content-discovery protocol. `peaveil` discovers
  *peers*; layer a DHT on top if you need content
  addressing.
- Not a global-coverage guarantee. The view is bounded and
  randomly sampled, so the probability of *any particular*
  peer being in your view at *any particular* moment is a
  function of the view size and the network size, not a
  guarantee.

## How it works

`peaveil` is a Newscast / Cyclon / PPS-style
probabilistic-peer-sampling protocol with a four-pool
view. Every node keeps a small, locally-known view of the
network partitioned into:

- **Bootstrap** — well-known addresses seeded as network
  entry points; sticky and excluded from the view cap.
  `peaveil` does not dial them (see below).
- **Trusted** — peers that have been seen often enough in
  gossip; the stable core of the view.
- **Recent** — peers that have been seen recently but not
  yet promoted to `Trusted`; the transient part of the
  view.
- **Random** — a tiny set of long-range exploration peers,
  sampled with a small bias to keep the discovery traffic
  from collapsing onto the trusted core.

On every tick the explorer:

1. Re-classifies and evicts (emitting `PeerEvicted`).
2. Picks a uniformly-random peer from the *live connection
   set* — `peaveil` gossips only over links you have already
   opened.
3. Draws a random subset of the view (including the
   self-entry, so the receiver learns about the sender).
4. Hands the subset to `peashape`'s cover-traffic scheduler
   for shaping and transmission.

On receive, the sample is decoded (or, if it is a
random cover frame, dropped), merged into the view, and the
explorer is poked to consider responding on its next tick.

## Who opens connections?

You do — never `peaveil`. Its scope is *discoverability*: it
maintains the view and gossips over the connections you have
opened, and it surfaces what it learns via `Node::view` /
`Node::known_peers` and the `DiscoveryEvent` stream. Deciding
*who* and *when* to connect to — bootstrap entry points and
discovered peers alike — is yours, via `Node::connect` /
`Node::disconnect`. That is the *pea*-stack philosophy: a
library does strictly what you cannot do for yourself, and
opening a socket is something you can already do.

## Composition with `peashape` and `peasub`

`peaveil` is a building block in the *pea* stack:

```
+---------------------------------------------------+
|                application                         |
+---------------------------------------------------+
|       peaveil           peasub (pub/sub)           |   <- discovery + pub/sub
+---------------------------------------------------+
|                 peashape (cover + shaping)         |   <- constant-size, constant-rate
+---------------------------------------------------+
|                  pea2pea (transport)               |   <- TCP
+---------------------------------------------------+
```

Every byte `peaveil` puts on the wire goes through
`peashape`'s scheduler, so the on-the-wire timing
distribution and size distribution are independent of
whether the explorer is actively sampling or idle. An
observer cannot tell *"this node is exchanging peer
samples right now"* from *"this node is doing nothing at
all."*

`peasub` is the gossip / pub-sub layer of the same
family. It runs on the same `peashape` substrate but
spreads application-level messages rather than peer
samples; the two can be used side-by-side, sharing the
connection set and the cover-traffic budget.

## Threat model

`peaveil` is designed to defeat a *passive global network
observer* who can:

- observe every byte sent between every pair of nodes;
- observe the timing of every byte;
- but cannot break the cryptographic primitives
  protecting the link (e.g. TLS via a `pea2pea`
  `Handshake`).

Against such an observer, the cover-traffic schedule
provided by `peashape` ensures that the *timing
distribution* and *size distribution* of a node's outbound
traffic are independent of whether the explorer is
sampling or idle. The observer learns nothing about the
existence, frequency, or destination of `peaveil`'s
discovery activity beyond the cover rate the node has
been configured for.

`peaveil` does **not** attempt to defeat:

- an observer that can compromise the node itself;
- an observer that controls a non-trivial fraction of the
  network's nodes and can correlate views across them
  (the Sybil attack against any sampling protocol);
- traffic *content* analysis: `peaveil` does not encrypt
  the contents of a peer sample. A passive observer who
  can read the wire learns the full list of peers this
  node has been talking to. End-to-end confidentiality of
  the sample is the application's responsibility; layer it
  via a `pea2pea` `Handshake` (e.g. Noise / TLS), or
  encrypt the payload before submitting it to `peashape`.
  The constant size, constant timing, and per-tick cover
  that `peashape` provides still defeat the *"is this
  node exchanging samples right now?"* question
  regardless of whether the payload is encrypted.

`peaveil` does **not** ship its own encryption, by design
— that is the *pea*verse philosophy: a library does
strictly only what it is designed to do, and any
additional property (encryption, authentication, etc.) is
the caller's responsibility to layer on.

## Quick start

```rust,no_run
use std::time::Duration;
use peaveil::{CoverStrategy, Node, NodeConfig};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let alice = Node::new(NodeConfig {
    name: Some("alice".into()),
    listener_addr: Some("127.0.0.1:0".parse()?),
    bootstrap: vec!["127.0.0.1:9001".parse()?],
    cover: CoverStrategy::Constant {
        interval: Duration::from_millis(100),
    },
    ..Default::default()
});
alice.spawn().await?;

// ask peaveil what it knows
let view = alice.view();
for p in view.trusted.iter().chain(view.recent.iter()).chain(view.random.iter()) {
    println!("{}:{} (seen {} times, last seen {:?} ago)",
        p.addr.ip(), p.addr.port(), p.seen_count, p.last_seen);
}

alice.shutdown().await;
# Ok(()) }
```

## Measurements

Every claim about `peaveil`'s behaviour is measurable in a
local simulation. The `peaveil::sim::Simulation` type is a
self-contained harness that spawns a configured number of
nodes, wires them into a topology, drives the network
forward in time, and exposes:

| Metric                      | How to measure                                              |
| --------------------------- | ----------------------------------------------------------- |
| **convergence time**        | wall-clock seconds to a target coverage threshold           |
| **peer diversity**          | the per-category distribution of view sizes                 |
| **resilience to churn**     | coverage recovery after `Simulation::kill` of a fraction    |
| **bootstrap latency**        | wall-clock seconds for a cold start to reach view_size/2    |
| **partition recovery**       | coverage after `Simulation::heal_partition`                 |
| **bandwidth overhead**       | `frame_size * cover_rate` per peer-pair                     |
| **discovery stability**      | view-size variance over time once steady state is reached  |

All random choices (sample target, bootstrap order,
churn victim selection) are driven by a seeded RNG, so
re-running the simulation with the same seed and
configuration produces metrics in the same bands. Exact
bit-for-bit equality across runs is *not* guaranteed
because the explorer ticks on real wall-clock time; the
OS scheduler is allowed to interleave the per-node
background tasks slightly differently across runs.
Pin the explorer's clock with `tokio::time::pause()` (and
swap `tokio::time::interval` for a virtual-clock ticker)
to get bit-exact determinism.

```rust,no_run
use peaveil::sim::{sim_config, Simulation};
use std::time::Duration;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut sim = Simulation::new(20, 0xC0FFEE, sim_config()).await;
sim.connect_ring().await;
// seed views with neighbours, etc.

for _ in 0..10 {
    sim.step(Duration::from_secs(1)).await;
    let m = sim.metrics();
    println!("alive={} avg_view={:.2} coverage={:.2}",
        m.alive, m.avg_view_size, m.coverage);
}
# Ok(()) }
```

## Run the demo

```sh
cargo run --example two_nodes             # 2-node peer discovery
cargo run --example simulation_metrics    # 20-node ring + partition recovery
```

## Run the tests

```sh
cargo test                 # all tests
cargo test --lib           # codec + view unit tests
cargo test --test discovery # integration + simulation tests
```

## Architecture

```
peaveil
├── src/
│   ├── lib.rs          # public API
│   ├── config.rs       # NodeConfig, CoverStrategy
│   ├── view.rs         # the four-pool View
│   ├── sample.rs       # PeerSample wire codec
│   ├── explorer.rs     # background exploration task
│   ├── node.rs         # public Node type
│   ├── events.rs       # DiscoveryEvent broadcast
│   ├── error.rs        # Error enum
│   ├── config_bridge.rs # NodeConfig -> ShapeConfig translation
│   └── sim.rs          # Simulation harness
├── examples/
│   ├── two_nodes.rs    # minimal end-to-end
│   └── simulation_metrics.rs  # measurement run
└── tests/
    └── discovery.rs    # integration + simulation tests
```

## License

CC0-1.0 OR MIT.

## 🫛 Peapod

This library is part of the Peapod: a collection of small, composable Rust libraries for building robust peer-to-peer systems.

| Library | Purpose |
| ------- | ------- |
| `pea2pea` | Lightweight P2P networking primitive |
| `peashape` | Traffic shaping |
| `peaveil` | Privacy-oriented peer discovery |
| `peasub` | Metadata-private dissemination |
| `peaplex` | Optional stream multiplexing |
| `peaboard` | Reference application |

Each library does one thing well and composes naturally with the others.
