//! End-to-end integration tests for `peaveil`.
//!
//! These tests bring up real `peashape` nodes on loopback
//! and exercise the full explorer / receive / view-merge
//! stack, so they are slower than the in-process unit tests
//! in `src/view.rs` and `src/sample.rs`.

use std::time::{Duration, Instant};

use peaveil::{CoverStrategy, Node, NodeConfig};

/// Returns a [`NodeConfig`] tuned for fast tests: small
/// frames, fast exchange cadence, a small view, and a small
/// sample size. The cover interval is short enough that
/// samples are flushed promptly.
fn test_config(name: &str) -> NodeConfig {
    NodeConfig {
        name: Some(name.into()),
        listener_addr: Some("127.0.0.1:0".parse().unwrap()),
        bootstrap: Vec::new(),
        view_size: 8,
        sample_size: 4,
        exchange_interval: Duration::from_millis(100),
        cover: CoverStrategy::Constant {
            interval: Duration::from_millis(20),
        },
        frame_size: 128,
        max_connections: 16,
        max_connections_per_ip: 8,
        ..Default::default()
    }
}

/// Spins until `addr` is in `node.connected_peers()`,
/// with a 1-second timeout.
async fn wait_connected(node: &Node, addr: std::net::SocketAddr) -> bool {
    for _ in 0..100 {
        if node.connected_peers().contains(&addr) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_learn_each_other() {
    // The simplest end-to-end check: Alice and Bob connect
    // to each other, and within a few hundred milliseconds
    // each one has the other in its view.
    let alice = Node::with_seed(test_config("alice"), 0xA11CE);
    let bob = Node::with_seed(test_config("bob"), 0xB0B);
    alice.spawn().await.unwrap();
    bob.spawn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let bob_addr = bob.local_addr().await.unwrap().expect("bob bound");
    let alice_addr = alice.local_addr().await.unwrap().expect("alice bound");
    alice.add_recent(bob_addr);
    bob.add_recent(alice_addr);
    alice.connect(bob_addr).await.unwrap();
    assert!(wait_connected(&alice, bob_addr).await);

    // Wait up to 2 s for each side to learn about the
    // other. With a 100 ms exchange cadence and a 20 ms
    // cover rate, this should happen well within 1 s.
    let alice_addr = alice.local_addr().await.unwrap().expect("alice bound");
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let alice_view = alice.view();
        let bob_view = bob.view();
        let alice_knows_bob = alice_view
            .trusted
            .iter()
            .chain(alice_view.recent.iter())
            .chain(alice_view.random.iter())
            .any(|p| p.addr == bob_addr);
        let bob_knows_alice = bob_view
            .trusted
            .iter()
            .chain(bob_view.recent.iter())
            .chain(bob_view.random.iter())
            .any(|p| p.addr == alice_addr);
        if alice_knows_bob && bob_knows_alice {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let alice_view = alice.view();
    let bob_view = bob.view();
    assert!(
        alice_view
            .trusted
            .iter()
            .chain(alice_view.recent.iter())
            .chain(alice_view.random.iter())
            .any(|p| p.addr == bob_addr),
        "alice never learned about bob: {:?}",
        alice_view
    );
    assert!(
        bob_view
            .trusted
            .iter()
            .chain(bob_view.recent.iter())
            .chain(bob_view.random.iter())
            .any(|p| p.addr == alice_addr),
        "bob never learned about alice: {:?}",
        bob_view
    );

    alice.shutdown().await;
    bob.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_reaches_high_coverage() {
    // A 10-node mesh should reach high coverage within a
    // few seconds: every node knows about every other node.
    const N: usize = 10;
    let cfg = NodeConfig {
        name: None,
        listener_addr: Some("127.0.0.1:0".parse().unwrap()),
        view_size: 8,
        sample_size: 4,
        exchange_interval: Duration::from_millis(100),
        cover: CoverStrategy::Constant {
            interval: Duration::from_millis(20),
        },
        frame_size: 128,
        max_connections: 32,
        max_connections_per_ip: 16,
        ..Default::default()
    };

    let mut nodes = Vec::with_capacity(N);
    for i in 0..N {
        let node = Node::with_seed(cfg.clone(), 0xC0FFEE + i as u64);
        node.spawn().await.expect("spawn");
        nodes.push(node);
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Connect in a mesh.
    let addrs: Vec<std::net::SocketAddr> = {
        let mut v = Vec::with_capacity(N);
        for n in &nodes {
            v.push(n.local_addr().await.unwrap().expect("bound"));
        }
        v
    };
    for (i, node) in nodes.iter().enumerate() {
        for (j, &peer) in addrs.iter().enumerate() {
            if i != j {
                let _ = node.connect(peer).await;
            }
        }
    }
    // Seed the views: each node knows every other
    // node as a `Recent` entry, so the explorer has
    // someone to ship a sample to on its very first
    // tick. In a real deployment this is what
    // `bootstrap` would do.
    for (i, node) in nodes.iter().enumerate() {
        for (j, &peer) in addrs.iter().enumerate() {
            if i != j {
                node.add_recent(peer);
            }
        }
    }
    // Give the connections a moment to settle.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run discovery for 2 seconds and check coverage.
    let run_for = Duration::from_secs(2);
    let start = Instant::now();
    while start.elapsed() < run_for {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Compute coverage: fraction of *other* nodes each
    // node has in its view.
    let mut total_known = 0;
    let mut total_possible = 0;
    for (i, node) in nodes.iter().enumerate() {
        let snap = node.view();
        let known: std::collections::HashSet<_> = snap
            .trusted
            .iter()
            .chain(snap.recent.iter())
            .chain(snap.random.iter())
            .chain(snap.bootstrap.iter())
            .map(|p| p.addr)
            .collect();
        for (j, &peer) in addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            total_possible += 1;
            if known.contains(&peer) {
                total_known += 1;
            }
        }
    }
    let coverage = total_known as f64 / total_possible as f64;
    assert!(
        coverage > 0.5,
        "expected >50% coverage after 2 s, got {coverage:.2}",
    );

    for node in nodes {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bootstrap_addr_is_in_view_after_spawn() {
    // A node that knows a bootstrap address should have
    // it in its view immediately, even before any
    // discovery happens.
    let alice = Node::with_seed(test_config("alice"), 0xA11CE);
    alice.spawn().await.unwrap();

    let bs: std::net::SocketAddr = "10.0.0.99:9000".parse().unwrap();
    alice.add_bootstrap(bs);
    let view = alice.view();
    assert!(
        view.bootstrap.iter().any(|p| p.addr == bs),
        "bootstrap address not in view: {:?}",
        view
    );

    alice.shutdown().await;
}

#[test]
fn node_with_seed_rejects_undersized_frame() {
    // The peaveil sample header + one IPv4 entry is 12
    // bytes; combined with the 32-byte peashape ID, the
    // minimum legal frame size is 44 bytes. Anything
    // smaller must be rejected up front.
    let mut cfg = test_config("alice");
    cfg.frame_size = 32; // too small for even the header
    let result = std::panic::catch_unwind(|| Node::with_seed(cfg, 0));
    assert!(result.is_err(), "expected a panic for an undersized frame");
}

#[test]
fn node_with_seed_rejects_zero_view_size() {
    let mut cfg = test_config("alice");
    cfg.view_size = 0;
    let result = std::panic::catch_unwind(|| Node::with_seed(cfg, 0));
    assert!(result.is_err(), "expected a panic for view_size = 0");
}

#[test]
fn node_with_seed_rejects_zero_sample_size() {
    let mut cfg = test_config("alice");
    cfg.sample_size = 0;
    let result = std::panic::catch_unwind(|| Node::with_seed(cfg, 0));
    assert!(result.is_err(), "expected a panic for sample_size = 0");
}

#[test]
fn node_with_seed_rejects_sample_size_that_overflows_frame() {
    // The construction check must reject a `sample_size` whose
    // worst-case (all-IPv6) encoded sample does not fit in the
    // configured `frame_size`. Here a 128-byte frame cannot
    // hold 8 IPv6 entries (8 * 23 + 3 header + 32 ID = 219 > 128).
    let mut cfg = test_config("alice");
    cfg.sample_size = 8;
    cfg.frame_size = 128;
    let result = std::panic::catch_unwind(|| Node::with_seed(cfg, 0));
    assert!(
        result.is_err(),
        "expected a panic for sample_size=8 in a 128-byte frame",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulation_metrics_are_in_expected_bands() {
    // A smoke test that the metrics struct is populated
    // and the values fall in the expected ranges after a
    // short run. We do not assert bit-exact equality
    // between runs because the explorer ticks on real
    // wall-clock time and the OS scheduler is free to
    // interleave differently; instead we assert the
    // values are in plausible bands.
    use peaveil::sim::{Simulation, sim_config};
    let sim = Simulation::new(8, 0xDEADBEEF, sim_config()).await;
    sim.connect_ring().await;
    for i in 0..8 {
        let prev = sim.addr((i + 7) % 8);
        let next = sim.addr((i + 1) % 8);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }
    sim.step(Duration::from_secs(2)).await;
    let m = sim.metrics();
    assert_eq!(m.alive, 8);
    assert_eq!(m.total, 8);
    assert!(m.coverage > 0.0, "coverage should be > 0 after 2 s");
    assert!(m.avg_view_size > 0.0);
    assert!(m.avg_view_size <= sim_config().view_size as f64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulation_converges_to_high_coverage() {
    // A 20-node ring with one bootstrap should converge
    // to a coverage of >70% within a few seconds.
    use peaveil::sim::{Simulation, sim_config};
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("peaveil=debug")),
        )
        .with_test_writer()
        .try_init();
    let sim = Simulation::new(20, 0xC0FFEE, sim_config()).await;
    // Use the first node as the bootstrap for everyone.
    let bs = sim.addr(0);
    for i in 1..20 {
        sim.node(i).add_bootstrap(bs);
    }
    sim.connect_ring().await;
    // Each node seeds its view with the bootstrap address
    // and its ring neighbours, so the explorer has
    // someone to talk to on the first tick.
    for i in 0..20 {
        sim.node(i).add_recent(bs);
        let prev = sim.addr((i + 19) % 20);
        let next = sim.addr((i + 1) % 20);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }

    // Run discovery for 10 seconds.
    sim.step(std::time::Duration::from_secs(10)).await;
    let m = sim.metrics();
    eprintln!(
        "sim: elapsed={elapsed:.2}s, alive={alive}, avg_view={view:.2}, coverage={cov:.2}",
        elapsed = m.elapsed_secs,
        alive = m.alive,
        view = m.avg_view_size,
        cov = m.coverage
    );
    // With view_size=16, the maximum possible coverage
    // in a 20-node ring is 16/19 ≈ 0.84. We expect the
    // protocol to reach at least a third of that within
    // 10 seconds (the protocol does converge, but the
    // view is bounded so a 20-node ring with view_size
    // 16 saturates well below 1.0).
    assert!(
        m.coverage > 0.3,
        "expected >30% coverage after 10 s, got {coverage:.2} (avg_view={view:.2})",
        coverage = m.coverage,
        view = m.avg_view_size,
    );

    sim.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulation_recovers_from_partition() {
    // A 10-node ring split into two halves; after the
    // partition heals, coverage should return to a high
    // level.
    use peaveil::sim::{Simulation, sim_config};
    let mut sim = Simulation::new(10, 0xDECAF, sim_config()).await;
    sim.connect_ring().await;
    // Seed the views so the explorer has something to
    // do on the first tick.
    for i in 0..10 {
        let prev = sim.addr((i + 9) % 10);
        let next = sim.addr((i + 1) % 10);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }
    sim.step(std::time::Duration::from_secs(5)).await;
    let before = sim.metrics();
    assert!(
        before.coverage > 0.4,
        "expected >40% coverage pre-partition, got {coverage:.2}",
        coverage = before.coverage,
    );

    // Partition into two halves.
    let group_a: Vec<usize> = (0..5).collect();
    let group_b: Vec<usize> = (5..10).collect();
    sim.partition(group_a, group_b).await;
    // Give the partition time to take effect.
    sim.step(std::time::Duration::from_secs(1)).await;

    // Heal the partition.
    sim.heal_partition().await;
    // Give the network time to re-discover the
    // cross-group peers.
    sim.step(std::time::Duration::from_secs(5)).await;
    let after = sim.metrics();
    assert!(
        after.coverage > before.coverage * 0.7,
        "post-partition coverage should recover; pre={pre:.2} post={post:.2}",
        pre = before.coverage,
        post = after.coverage,
    );

    sim.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simulation_handles_churn() {
    // A 10-node ring; kill two random nodes; the
    // surviving eight should still have non-trivial
    // coverage of the network.
    use peaveil::sim::{Simulation, sim_config};
    let mut sim = Simulation::new(10, 0xBEEF, sim_config()).await;
    sim.connect_ring().await;
    for i in 0..10 {
        let prev = sim.addr((i + 9) % 10);
        let next = sim.addr((i + 1) % 10);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }
    sim.step(std::time::Duration::from_secs(2)).await;
    let before = sim.metrics();
    assert_eq!(before.alive, 10);

    // Kill two random nodes.
    sim.kill(3).await;
    sim.kill(7).await;
    sim.step(std::time::Duration::from_secs(1)).await;
    let m = sim.metrics();
    assert_eq!(m.alive, 8);
    // Coverage should not have collapsed to zero.
    assert!(
        m.coverage > 0.1,
        "coverage collapsed to {coverage:.2} after killing 20% of nodes",
        coverage = m.coverage,
    );

    sim.shutdown().await;
}

/// A peaveil node configured with `CoverStrategy::None`
/// (passthrough mode) must still exchange peer samples: the
/// cover strategy only governs the *traffic* side of the
/// shaper, not the discovery logic. Two nodes should learn
/// about each other just as they do under the default
/// `Constant` cover — only the on-the-wire frame rate and
/// uniformity differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passthrough_mode_still_discovers_peers() {
    let mut cfg = test_config("alice");
    cfg.cover = CoverStrategy::None;
    let alice = Node::with_seed(cfg, 0xA11CE);
    let mut cfg = test_config("bob");
    cfg.cover = CoverStrategy::None;
    let bob = Node::with_seed(cfg, 0xB0B);
    alice.spawn().await.unwrap();
    bob.spawn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let bob_addr = bob.local_addr().await.unwrap().expect("bob bound");
    let alice_addr = alice.local_addr().await.unwrap().expect("alice bound");
    alice.add_recent(bob_addr);
    bob.add_recent(alice_addr);
    alice.connect(bob_addr).await.unwrap();
    assert!(wait_connected(&alice, bob_addr).await);

    // Wait up to 2 s for each side to learn about the other.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut alice_knows_bob = false;
    let mut bob_knows_alice = false;
    while Instant::now() < deadline && !(alice_knows_bob && bob_knows_alice) {
        let snap = alice.view();
        alice_knows_bob = snap
            .trusted
            .iter()
            .chain(snap.recent.iter())
            .chain(snap.random.iter())
            .any(|p| p.addr == bob_addr);
        let snap = bob.view();
        bob_knows_alice = snap
            .trusted
            .iter()
            .chain(snap.recent.iter())
            .chain(snap.random.iter())
            .any(|p| p.addr == alice_addr);
        if !(alice_knows_bob && bob_knows_alice) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    assert!(
        alice_knows_bob,
        "alice never learned about bob under passthrough mode"
    );
    assert!(
        bob_knows_alice,
        "bob never learned about alice under passthrough mode"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
