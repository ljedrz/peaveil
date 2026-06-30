//! Integration test for the encrypted handshake pattern.
//!
//! Mirrors the protocol used in `examples/encrypted.rs`:
//! two `peaveil` nodes register a `PskHandshake`
//! (pre-shared key + ChaCha20-Poly1305 stream wrap) and
//! verify that the explorer exchanges samples over the
//! encrypted link. This is a regression guard for the
//! wiring of [`peaveil::Handshake`] through
//! [`peaveil::Node::p2p`]: if the contract between
//! `peaveil` and `pea2pea` regresses, this test fails.
//!
//! The AEAD plumbing lives in `tests/common/mod.rs` so
//! additional integration tests can reuse it without
//! duplicating the wire codec. (`examples/encrypted.rs`
//! deliberately carries its own self-contained copy, since
//! an example should not depend on internal test
//! infrastructure.)

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use peaveil::{CoverStrategy, Handshake, Node, NodeConfig};

use common::PskHandshake;

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
async fn encrypted_handshake_lets_nodes_discover() {
    // Two `peaveil::Node`s wire up a pre-shared-key
    // `pea2pea` `Handshake` *before* `spawn`. Once
    // spawned, the listener on each side only admits
    // connections that complete the handshake; the AEAD
    // wrap then carries every peaveil frame, including
    // cover traffic.
    let alice = Node::with_seed(test_config("alice"), 0xA11CE);
    let bob = Node::with_seed(test_config("bob"), 0xB0B);

    for n in [&alice, &bob] {
        let hs = PskHandshake {
            inner: Arc::new(n.peashape().clone()),
        };
        hs.enable_handshake().await;
    }

    alice.spawn().await.unwrap();
    bob.spawn().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let bob_addr = bob.local_addr().await.unwrap().expect("bob bound");
    let alice_addr = alice.local_addr().await.unwrap().expect("alice bound");
    alice.add_recent(bob_addr);
    bob.add_recent(alice_addr);
    alice.connect(bob_addr).await.unwrap();
    assert!(wait_connected(&alice, bob_addr).await, "alice never connected to bob");

    // Wait up to 2 s for each side to learn about the
    // other through the encrypted link.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let alice_knows_bob = alice
            .view()
            .trusted
            .iter()
            .chain(alice.view().recent.iter())
            .chain(alice.view().random.iter())
            .any(|p| p.addr == bob_addr);
        let bob_knows_alice = bob
            .view()
            .trusted
            .iter()
            .chain(bob.view().recent.iter())
            .chain(bob.view().random.iter())
            .any(|p| p.addr == alice_addr);
        if alice_knows_bob && bob_knows_alice {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let av = alice.view();
    let bv = bob.view();
    assert!(
        av.trusted
            .iter()
            .chain(av.recent.iter())
            .chain(av.random.iter())
            .any(|p| p.addr == bob_addr),
        "alice never learned about bob over AEAD: {:?}",
        av
    );
    assert!(
        bv.trusted
            .iter()
            .chain(bv.recent.iter())
            .chain(bv.random.iter())
            .any(|p| p.addr == alice_addr),
        "bob never learned about alice over AEAD: {:?}",
        bv
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
