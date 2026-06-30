//! The minimal end-to-end usage pattern: two `peaveil`
//! nodes are wired up, each one learns about the other
//! through the probabilistic peer-sampling protocol, and
//! we print the resulting view of each.
//!
//! The `peaveil::Node` API is deliberately tiny: build a
//! node, optionally seed it with a few bootstrap addresses,
//! spawn it, and either connect to specific peers via
//! [`Node::connect`] or rely on the explorer to discover
//! them automatically. The view evolves on its own from
//! then on.
//!
//! Run with: cargo run --example two_nodes

use std::time::Duration;

use peaveil::{CoverStrategy, Node, NodeConfig};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║  peaveil — two-node peer-discovery demo                      ║");
    println!("╚═════════════════════════════════════════════════════════════╝");
    println!();
    println!("Two nodes (Alice, Bob) are wired up. They each connect");
    println!("directly to the other; the explorer continuously samples");
    println!("its view and merges incoming peer samples. After a few");
    println!("seconds both nodes should have the other in their view.\n");

    fn mk_node(name: &str) -> Result<Node, Box<dyn std::error::Error>> {
        Ok(Node::new(NodeConfig {
            name: Some(name.into()),
            listener_addr: Some("127.0.0.1:0".parse()?),
            cover: CoverStrategy::Constant {
                interval: Duration::from_millis(100),
            },
            ..Default::default()
        }))
    }

    let alice = mk_node("alice")?;
    let bob = mk_node("bob")?;
    alice.spawn().await?;
    bob.spawn().await?;

    let alice_addr = alice.local_addr().await?.expect("alice bound");
    let bob_addr = bob.local_addr().await?.expect("bob bound");
    println!("alice bound on {alice_addr}");
    println!("bob   bound on {bob_addr}");

    // Opening the connection is the application's job —
    // peaveil never dials. Once a link exists, the explorer
    // gossips over it automatically; we connect both ways here
    // so each side has the other as a gossip target. (Seeding
    // the view with `add_recent` first is optional — it just
    // lets a node mention the peer to others before it has
    // exchanged a sample with it directly.)
    alice.add_recent(bob_addr);
    bob.add_recent(alice_addr);
    alice.connect(bob_addr).await?;
    bob.connect(alice_addr).await?;

    // Subscribe to the discovery events of one side so we
    // can print every sample sent and received.
    let mut alice_events = alice.subscribe_events();

    let alice_events_task = tokio::spawn(async move {
        while let Ok(event) = alice_events.recv().await {
            match event {
                peaveil::DiscoveryEvent::SampleSent { to, count } => {
                    println!("alice -> {to}: sent sample ({count} entries)");
                }
                peaveil::DiscoveryEvent::SampleReceived { count, .. } => {
                    println!("alice <- ???: received sample ({count} entries)");
                }
                peaveil::DiscoveryEvent::PeerDiscovered { addr, category } => {
                    println!("alice discovered {addr} as {category:?}");
                }
                _ => {}
            }
        }
    });

    // Let the explorer run for a few seconds.
    tokio::time::sleep(Duration::from_secs(3)).await;
    alice_events_task.abort();

    println!();
    println!("=== Alice's view ===");
    let av = alice.view();
    print_view(&av);
    println!();
    println!("=== Bob's view ===");
    let bv = bob.view();
    print_view(&bv);

    alice.shutdown().await;
    bob.shutdown().await;
    Ok(())
}

fn print_view(view: &peaveil::ViewSnapshot) {
    let total = view.total();
    if total == 0 {
        println!("  (empty — only self-entry, no other peers known)");
        return;
    }
    for p in &view.trusted {
        println!(
            "  [trusted] {}:{}  (seen {} times, last seen {:?} ago)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
            p.last_seen
        );
    }
    for p in &view.recent {
        println!(
            "  [recent]  {}:{}  (seen {} times, last seen {:?} ago)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
            p.last_seen
        );
    }
    for p in &view.random {
        println!(
            "  [random]  {}:{}  (seen {} times, last seen {:?} ago)",
            p.addr.ip(),
            p.addr.port(),
            p.seen_count,
            p.last_seen
        );
    }
    for p in &view.bootstrap {
        println!(
            "  [boot]    {}:{}  (bootstrap, last seen {:?} ago)",
            p.addr.ip(),
            p.addr.port(),
            p.last_seen
        );
    }
}
