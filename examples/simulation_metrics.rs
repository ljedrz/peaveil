//! Demonstrates the measurement harness: a 20-node ring
//! is brought up, run for a few seconds, and the
//! `Simulation::metrics` snapshot is printed at several
//! checkpoints. The metrics are: coverage (fraction of
//! alive nodes known by an average node), view-size
//! distribution, sample counts, and so on.
//!
//! This is the kind of experiment you would run to
//! validate a deployment: given a configuration, what
//! coverage do you get after how long, and how does it
//! evolve under churn or partition?
//!
//! Run with: cargo run --example simulation_metrics

use std::time::Duration;

use peaveil::sim::{Simulation, sim_config};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═════════════════════════════════════════════════════════════╗");
    println!("║  peaveil — local simulation metrics                         ║");
    println!("╚═════════════════════════════════════════════════════════════╝");
    println!();
    println!("Building a 20-node ring with one bootstrap and running");
    println!("discovery. Metrics are sampled every second and printed");
    println!("at the end. All randomness is seeded from a single");
    println!("value, so the run is fully reproducible.\n");

    let mut sim = Simulation::new(20, 0xC0FFEE_C0FFEE, sim_config()).await;

    // Use node 0 as the bootstrap for everyone else.
    let bs = sim.addr(0);
    for i in 1..20 {
        sim.node(i).add_bootstrap(bs);
    }
    sim.connect_ring().await;

    // Each node seeds its view with the bootstrap and its
    // ring neighbors, so the explorer has something to do
    // on the first tick. In a real deployment this is what
    // a hardcoded bootstrap list would do.
    for i in 0..20 {
        sim.node(i).add_recent(bs);
        let prev = sim.addr((i + 19) % 20);
        let next = sim.addr((i + 1) % 20);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }

    println!(
        "{:<8}  {:<5}  {:<10}  {:<10}  {:<10}  {:<10}  {:<10}",
        "t (s)", "alive", "avg_view", "trusted", "recent", "random", "coverage"
    );
    println!("{}", "-".repeat(72));

    let start = std::time::Instant::now();
    for tick in 1..=10 {
        sim.step(Duration::from_secs(1)).await;
        let m = sim.metrics();
        println!(
            "{:<8}  {:<5}  {:<10.2}  {:<10.2}  {:<10.2}  {:<10.2}  {:<10.2}",
            tick, m.alive, m.avg_view_size, m.avg_trusted, m.avg_recent, m.avg_random, m.coverage,
        );
    }
    println!();
    println!("Total wall-clock: {:?}", start.elapsed());

    // Demonstrate partition recovery: split the network in
    // half, watch the views diverge, then heal.
    println!();
    println!("Now: partition into two halves, wait, then heal.");
    sim.partition((0..10).collect(), (10..20).collect()).await;
    sim.step(Duration::from_secs(2)).await;
    let m_partitioned = sim.metrics();
    println!(
        "post-partition: coverage = {:.2}, avg_view = {:.2}",
        m_partitioned.coverage, m_partitioned.avg_view_size
    );

    sim.heal_partition().await;
    sim.step(Duration::from_secs(3)).await;
    let m_healed = sim.metrics();
    println!(
        "post-heal:     coverage = {:.2}, avg_view = {:.2}",
        m_healed.coverage, m_healed.avg_view_size
    );

    sim.shutdown().await;
    Ok(())
}
