//! Live ASCII visualization of `peaveil`'s discovery loop.
//!
//! Builds a 20-node simulation, drives it forward tick by tick,
//! and redraws a colored ASCII dashboard each tick so you can
//! watch the view propagate across the ring: a bootstrap wave
//! in the first few ticks, then a slow churn of promotions and
//! evictions as random exploration kicks in.
//!
//! Run with: `cargo run --example discovery_viz`
//!
//! The whole thing is deterministic — the same seed produces
//! the same sequence of events. Hit Ctrl-C to exit early; the
//! terminal is restored on the way out (including on panic).

use std::io::Write;
use std::time::{Duration, Instant};

use peaveil::sim::{Simulation, sim_config};
use peaveil::{DiscoveryEvent, PeerCategory};
use tokio::sync::broadcast::error::TryRecvError;

// ---- knobs ----------------------------------------------------------------

const N_NODES: usize = 20;
const N_TICKS: u64 = 150; // ~15 s of simulated time at the default tick
const TICK_MS: u64 = 100;

// ---- ANSI -----------------------------------------------------------------

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GRN: &str = "\x1b[32m";
const YEL: &str = "\x1b[33m";
const MAG: &str = "\x1b[35m";
const CYN: &str = "\x1b[36m";
const HOME: &str = "\x1b[2J\x1b[H";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

// ---- event log ------------------------------------------------------------

const LOG_LINES: usize = 8;

struct EventLog {
    lines: Vec<String>,
}

impl EventLog {
    fn new() -> Self {
        Self {
            lines: Vec::with_capacity(LOG_LINES),
        }
    }
    fn push(&mut self, line: String) {
        self.lines.push(line);
        if self.lines.len() > LOG_LINES {
            self.lines.remove(0);
        }
    }
}

// ---- main -----------------------------------------------------------------

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Make sure the terminal is restored even if we panic.
    struct RestoreCursor;
    impl Drop for RestoreCursor {
        fn drop(&mut self) {
            print!("{RESET}{SHOW_CURSOR}");
            let _ = std::io::stdout().flush();
        }
    }
    let _restore = RestoreCursor;

    let sim = Simulation::new(N_NODES, 0xC0FFEE_C0FFEE, sim_config()).await;
    let bs = sim.addr(0);
    for i in 1..N_NODES {
        sim.node(i).add_bootstrap(bs);
    }
    sim.connect_ring().await;
    for i in 0..N_NODES {
        sim.node(i).add_recent(bs);
        let prev = sim.addr((i + N_NODES - 1) % N_NODES);
        let next = sim.addr((i + 1) % N_NODES);
        sim.node(i).add_recent(prev);
        sim.node(i).add_recent(next);
    }

    // Subscribe to every node's event channel so we can render
    // the most recent activity. Each subscriber sees only the
    // events fired after it subscribed, so we collect from t=0
    // by subscribing before the first step.
    let mut subs: Vec<tokio::sync::broadcast::Receiver<DiscoveryEvent>> = (0..N_NODES)
        .map(|i| sim.node(i).subscribe_events())
        .collect();

    let mut log = EventLog::new();
    let started = Instant::now();
    let addrs: Vec<std::net::SocketAddr> = (0..N_NODES).map(|i| sim.addr(i)).collect();

    // One-shot screen clear + hide cursor.
    print!("{HIDE_CURSOR}");
    let _ = std::io::stdout().flush();

    // Install a Ctrl-C handler so the terminal is restored on
    // early exit (SIGINT terminates without running Drop, so the
    // RestoreCursor guard alone isn't enough).
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    for tick in 0..N_TICKS {
        tokio::select! {
            _ = &mut ctrl_c => break,
            _ = sim.step(Duration::from_millis(TICK_MS)) => {}
        }

        // Drain each subscriber, log the most interesting events.
        for (i, rx) in subs.iter_mut().enumerate() {
            loop {
                match rx.try_recv() {
                    Ok(ev) => log.push(format_event(i, &ev, tick, &addrs)),
                    Err(TryRecvError::Lagged(n)) => {
                        log.push(format!("node {i:>2}  lagged {n} events"));
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Closed) => break,
                }
            }
        }

        // Render.
        let mut frame = String::with_capacity(4096);
        render(&mut frame, &sim, &log, tick, started.elapsed());
        print!("{HOME}{frame}");
        let _ = std::io::stdout().flush();
    }

    // Show the final state for a beat before exiting.
    std::thread::sleep(Duration::from_millis(500));
    // Tear down every node (pea2pea::Node holds an Arc cycle and
    // won't drop on its own — see pea2pea's AGENTS.md).
    sim.shutdown().await;
    // _restore drops at scope end, restoring the terminal.
    Ok(())
}

// ---- event formatting -----------------------------------------------------

fn format_event(
    i: usize,
    ev: &DiscoveryEvent,
    tick: u64,
    addrs: &[std::net::SocketAddr],
) -> String {
    let label = |addr: &std::net::SocketAddr| -> String {
        match addrs.iter().position(|a| a == addr) {
            Some(n) => format!("node {n:>2}"),
            None => format!("{:?}", addr.ip()),
        }
    };
    match ev {
        DiscoveryEvent::SampleSent { to: _, count } => format!(
            "t+{:>4}  node {:>2}  →  sample ({count})",
            tick_ms_label(tick),
            i
        ),
        DiscoveryEvent::SampleReceived { count, .. } => format!(
            "t+{:>4}  node {:>2}  ←  sample ({count})",
            tick_ms_label(tick),
            i
        ),
        DiscoveryEvent::PeerDiscovered { addr, category } => {
            let name = label(addr);
            let cat = cat_short(*category);
            format!(
                "t+{:>4}  node {:>2}  +  {name} ({cat})",
                tick_ms_label(tick),
                i
            )
        }
        DiscoveryEvent::PeerEvicted { addr } => {
            let name = label(addr);
            format!("t+{:>4}  node {:>2}  −  {name}", tick_ms_label(tick), i)
        }
        _ => String::new(),
    }
}

fn tick_ms_label(tick: u64) -> String {
    format!("{:.1}s", (tick + 1) as f64 * TICK_MS as f64 / 1000.0)
}

fn cat_short(c: PeerCategory) -> &'static str {
    match c {
        PeerCategory::Bootstrap => "Bootstrap",
        PeerCategory::Trusted => "Trusted",
        PeerCategory::Recent => "Recent",
        PeerCategory::Random => "Random",
        _ => "?",
    }
}

// ---- rendering ------------------------------------------------------------

fn render(out: &mut String, sim: &Simulation, log: &EventLog, tick: u64, elapsed: Duration) {
    // ---- top: header bar
    let m = sim.metrics();
    let header = format!(
        "{BOLD}peaveil — live discovery{RESET}        \
         t={tick:<3}   alive={alive:<2}   \
         avg_view={av:.1}   trusted={tr:.1}   recent={rc:.1}   random={rd:.1}   coverage={cov:.2}",
        tick = tick + 1,
        alive = m.alive,
        av = m.avg_view_size,
        tr = m.avg_trusted,
        rc = m.avg_recent,
        rd = m.avg_random,
        cov = m.coverage,
    );
    push_line(out, &header);
    push_line(
        out,
        &format!(
            "{DIM}seed 0xc0ffee_c0ffee   elapsed {:.1}s{RESET}",
            elapsed.as_secs_f64()
        ),
    );

    // ---- middle: the map
    push_line(out, "");
    draw_map(out, sim);
    push_line(out, "");

    // ---- view-strip: a 4xN grid of pool sizes per node
    draw_view_strip(out, sim);
    push_line(out, "");

    // ---- event log
    push_line(out, &format!("{BOLD}events (most recent last){RESET}"));
    for line in &log.lines {
        push_line(out, line);
    }
    push_line(out, "");
    push_line(
        out,
        &format!(
            "{DIM}legend: {BOLD}B{RESET}{DIM}=bootstrap {BOLD}T{RESET}{DIM}=trusted {BOLD}R{RESET}{DIM}=recent {BOLD}N{RESET}{DIM}=random{RESET}"
        ),
    );
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

/// Draw the 20 nodes positioned in a circle. Each node is a
/// single character (its index) and is colored by how many
/// *known* peers it currently has — red for lonely (0–1),
/// yellow for warming up (2–3), green for well-discovered (4+).
fn draw_map(out: &mut String, sim: &Simulation) {
    // Circle parameters (in terminal cells).
    let cx = 22.0_f64;
    let cy = 6.0_f64;
    let r = 5.0_f64;

    // Build a sparse char grid: the top-left is (0, 0) for
    // easy indexing; the cell at (col, row) maps to a 2D
    // position (col, row) on the screen.
    let cols = 45;
    let rows = 13;
    let mut grid: Vec<Vec<Option<(usize, char)>>> = vec![vec![None; cols]; rows];

    // Place every alive node at its (col, row) on the circle.
    for i in 0..sim.len() {
        let theta = (i as f64) * 2.0 * std::f64::consts::PI / (sim.len() as f64);
        let col = (cx + r * theta.cos()).round() as isize;
        let row = (cy + r * theta.sin()).round() as isize;
        if (0..cols as isize).contains(&col) && (0..rows as isize).contains(&row) {
            grid[row as usize][col as usize] = Some((i, node_letter(i)));
        }
    }

    for grid_row in grid.iter().take(rows) {
        let mut line = String::new();
        for cell in grid_row.iter().take(cols) {
            match cell {
                Some((i, ch)) => {
                    let snap = sim.node(*i).view();
                    let total = snap.total();
                    let color = match total {
                        0..=1 => RED,
                        2..=3 => YEL,
                        _ => GRN,
                    };
                    if *i == 0 {
                        // bootstrap node
                        line.push_str(&format!("{BOLD}{MAG}{ch}{RESET}"));
                    } else {
                        line.push_str(&format!("{color}{ch}{RESET}"));
                    }
                }
                None => line.push(' '),
            }
        }
        push_line(out, line.trim_end());
    }
}

fn node_letter(i: usize) -> char {
    if i < 26 {
        (b'A' + i as u8) as char
    } else {
        (b'0' + (i - 26) as u8) as char
    }
}

/// Four rows labelled `b/t/r/n` showing the count of known
/// peers in each pool, one column per node. A letter in the
/// cell is shown if the count is at least 1; the letter
/// corresponds to the pool (B/T/R/N). Empty cells are a dot.
fn draw_view_strip(out: &mut String, sim: &Simulation) {
    // Header: the node indices, right-padded to 2 chars + 1 space.
    // The 3-space prefix matches the data rows' `label + ": "` prefix.
    let mut header = String::from("   ");
    for i in 0..sim.len() {
        header.push_str(&format!("{:>2} ", i));
    }
    push_line(out, &header);

    let labels = [
        ('b', PeerCategory::Bootstrap),
        ('t', PeerCategory::Trusted),
        ('r', PeerCategory::Recent),
        ('n', PeerCategory::Random),
    ];
    for (label, cat) in labels {
        let mut row = String::new();
        row.push(label);
        row.push_str(": ");
        for i in 0..sim.len() {
            let snap = sim.node(i).view();
            let count = match cat {
                PeerCategory::Bootstrap => snap.bootstrap.len(),
                PeerCategory::Trusted => snap.trusted.len(),
                PeerCategory::Recent => snap.recent.len(),
                PeerCategory::Random => snap.random.len(),
                _ => 0,
            };
            if count == 0 {
                // 3 visible chars: dot + 2 spaces (matches header's 3-char columns)
                row.push_str(&format!("{DIM}·{RESET}  "));
            } else {
                let ch = match cat {
                    PeerCategory::Bootstrap => format!("{BOLD}{MAG}B{RESET}"),
                    PeerCategory::Trusted => format!("{GRN}T{RESET}"),
                    PeerCategory::Recent => format!("{YEL}R{RESET}"),
                    PeerCategory::Random => format!("{CYN}N{RESET}"),
                    _ => format!("{DIM}?{RESET}"),
                };
                row.push_str(&ch);
                row.push_str("  ");
            }
        }
        push_line(out, &row);
    }
}
