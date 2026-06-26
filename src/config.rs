//! Configuration types for a [`Node`].
//!
//! [`Node`]: crate::Node

use std::net::SocketAddr;
use std::time::Duration;

use peashape::ShapingStrategy;

/// How the node generates outbound traffic on top of `peashape`.
///
/// `peaveil` reuses `peashape`'s shaping primitive: every
/// outbound frame is constant-sized and emitted at a constant
/// (or Poisson-distributed) rate. The metadata-privacy property
/// `peashape` provides is the basis for the privacy claims of
/// `peaveil` — without it, an observer could distinguish a node
/// that is exchanging peer samples from a node that is idle
/// just by watching the wire.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum CoverStrategy {
    /// One frame per fixed `interval`.
    Constant {
        /// The fixed delay between consecutive cover frames.
        interval: Duration,
    },

    /// Inter-arrival times drawn from `Exp(rate)`, i.e. a
    /// Poisson process of rate `rate` frames per second.
    Poisson {
        /// The Poisson-process rate, in frames per second.
        rate: f64,
    },
}

impl CoverStrategy {
    pub(crate) fn as_shaping(&self) -> ShapingStrategy {
        match *self {
            CoverStrategy::Constant { interval } => ShapingStrategy::Constant { interval },
            CoverStrategy::Poisson { rate } => ShapingStrategy::Poisson { rate },
        }
    }
}

/// The set of parameters that govern a [`Node`].
///
/// Most callers only need to set [`NodeConfig::bootstrap`]; every
/// other field has a sensible default. To see what the defaults
/// are, use [`NodeConfig::default`] and read the resulting
/// struct.
///
/// Internally a `NodeConfig` is translated into a
/// [`peashape::ShapeConfig`] (for the wire-level shaping) plus a
/// `peaveil`-specific block (for the view, exchange cadence, and
/// sample size).
///
/// [`Node`]: crate::Node
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// A friendly identifier of the node, surfaced in `tracing`
    /// output. If `None`, `pea2pea` assigns a numeric ID.
    pub name: Option<String>,

    /// The local socket address to bind the listener to. If
    /// `None`, the node will not accept inbound connections (it
    /// can still initiate outbound ones via [`Node::connect`]).
    ///
    /// [`Node::connect`]: crate::Node::connect
    pub listener_addr: Option<SocketAddr>,

    /// A set of well-known addresses seeded into the view as
    /// entry points.
    ///
    /// These occupy a dedicated, sticky [`Bootstrap`] category
    /// in the [`View`](crate::ViewSnapshot): they are never aged
    /// out and do not count against `view_size`, so the node
    /// always remembers where to re-enter the network. They are
    /// the only peers known before the first sample is received.
    ///
    /// `peaveil` does **not** dial these itself — opening
    /// connections is the application's responsibility (see the
    /// crate-level "who connects" note). Read them back via
    /// [`Node::view`] and dial whichever you choose with
    /// [`Node::connect`]; once connected, `peaveil` gossips over
    /// the link like any other.
    ///
    /// [`Bootstrap`]: crate::PeerCategory::Bootstrap
    /// [`Node::connect`]: crate::Node::connect
    /// [`Node::view`]: crate::Node::view
    pub bootstrap: Vec<SocketAddr>,

    /// The maximum number of peers the node keeps in its
    /// [`View`](crate::ViewSnapshot) at any time.
    ///
    /// `peaveil` deliberately caps the view: a *small*,
    /// *continuously refreshed* view is the whole point of
    /// probabilistic peer sampling. A view of 16–32 entries is
    /// enough for `O(log N)` connectivity in a healthy overlay
    /// and is what the defaults are tuned for.
    pub view_size: usize,

    /// The number of peers encoded in a single sample frame.
    ///
    /// Smaller samples mean cheaper exchanges (less bandwidth
    /// per tick) and weaker per-exchange mixing; larger samples
    /// do the opposite. With the default `frame_size` of 256
    /// bytes and a 32-byte ID prefix, the payload can hold up to
    /// ~24 IPv4 peers or ~10 IPv6 peers per sample.
    pub sample_size: usize,

    /// How often the explorer initiates a sample exchange.
    ///
    /// This is the *application-level* cadence. The on-the-wire
    /// cadence is governed by `cover` (via `peashape`); the
    /// explorer merely decides *what* to put in the next
    /// available cover slot.
    pub exchange_interval: Duration,

    /// The on-the-wire schedule (constant or Poisson). This is
    /// the central knob controlling the metadata-privacy
    /// properties of the node.
    pub cover: CoverStrategy,

    /// The on-the-wire size, in bytes, of every `peaveil`
    /// frame.
    ///
    /// All frames (real and cover) are padded to exactly this
    /// size, so an observer cannot distinguish them by length.
    /// Must be large enough to fit `sample_size` peers after the
    /// `peaveil` framing and the 32-byte peashape ID prefix.
    pub frame_size: usize,

    /// Upper bound, in bytes, on a single frame the decoder
    /// will accept.
    pub max_frame_size: usize,

    /// Maximum number of simultaneously-active connections.
    pub max_connections: u16,

    /// Maximum number of connections to a single IP address.
    /// The `pea2pea` default of `1` is too restrictive for
    /// typical tests, so this defaults to `8`.
    pub max_connections_per_ip: u16,

    /// Whether to set `SO_REUSEPORT` on the listener socket.
    pub reuse_listener_port: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            name: None,
            listener_addr: None,
            bootstrap: Vec::new(),
            // 24 entries: a comfortable default for O(log N) PPS
            // overlays up to a few hundred nodes without too much
            // churn pressure on the eviction policy.
            view_size: 24,
            // 8 peers per sample fits comfortably in a 256-byte
            // frame; it is also a good "Cyclon"-style default
            // that mixes aggressively without flooding.
            sample_size: 8,
            // 500 ms: a fresh sample goes out twice per second.
            // For a 24-entry view and 8-peer samples this is
            // roughly 16 view-entries exchanged per second per
            // node, which keeps the overlay well-mixed under
            // typical conditions.
            exchange_interval: Duration::from_millis(500),
            // 100 ms constant cover rate: 10 frames/s out, so
            // peaveil's discovery traffic occupies a small,
            // steady fraction of the cover budget.
            cover: CoverStrategy::Constant {
                interval: Duration::from_millis(100),
            },
            // 256 bytes = 32-byte ID + 224-byte payload,
            // which holds up to 24 IPv4 peers per sample.
            frame_size: 256,
            max_frame_size: 1024 * 1024,
            max_connections: 64,
            max_connections_per_ip: 8,
            reuse_listener_port: false,
        }
    }
}
