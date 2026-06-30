//! The [`Node`] type — the public entry point to `peaveil`.
//!
//! A `Node` is a thin wrapper around a [`peashape::Node`]
//! that adds the discovery-specific state: the local
//! [`ViewSnapshot`](crate::view::ViewSnapshot), the
//! background explorer task, and a `tokio::sync::broadcast`
//! channel of [`DiscoveryEvent`]s.
//!
//! `Node` is cheap to `clone`: clones share the same view,
//! the same peashape shaper, and the same explorer task.
//! This is the same pattern used by `peashape` and `peasub`.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast};
use tracing::Span;

use crate::config::NodeConfig;
use crate::events::Events;
use crate::explorer::Explorer;
use crate::view::{View, ViewConfig};

/// Default capacity of the broadcast channel of
/// [`DiscoveryEvent`]s. Late subscribers see only events fired
/// after they subscribed.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// An observable event in the local discovery loop. Fired by
/// the explorer and by the peaveil receive task; observed by
/// callers of [`Node::subscribe_events`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum DiscoveryEvent {
    /// A peer sample was sent to a specific peer.
    SampleSent {
        /// The destination peer.
        to: SocketAddr,
        /// The number of entries in the sample.
        count: usize,
    },
    /// A peer sample was received. The `from` field is
    /// reported as the unspecified address `0.0.0.0:0`
    /// because the peashape broadcast strips the source;
    /// the stochastic exchange model does not need it.
    SampleReceived {
        /// Placeholder; see the type-level docs.
        from: SocketAddr,
        /// The number of entries in the sample.
        count: usize,
    },
    /// A new peer has been added to the local view, learned
    /// from a received sample.
    PeerDiscovered {
        /// The peer's address.
        addr: SocketAddr,
        /// The pool it landed in.
        category: crate::view::PeerCategory,
    },
    /// A peer was evicted from the local view (aged out of the
    /// `Recent`/`Random` pool, or trimmed to keep the view
    /// within its capacity).
    PeerEvicted {
        /// The peer's address.
        addr: SocketAddr,
    },
}

/// The shared, node-wide state that backs every clone of a
/// [`Node`].
pub(crate) struct NodeInner {
    /// The configuration the node was built from.
    pub(crate) config: NodeConfig,
    /// The peashape node that owns the wire-level state
    /// (lanes, scheduler, connection set, codec).
    pub(crate) peashape: peashape::Node,
    /// The local view. Always present; the self-entry is
    /// inserted on construction.
    pub(crate) view: Mutex<View>,
    /// The background explorer task.
    ///
    /// Stored behind an `OnceLock` to break a chicken-and-egg
    /// cycle: the explorer holds an `Arc<NodeInner>` to access
    /// the view, the lanes, and the events channel; the
    /// `NodeInner` owns the explorer. The lock is filled once,
    /// immediately after `NodeInner` is constructed, before
    /// any clone of the `Node` is observable.
    pub(crate) explorer: std::sync::OnceLock<Explorer>,
    /// Discovery events. The receiver side is exposed by
    /// [`Node::subscribe_events`].
    pub(crate) events: Events,
    /// Set to true by `Node::shutdown`. The explorer polls
    /// this on every tick to break out of its loop.
    pub(crate) shutting_down: AtomicBool,
    /// Fires when shutdown has been requested. Used by
    /// background helpers that want to wake up immediately
    /// rather than waiting for a tick.
    pub(crate) shutdown_waiter: Notify,
    /// The tracing span of this node. Used by the explorer
    /// to attach its debug logs.
    pub(crate) span: Span,
    /// Handle to the peaveil receive task. Aborted on
    /// shutdown.
    pub(crate) receive_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl NodeInner {
    /// Returns a `recent_window` derived from the
    /// configuration: the number of recently-contacted peers
    /// the explorer remembers for ping-pong avoidance.
    /// Defaults to `min(view_size / 2, 4)`.
    pub fn recent_window(&self) -> usize {
        (self.config.view_size / 2).clamp(1, 4)
    }
}

/// A single peer in a `peaveil` network.
#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<NodeInner>,
}

impl Node {
    /// Constructs a new, unstarted `Node` with a
    /// deterministic seed (`0`). Call [`Node::spawn`] to
    /// enable the `pea2pea` protocols, bring up the
    /// listener, launch the peashape shaping scheduler, and
    /// start the explorer.
    ///
    /// `Node::new` is deterministic: two nodes built with
    /// the same configuration have identical exploration
    /// orders. For production deployments where you want
    /// each node to behave differently, use
    /// [`Node::with_seed`] with a random seed (e.g.
    /// `rand::random()`).
    ///
    /// # Panics
    ///
    /// Panics if the configuration is internally inconsistent
    /// (see [`peashape::ShapeConfig`] for the full list). In
    /// addition, `view_size > 0`, `sample_size > 0`, and the
    /// configured `frame_size` must be large enough to hold
    /// `sample_size` IPv4 peers after the peaveil framing and
    /// the 32-byte peashape ID prefix.
    pub fn new(config: NodeConfig) -> Self {
        Self::with_seed(config, 0)
    }

    /// Same as [`Node::new`], but with a deterministic seed
    /// for the explorer's RNG. Use this for reproducible
    /// simulations.
    pub fn with_seed(config: NodeConfig, seed: u64) -> Self {
        // Validate that the frame is large enough to hold
        // the peaveil header plus at least one IPv4 peer.
        // Without this, the explorer would silently fail to
        // ship any sample because the encoded payload is
        // larger than the configured frame size.
        let min_frame =
            peashape::ID_SIZE + crate::sample::SAMPLE_HEADER_SIZE + crate::sample::IPV4_ENTRY_SIZE;
        assert!(
            config.frame_size >= min_frame,
            "frame_size ({fs} bytes) is too small: a peaveil frame needs at least \
             {min} bytes (peashape ID ({id}) + sample header ({hdr}) + one IPv4 entry ({e}))",
            fs = config.frame_size,
            min = min_frame,
            id = peashape::ID_SIZE,
            hdr = crate::sample::SAMPLE_HEADER_SIZE,
            e = crate::sample::IPV4_ENTRY_SIZE,
        );
        assert!(config.view_size > 0, "view_size must be non-zero");
        assert!(config.sample_size > 0, "sample_size must be non-zero");

        // Worst-case payload for a single sample: every entry
        // is IPv6 (the largest entry). If the configured
        // `frame_size` cannot hold the peashape ID prefix plus
        // this worst-case payload, the explorer would later be
        // unable to ship a full sample and the constant-size
        // frame property (central to the privacy claim) would
        // silently break. Reject this up front so the caller
        // gets a clear panic at construction rather than a
        // runtime `Error::SampleTooLarge` on every tick.
        let worst_case_payload =
            crate::sample::SAMPLE_HEADER_SIZE + config.sample_size * crate::sample::IPV6_ENTRY_SIZE;
        assert!(
            peashape::ID_SIZE + worst_case_payload <= config.frame_size,
            "frame_size ({fs} bytes) is too small for sample_size={ss}: \
             a worst-case (all-IPv6) sample needs at least {need} bytes \
             (peashape ID ({id}) + sample header ({hdr}) + {ss} x IPv6 entry ({e}))",
            fs = config.frame_size,
            ss = config.sample_size,
            need = peashape::ID_SIZE + worst_case_payload,
            id = peashape::ID_SIZE,
            hdr = crate::sample::SAMPLE_HEADER_SIZE,
            e = crate::sample::IPV6_ENTRY_SIZE,
        );

        // We need a `self_addr` to build the view, but the
        // actual bound listener address is only known
        // after `spawn`. We use a placeholder; `spawn`
        // patches it.
        let placeholder: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let peashape_node = peashape::Node::new(crate::config_bridge::config_to_shape(&config));
        let view = View::new(
            ViewConfig {
                max_non_bootstrap: config.view_size,
                ..ViewConfig::default()
            },
            placeholder,
            seed,
        );
        let span = tracing::info_span!("peaveil", name = config.name.as_deref().unwrap_or("?"));

        // The explorer holds an `Arc<NodeInner>` for
        // background access, but `NodeInner` owns the
        // explorer. The `OnceLock` breaks the cycle: we
        // build the inner with an empty lock, then install
        // the explorer with a back-reference. The lock is
        // filled exactly once, before any clone of `Node`
        // is observable.
        let inner = Arc::new(NodeInner {
            config: config.clone(),
            peashape: peashape_node,
            view: Mutex::new(view),
            explorer: std::sync::OnceLock::new(),
            events: Events::new(),
            shutting_down: AtomicBool::new(false),
            shutdown_waiter: Notify::new(),
            span,
            receive_handle: Mutex::new(None),
        });
        inner
            .explorer
            .set(Explorer::new(inner.clone(), seed))
            .ok()
            .expect("OnceLock::set called exactly once");
        Self { inner }
    }

    /// Starts the node.
    ///
    /// Spawns the underlying `peashape` node (which enables
    /// the `pea2pea` protocols, brings up the listener, and
    /// starts the cover-traffic scheduler), patches the view
    /// with the bound listener address, registers the
    /// peaveil receive task, and starts the explorer.
    pub async fn spawn(&self) -> io::Result<Option<SocketAddr>> {
        let addr = self.inner.peashape.spawn().await?;
        let self_addr = addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        // Patch the view with the actual self_addr. The
        // view's `addrs` set and the self-entry's
        // `last_seen` are updated together; the old
        // placeholder is removed so callers that look the
        // self-address up via `Node::is_known` get the
        // post-bind address immediately.
        self.inner
            .view
            .lock()
            .set_self_addr(self_addr, Instant::now());

        // Re-insert bootstrap addresses into the view now
        // that we have a real listener.
        let bootstrap = self.inner.config.bootstrap.clone();
        if !bootstrap.is_empty() {
            self.inner.view.lock().add_bootstrap(bootstrap);
        }

        // Start the peaveil receive task.
        self.spawn_receive_task();

        // Start the explorer.
        self.inner
            .explorer
            .get()
            .expect("explorer initialized")
            .spawn();

        Ok(addr)
    }

    /// Returns the local socket address this node is
    /// listening on, or `None` if no listener was configured.
    pub async fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        let a = self.inner.peashape.local_addr().await?;
        Ok(Some(a))
    }

    /// Returns the addresses of currently-connected peers.
    pub fn connected_peers(&self) -> Vec<SocketAddr> {
        self.inner.peashape.connected_peers()
    }

    /// Initiates an outbound connection to a peer. If the
    /// node is already connected, the call succeeds without
    /// taking further action.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.inner.peashape.connect(addr).await
    }

    /// Closes the connection to a peer, if one is currently
    /// open. Returns `true` if a connection was actually torn
    /// down.
    pub async fn disconnect(&self, addr: SocketAddr) -> bool {
        self.inner.peashape.disconnect(addr).await
    }

    /// Returns a point-in-time snapshot of the local view.
    pub fn view(&self) -> crate::view::ViewSnapshot {
        self.inner.view.lock().snapshot()
    }

    /// Seeds an address into the sticky bootstrap pool — a
    /// known entry point the node never ages out. `peaveil`
    /// does not dial it; the application connects to entry
    /// points it chooses via [`Node::connect`].
    pub fn add_bootstrap(&self, addr: SocketAddr) {
        self.inner.view.lock().add_bootstrap([addr]);
    }

    /// Seeds an address into the recent (transient) pool — the
    /// "I know this peer exists" hint, used for addresses
    /// learned out-of-band. Unlike the bootstrap pool, recent
    /// entries age out if they are never refreshed by a sample.
    ///
    /// This is purely a view seed: `peaveil` gossips over the
    /// connections the application has opened, so it is not
    /// required before [`Node::connect`] — but seeding a peer
    /// here lets the node tell others about it before it has
    /// exchanged a sample with it directly.
    ///
    /// [`Node::connect`]: crate::Node::connect
    pub fn add_recent(&self, addr: SocketAddr) {
        self.inner.view.lock().add_recent([addr]);
    }

    /// Returns true if `addr` is in the local view
    /// (including the self-entry and bootstrap entries).
    pub fn is_known(&self, addr: &SocketAddr) -> bool {
        self.inner.view.lock().contains(addr)
    }

    /// Drops the entry for `addr` from the local view, if
    /// it is a non-bootstrap, non-self entry. The
    /// reclassification pass would evict the entry anyway
    /// after `trusted_max_age` / `recent_max_age` /
    /// `random_max_age`, but this method gives the caller
    /// immediate eviction (e.g. when a peer's connection
    /// has been observed to fail) and is the right knob
    /// for simulation harnesses that need to forget a
    /// killed node from every other node's view.
    pub fn drop_peer(&self, addr: &SocketAddr) {
        self.inner.view.lock().drop_entry(addr);
    }

    /// Returns a sorted, deduplicated list of all
    /// non-self addresses currently in the view.
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        let snap = self.inner.view.lock().snapshot();
        let mut all: Vec<SocketAddr> = snap
            .trusted
            .into_iter()
            .chain(snap.recent)
            .chain(snap.random)
            .chain(snap.bootstrap)
            .map(|p| p.addr)
            .collect();
        all.sort();
        all.dedup();
        all
    }

    /// Returns a broadcast receiver that yields every
    /// [`DiscoveryEvent`] the node fires. The channel has a
    /// bounded capacity ([`EVENT_CHANNEL_CAPACITY`]); a slow
    /// subscriber will see `RecvError::Lagged` and miss
    /// events when the buffer fills.
    pub fn subscribe_events(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.inner.events.subscribe()
    }

    /// Returns a reference to the underlying `peashape::Node`.
    /// Useful for applications that want to send shaped
    /// traffic on the same connection set.
    pub fn peashape(&self) -> &peashape::Node {
        &self.inner.peashape
    }

    /// Returns a reference to the underlying `pea2pea::Node`.
    ///
    /// Exposed so that callers can layer additional `pea2pea`
    /// protocols on top of `peaveil` — most importantly, a
    /// custom [`Handshake`](pea2pea::protocols::Handshake) to
    /// encrypt and authenticate the TCP connection. Register
    /// the handshake through the returned `&pea2pea::Node`
    /// **before** calling [`Node::spawn`]: once `spawn`
    /// returns, the listener is already accepting connections
    /// and the peaveil receive task is already pulling
    /// frames, so a handshake registered afterwards will not
    /// be applied to links that come up later.
    ///
    /// `peaveil` itself stays out of the crypto business, but
    /// the underlying transport is fully under the caller's
    /// control — this is the recommended way to add
    /// transport-level encryption to a `peaveil` deployment.
    /// See `examples/encrypted.rs` for a minimal
    /// pre-shared-key handshake that wraps the TCP stream
    /// with ChaCha20-Poly1305.
    pub fn p2p(&self) -> &pea2pea::Node {
        self.inner.peashape.p2p()
    }

    /// Returns the [`NodeConfig`] this node was built from.
    pub fn config(&self) -> &NodeConfig {
        &self.inner.config
    }

    /// Reseeds the explorer's RNG. Used by the simulation
    /// harness to drive fully-reproducible runs.
    pub fn reseed(&self, seed: u64) {
        if let Some(e) = self.inner.explorer.get() {
            e.reseed(seed);
        }
    }

    /// Gracefully shuts the node down. Sets the shutdown
    /// flag, wakes the explorer out of any pending sleep,
    /// aborts the receive task, and shuts the peashape node
    /// down. After `shutdown` returns the node is unusable;
    /// callers should drop it.
    pub async fn shutdown(&self) {
        self.inner
            .shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.shutdown_waiter.notify_waiters();
        if let Some(e) = self.inner.explorer.get() {
            e.abort();
        }
        if let Some(h) = self.inner.receive_handle.lock().take() {
            h.abort();
        }
        self.inner.peashape.shutdown().await;
    }

    fn spawn_receive_task(&self) {
        let inner = self.inner.clone();
        let mut rx = inner.peashape.subscribe();
        let handle = tokio::spawn(async move {
            // The peaveil receive task filters every
            // peashape frame, decoding the ones that
            // look like peaveil peer samples and
            // forwarding the rest to a no-op (cover
            // frames are not interesting to peaveil).
            let min_len = peashape::ID_SIZE + crate::sample::SAMPLE_HEADER_SIZE;
            while let Ok(frame) = rx.recv().await {
                if frame.len() < min_len {
                    continue;
                }
                let payload = &frame[peashape::ID_SIZE..];
                match crate::sample::PeerSample::decode(payload) {
                    Ok(sample) => {
                        crate::explorer::handle_received_sample(&inner, sample);
                    }
                    Err(_) => {
                        // Not a peaveil frame (or a
                        // corrupt one). Silently drop.
                    }
                }
            }
        });
        *self.inner.receive_handle.lock() = Some(handle);
    }
}
