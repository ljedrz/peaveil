//! Configuration translation to the underlying `peashape` layer.
//!
//! `peaveil` sits on top of `peashape`, which provides the
//! wire-level shaping. The mapping from a [`NodeConfig`] to
//! the corresponding [`peashape::ShapeConfig`] lives here.
//!
//! [`NodeConfig`]: crate::NodeConfig

use crate::config::NodeConfig;
use peashape::ShapeConfig;

/// Translates a `peaveil` [`NodeConfig`] into a `peashape`
/// [`ShapeConfig`] for the underlying transport.
///
/// `peaveil`'s discovery traffic is shaped exactly the way
/// `peashape` shapes any other application traffic: as
/// constant-size, constant-rate (or Poisson) frames. The
/// shape-config parameters are the relevant subset of the
/// `peaveil::NodeConfig`:
///
/// - `frame_size` and the lane capacities are passed through
///   unchanged;
/// - `cover` (constant or Poisson) drives the shaping
///   strategy;
/// - `view_size` and `sample_size` are *not* used by the
///   peashape layer; they are peaveil-internal knobs.
///
/// [`NodeConfig`]: crate::NodeConfig
pub(crate) fn config_to_shape(config: &NodeConfig) -> ShapeConfig {
    ShapeConfig {
        name: config.name.clone(),
        listener_addr: config.listener_addr,
        strategy: config.cover.as_shaping(),
        // peaveil's discovery traffic is *unicast-heavy*: every
        // explorer tick ships one sample to one specific peer.
        // peashape's own guidance is that `Global` scope leaks a
        // residual aggregate signal for unicast workloads (a peer
        // that receives sustained unicast gets frames at a
        // marginally higher long-run rate than its cover-only
        // share), whereas `PerConnection` avoids it entirely: a
        // real sample simply occupies the cover slot the
        // recipient's link was going to emit anyway, so it is
        // indistinguishable on that link from pure cover. Since
        // the *destination* privacy of discovery traffic is a
        // first-class claim of peaveil, we use `PerConnection`.
        //
        // Under `PerConnection` the per-link rate is the cover
        // interval times the connected-peer count, and varies
        // only with the connection count — never with whether the
        // explorer is actively sampling. `fanout` is irrelevant in
        // this mode.
        scope: peashape::ShapingScope::PerConnection { randomize: true },
        fanout: 1,
        frame_size: config.frame_size,
        // The high-priority lane is for "real" application
        // traffic; peaveil uses it for its peer samples.
        high_lane_capacity: 16,
        // The low-priority lane is for relay traffic; peaveil
        // does not relay, so the capacity is just a
        // comfortable buffer for any pre-built frames the
        // application might enqueue.
        low_lane_capacity: 64,
        max_frame_size: config.max_frame_size,
        max_connections: config.max_connections,
        max_connections_per_ip: config.max_connections_per_ip,
        reuse_listener_port: config.reuse_listener_port,
        ..ShapeConfig::default()
    }
}
