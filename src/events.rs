//! The broadcast channel of [`DiscoveryEvent`]s.
//!
//! One [`Events`] is owned by every [`NodeInner`]. It
//! multiplexes a single `tokio::sync::broadcast` sender that
//! the explorer and the receive task use to publish events,
//! and that [`Node::subscribe_events`] clones receivers from.
//!
//! [`NodeInner`]: crate::node::NodeInner
//! [`Node::subscribe_events`]: crate::Node::subscribe_events
//! [`DiscoveryEvent`]: crate::node::DiscoveryEvent

use tokio::sync::broadcast;

use crate::node::DiscoveryEvent;

/// The shared, node-wide event multiplexer.
pub(crate) struct Events {
    sender: broadcast::Sender<DiscoveryEvent>,
}

impl Events {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(crate::node::EVENT_CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Publishes an event to all current subscribers.
    /// Subscribers that fall behind see `RecvError::Lagged`
    /// and miss events when the channel buffer fills.
    pub fn dispatch(&self, event: DiscoveryEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribes to the event stream. Each subscriber
    /// gets its own buffer slot; events fired before the
    /// subscription are not observed.
    pub fn subscribe(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.sender.subscribe()
    }
}
