//! `N_ready` of the conservative rate limit, read from the endpoint watch (Story 10.1).

use iam_domain::{ReadyPeers, WatchTarget};

use crate::EndpointView;

/// The ready endpoints of the peers Service `iam-gateway-peers` in the endpoint directory.
#[derive(Debug, Clone)]
pub struct EndpointReadyPeers {
    view: EndpointView,
    target: WatchTarget,
}

impl EndpointReadyPeers {
    /// A count over the endpoints `view` holds for the peers Service `target`.
    #[must_use]
    pub const fn new(view: EndpointView, target: WatchTarget) -> Self {
        Self { view, target }
    }
}

impl ReadyPeers for EndpointReadyPeers {
    fn ready_endpoints(&self) -> u32 {
        u32::try_from(self.view.offered(&self.target).len()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
mod tests;
