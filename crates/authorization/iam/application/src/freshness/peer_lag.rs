//! The cross-check of the freshness proof against the peers (FR-73).
//!
//! A pod that holds a fresh proof while a peer reports a newer applied version for more than
//! [`PEER_LAG_TOLERANCE`] cannot be right: either the proof or the snapshot is wrong. The tracker
//! is the pure part of the check: it remembers since when a peer has been ahead.

use std::time::Duration;

use iam_domain::{BootInstant, PolicyVersion};

/// How long a peer may report a newer applied version before the proof is invalid.
pub const PEER_LAG_TOLERANCE: Duration = Duration::from_secs(1);

/// What one observation of the peers showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLag {
    /// No peer is ahead.
    None,
    /// A peer is ahead, for no longer than the tolerance.
    Ahead,
    /// A peer has been ahead for longer than the tolerance: the proof is invalid.
    Exceeded {
        /// How long a peer has been ahead.
        lag: Duration,
        /// The newest version a peer reports.
        peer: PolicyVersion,
        /// Whether this is the first observation of the episode, the one that alerts.
        first: bool,
    },
}

/// Remembers since when a peer has been ahead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerLagTracker {
    ahead_since: Option<BootInstant>,
    alerted: bool,
}

impl PeerLagTracker {
    /// A tracker that has seen no peer ahead.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ahead_since: None,
            alerted: false,
        }
    }

    /// Observes the versions `peers` report at `now` against `own`, the version this pod applied.
    pub fn observe(
        &mut self,
        now: BootInstant,
        own: PolicyVersion,
        peers: &[PolicyVersion],
    ) -> PeerLag {
        let Some(peer) = peers.iter().copied().filter(|peer| *peer > own).max() else {
            *self = Self::new();
            return PeerLag::None;
        };
        let since = *self.ahead_since.get_or_insert(now);
        let lag = now.saturating_since(since);
        if lag <= PEER_LAG_TOLERANCE {
            return PeerLag::Ahead;
        }
        let first = !self.alerted;
        self.alerted = true;
        PeerLag::Exceeded { lag, peer, first }
    }
}

#[cfg(test)]
mod tests;
