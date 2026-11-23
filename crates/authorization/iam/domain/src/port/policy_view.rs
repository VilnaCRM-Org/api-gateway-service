//! Port that hands out the policy snapshot that is current now.

use std::sync::Arc;

use crate::snapshot::read::PolicySnapshot;

/// The current policy snapshot. A reader keeps the `Arc` for the whole request and so reads one
/// version, however many versions are published meanwhile.
pub trait PolicyView: std::fmt::Debug + Send + Sync {
    /// The snapshot published last, or `None` before the first one: nothing is known yet, so the
    /// gateway answers `iam_stale`.
    fn current(&self) -> Option<Arc<dyn PolicySnapshot>>;
}
