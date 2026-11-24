//! Port that asks the other gateway pods which policy version they applied (FR-73).

use crate::value_object::policy_version::PolicyVersion;

/// The cross-check of the freshness proof: a peer that applied a newer version than this pod
/// shows that the pod's proof cannot be right.
#[async_trait::async_trait]
pub trait PeerFreshnessClient: std::fmt::Debug + Send + Sync {
    /// The versions the reachable peers applied now. A peer that does not answer is left out; an
    /// empty list means the cross-check has nothing to compare.
    async fn applied_versions(&self) -> Vec<PolicyVersion>;
}
