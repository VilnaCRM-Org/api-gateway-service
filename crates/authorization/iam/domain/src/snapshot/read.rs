//! The read API of a policy snapshot: one consistent, immutable state that every decision of a
//! request reads (FR-71).

use crate::policy::compiled_role_set::CompiledRoleSet;
use crate::state::model::{
    AssignmentState, CatalogueEntryState, RatePolicyState, RouteState, UpstreamState,
};
use crate::value_object::boot_instant::BootInstant;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RatePolicyId, RoleId, UpstreamId};
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::route_host::RouteHost;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;
use crate::value_object::upstream_name::UpstreamName;

/// What proves that a snapshot is current: the version it holds and the instant on the boot clock
/// at which the builder last confirmed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessProof {
    /// The version the snapshot holds.
    pub version: PolicyVersion,
    /// When the snapshot was published, on the boot clock.
    pub published_at: BootInstant,
}

/// An immutable policy snapshot. The same value answers every read of one request, so a decision
/// never mixes two versions.
pub trait PolicySnapshot: std::fmt::Debug + Send + Sync {
    /// The policy version.
    fn version(&self) -> PolicyVersion;

    /// The digest of the raw state at that version.
    fn digest(&self) -> PolicyDigestValue;

    /// The hash of the derived structures: it equals the hash of a full rebuild from the same raw
    /// state.
    fn derived_hash(&self) -> PolicyDigestValue;

    /// The accounted size of the snapshot in bytes: an estimate of what the raw state and the
    /// derived structures hold. It is a measurement and not a limit; the bound of NFR-38 is
    /// proven by the load tests.
    fn accounted_bytes(&self) -> usize;

    /// The epoch of the policy log the snapshot follows.
    fn log_epoch(&self) -> LogEpoch;

    /// The proof of freshness.
    fn freshness_proof(&self) -> FreshnessProof;

    /// The route that serves `method` and `path` on `host`.
    fn route(&self, host: &RouteHost, method: HttpMethod, path: &str) -> Option<&RouteState>;

    /// The upstream called `name`.
    fn upstream(&self, name: &UpstreamName) -> Option<&UpstreamState>;

    /// The upstream with the identifier `id`: the upstream table the routes point into.
    fn upstream_by_id(&self, id: UpstreamId) -> Option<&UpstreamState>;

    /// The compiled grants of a role.
    fn role_set(&self, role: RoleId) -> Option<&CompiledRoleSet>;

    /// The assignments of a subject, empty when it has none.
    fn assignments(&self, subject: &SubjectRef) -> &[AssignmentState];

    /// The subjects that hold `role`, in key order.
    fn subjects_of_role(&self, role: RoleId) -> Vec<SubjectRef>;

    /// The rate policy with the identifier `id`.
    fn rate_policy(&self, id: RatePolicyId) -> Option<&RatePolicyState>;

    /// The entries of the catalogue of `service`, once its manifest and every chunk are present.
    fn catalogue(&self, service: &ServiceName) -> Option<&[CatalogueEntryState]>;
}
