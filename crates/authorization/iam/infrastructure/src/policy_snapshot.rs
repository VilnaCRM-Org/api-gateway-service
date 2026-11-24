//! The policy snapshot of the gateway (FR-71, NFR-16).
//!
//! It holds copy-on-write shards of the raw policy state, the derived structures that decisions
//! read, the builder that applies complete versions and the cell that publishes the snapshot.

pub mod arc_swap_policy_snapshot;
pub mod builder;
pub mod matchit_route_table_compiler;
pub mod snapshot_revocation_view;

mod data;
mod derived;
mod fnv;
mod shards;
mod working;

pub use arc_swap_policy_snapshot::ArcSwapPolicySnapshot;
pub use builder::{
    ApplyOutcome, PUBLISH_INTERVAL, PolicySnapshotBuilder, RawEntry, SnapshotBuildError,
    SnapshotPorts,
};
pub use matchit_route_table_compiler::MatchitRouteTableCompiler;
pub use snapshot_revocation_view::{SnapshotRevocationError, SnapshotRevocationView};
