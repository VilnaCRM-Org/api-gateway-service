//! GraphQL side of the write outcome: the `consistency` input of every write and the
//! `propagation` field of its payload (FR-75).
//!
//! The values are the upper-case words `PUBLISHED`, `PROPAGATED` and `COMMITTED_PENDING`, carried
//! as text like the other closed value sets of this schema (`kind`, `status`).

use async_graphql::SimpleObject;
use iam_domain::{ChangeReceipt, PolicyVersion, PropagationOutcome, WriteMode};
use shared_application::http::Problem;

use crate::error::IamError;
use crate::http::extract::supported_write_mode;

/// The `status` of a write whose policy version Kafka acknowledged.
pub const STATUS_PUBLISHED: &str = "PUBLISHED";

/// The `status` of a committed write whose policy version Kafka did not acknowledge in time.
pub const STATUS_COMMITTED_PENDING: &str = "COMMITTED_PENDING";

/// What a write learned about the publication of its policy version.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "Propagation")]
pub struct PropagationObject {
    /// How far the change got: `PUBLISHED` when Kafka acknowledged the policy version, or `COMMITTED_PENDING` when the change is committed and Kafka did not acknowledge the version within the wait.
    pub status: String,
    /// The policy version that the change produced.
    pub policy_version: Option<i64>,
    /// The number of gateway pods that applied the version; null until Story 13.4.
    pub pods_acknowledged: Option<i32>,
    /// The number of gateway pods that did not apply the version in time; null until Story 13.4.
    pub pods_timed_out: Option<i32>,
}

/// Maps the receipt of a write to the GraphQL propagation field, as `response::write_status` maps
/// it to a REST status.
#[derive(Debug, Clone, Copy)]
pub struct WriteOutcomeMapper;

impl WriteOutcomeMapper {
    /// The propagation of a receipt, none when the change did not affect decisions and waited for
    /// nothing.
    #[must_use]
    pub fn propagation(receipt: &ChangeReceipt) -> Option<PropagationObject> {
        let status = match receipt.propagation()? {
            PropagationOutcome::Published { .. } => STATUS_PUBLISHED,
            PropagationOutcome::CommittedPending => STATUS_COMMITTED_PENDING,
        };
        Some(PropagationObject {
            status: status.to_owned(),
            policy_version: receipt.policy_version().map(PolicyVersion::value),
            pods_acknowledged: None,
            pods_timed_out: None,
        })
    }
}

/// The write mode that the `consistency` input names, `published` when it is absent.
///
/// # Errors
///
/// The 422 problem of a value that is neither `PUBLISHED` nor `PROPAGATED`, and of a mode that is
/// not delivered yet, which names the mode.
pub fn write_mode(consistency: Option<&str>) -> Result<WriteMode, Problem> {
    let mode = match consistency {
        None | Some("PUBLISHED") => WriteMode::Published,
        Some("PROPAGATED") => WriteMode::Propagated,
        Some(_other) => {
            return Err(Problem::from(IamError::invalid_property(
                "consistency",
                "The consistency must be `PUBLISHED` or `PROPAGATED`.",
                "write_mode",
            )));
        }
    };
    supported_write_mode(mode, "consistency").map_err(Problem::from)
}

#[cfg(test)]
mod tests;
