//! The cut-off of one user's tokens.

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::revocation::revocation_source::RevocationSource;

/// Every token of `user` issued at or before `tokens_valid_after` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTokenCutoff {
    /// The user.
    pub user: Uuid,
    /// Tokens whose `iat` is at or before this instant are refused.
    pub tokens_valid_after: SystemTime,
    /// Who set the cut-off.
    pub source: RevocationSource,
    /// When it was last moved.
    pub updated_at: SystemTime,
    /// The earliest instant at which the record may be pruned.
    pub prune_after: SystemTime,
}
