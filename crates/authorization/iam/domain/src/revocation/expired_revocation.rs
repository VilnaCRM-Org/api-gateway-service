//! A revocation record whose prune-after instant has passed, ready for its tombstone (FR-79).

use std::time::SystemTime;

use shared_domain::Uuid;

use crate::state::key::StateKey;
use crate::value_object::session_id::SessionId;

/// The largest number of revocation records that one tombstone commit removes; the others follow
/// with the next run.
pub const MAX_TOMBSTONES_PER_RUN: u32 = 500;

/// A session revocation or a user cut-off whose `prune_after` lies in the past.
///
/// The global cut-off is never one of them: it is a single record that carries no prune-after
/// instant and is never tombstoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiredRevocation {
    /// A revoked session.
    Session {
        /// The revoked session.
        session: SessionId,
        /// The stored prune-after instant.
        prune_after: SystemTime,
    },
    /// The cut-off of one user.
    UserCutoff {
        /// The user.
        user: Uuid,
        /// The stored prune-after instant.
        prune_after: SystemTime,
    },
}

impl ExpiredRevocation {
    /// The key of the state record that the tombstone replaces.
    #[must_use]
    pub fn state_key(&self) -> StateKey {
        match self {
            Self::Session { session, .. } => StateKey::SessionRevocation(session.clone()),
            Self::UserCutoff { user, .. } => StateKey::UserRevocation(*user),
        }
    }

    /// The stored prune-after instant.
    #[must_use]
    pub const fn prune_after(&self) -> SystemTime {
        match self {
            Self::Session { prune_after, .. } | Self::UserCutoff { prune_after, .. } => {
                *prune_after
            }
        }
    }

    /// The kind of the record, as the audit record names its target.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Session { .. } => "session_revocation",
            Self::UserCutoff { .. } => "user_cutoff",
        }
    }

    /// The identifier of the record: the session id or the user id.
    #[must_use]
    pub fn target_id(&self) -> String {
        match self {
            Self::Session { session, .. } => session.to_string(),
            Self::UserCutoff { user, .. } => user.to_string(),
        }
    }
}

#[cfg(test)]
mod tests;
