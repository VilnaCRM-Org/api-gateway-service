//! The write of one session revocation or cut-off that a change hands to the unit of work.

use std::time::SystemTime;

use crate::revocation::expired_revocation::ExpiredRevocation;
use crate::revocation::global_token_cutoff::GlobalTokenCutoff;
use crate::revocation::session_revocation::SessionRevocation;
use crate::revocation::user_token_cutoff::UserTokenCutoff;
use crate::state::key::StateKey;
use crate::value_object::change_statement::ChangeStatement;

/// One write of the revocation state: a revoked session, a user cut-off or the global cut-off.
///
/// The storage never moves a cut-off back and keeps the first record of a revoked session, so a
/// repeated statement leaves the state it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatement {
    /// Record a revoked session; a session that is already revoked keeps its first record.
    Session(SessionRevocation),
    /// Set the cut-off of one user; an earlier instant than the stored one changes nothing.
    UserCutoff(UserTokenCutoff),
    /// Set the global cut-off; an earlier instant than the stored one changes nothing.
    GlobalCutoff(GlobalTokenCutoff),
    /// Remove an expired session revocation or user cut-off, so that its state record becomes a
    /// tombstone (Story 13.6); a record whose `prune_after` is not strictly before `now` any more
    /// (a cut-off that was moved since it was read) stays.
    Prune {
        /// The record to remove.
        target: ExpiredRevocation,
        /// The instant the record is compared with, the time of the emitter run.
        now: SystemTime,
    },
}

impl RevocationStatement {
    /// The key of the state record that the write changes: `revocation/session/<sid>`,
    /// `revocation/user/<uid>` or `revocation/global`.
    #[must_use]
    pub fn state_key(&self) -> StateKey {
        match self {
            Self::Session(revocation) => StateKey::SessionRevocation(revocation.session.clone()),
            Self::UserCutoff(cutoff) => StateKey::UserRevocation(cutoff.user),
            Self::GlobalCutoff(_) => StateKey::GlobalRevocation,
            Self::Prune { target, .. } => target.state_key(),
        }
    }
}

impl From<RevocationStatement> for ChangeStatement {
    fn from(statement: RevocationStatement) -> Self {
        Self::SaveRevocation(Box::new(statement))
    }
}

#[cfg(test)]
mod tests;
