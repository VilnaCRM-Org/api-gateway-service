//! The rule that refuses tokens of revoked sessions and cut-off subjects.

use std::time::SystemTime;

use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

/// The revocation state that applies to one token, as read through the `RevocationView` port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RevocationStatus {
    /// Whether the token's session is recorded as revoked.
    pub session_revoked: bool,
    /// The cut-off of the token's user, when one is set.
    pub user_cutoff: Option<SystemTime>,
    /// The global cut-off, when one is set.
    pub global_cutoff: Option<SystemTime>,
}

/// Refuses a token when its session is revoked, when its `iat` is at or before the user's
/// cut-off, or when its `iat` is at or before the global cut-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationRule;

impl RevocationRule {
    /// Checks the identity against the revocation state.
    ///
    /// # Errors
    ///
    /// Returns [`TokenRejection::Revoked`] when one of the three conditions holds.
    pub fn check(
        identity: &TokenIdentity,
        status: &RevocationStatus,
    ) -> Result<(), TokenRejection> {
        if Self::revokes(identity.issued_at(), status) {
            return Err(TokenRejection::Revoked);
        }
        Ok(())
    }

    /// Whether a token issued at `issued_at` is revoked by `status`: its session is revoked, or
    /// it was issued at or before the cut-off of its user or the global cut-off. An open stream
    /// is decided again with this rule when a version changes the revocation state.
    #[must_use]
    pub fn revokes(issued_at: SystemTime, status: &RevocationStatus) -> bool {
        let cut_off =
            |cutoff: Option<SystemTime>| cutoff.is_some_and(|instant| issued_at <= instant);
        status.session_revoked || cut_off(status.user_cutoff) || cut_off(status.global_cutoff)
    }
}

#[cfg(test)]
mod tests;
