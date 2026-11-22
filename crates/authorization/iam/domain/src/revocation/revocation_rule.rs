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
        let issued_at = identity.issued_at();
        let cut_off =
            |cutoff: Option<SystemTime>| cutoff.is_some_and(|instant| issued_at <= instant);
        if status.session_revoked || cut_off(status.user_cutoff) || cut_off(status.global_cutoff) {
            return Err(TokenRejection::Revoked);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
