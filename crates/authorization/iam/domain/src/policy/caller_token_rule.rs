//! The extra rules a service principal's token must satisfy to call IAM's own API.

use std::time::Duration;

use crate::value_object::subject::SubjectKind;
use crate::value_object::token_identity::TokenIdentity;
use crate::value_object::token_rejection::TokenRejection;

/// What a service caller's token must satisfy to call IAM's own API.
///
/// It must name the IAM caller audience in `aud` and must not live longer than the service token
/// lifetime, because a service token cannot be revoked by session; a user token is checked against
/// the revocation state instead and passes this rule unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerTokenRule {
    audience: String,
    max_service_lifetime: Duration,
}

impl CallerTokenRule {
    /// The rule for `JWT_CALLER_AUDIENCE` and `JWT_SERVICE_TOKEN_MAX_LIFETIME`.
    #[must_use]
    pub const fn new(audience: String, max_service_lifetime: Duration) -> Self {
        Self {
            audience,
            max_service_lifetime,
        }
    }

    /// The audience a service caller's token must contain.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The longest accepted `exp - iat` of a service caller's token.
    #[must_use]
    pub const fn max_service_lifetime(&self) -> Duration {
        self.max_service_lifetime
    }

    /// Checks the identity of a resolved caller token.
    ///
    /// # Errors
    ///
    /// Returns [`TokenRejection::Invalid`] for a service principal's token whose `aud` lacks the
    /// caller audience or whose lifetime exceeds the service token lifetime.
    pub fn check(&self, identity: &TokenIdentity) -> Result<(), TokenRejection> {
        if identity.subject_kind() == SubjectKind::User {
            return Ok(());
        }
        let short_lived = identity.lifetime() <= self.max_service_lifetime;
        if identity.has_audience(&self.audience) && short_lived {
            Ok(())
        } else {
            Err(TokenRejection::Invalid)
        }
    }
}

#[cfg(test)]
mod tests;
