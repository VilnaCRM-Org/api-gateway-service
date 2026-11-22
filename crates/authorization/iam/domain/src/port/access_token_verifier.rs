//! Access token verification port.

use crate::value_object::access_token::AccessToken;
use crate::value_object::credential::Credential;
use crate::value_object::token_rejection::TokenRejection;

/// Verifies a bearer credential offline: signature, issuer, audience, header rules, required
/// claims and the [`TokenLifetimeRule`](crate::policy::token_lifetime_rule::TokenLifetimeRule).
///
/// It never persists the token and never calls the issuer.
pub trait AccessTokenVerifier: std::fmt::Debug + Send + Sync {
    /// The identity the credential proves.
    ///
    /// # Errors
    ///
    /// Returns [`TokenRejection::Missing`] for a blank credential, [`TokenRejection::Expired`] for
    /// a token whose expiry lies beyond the skew in the past and [`TokenRejection::Invalid`] for
    /// every other refusal.
    fn verify(&self, credential: &Credential) -> Result<AccessToken, TokenRejection>;

    /// A number that changes whenever the trusted key set changes, so that a memo of verified
    /// tokens is flushed.
    fn key_set_version(&self) -> u64;
}
