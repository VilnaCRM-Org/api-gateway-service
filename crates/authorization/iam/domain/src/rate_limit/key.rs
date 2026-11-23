//! The key a rate counter is kept under (FR-65).
//!
//! The key holds the key kind of the policy and a hash of the parts the kind counts by, so no
//! subject id, IP address or token appears in a key of the shared store or of a log.

use crate::port::request_digester::RequestDigester;
use crate::rate_policy::fields::RateKeyKind;

/// The values a request offers to key a counter by; a kind reads only the parts it counts by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateKeyParts<'a> {
    /// The authenticated subject, known after authentication.
    pub subject: Option<&'a str>,
    /// The client address.
    pub ip: Option<&'a str>,
    /// The matched route.
    pub route: Option<&'a str>,
}

/// A part that the key kind counts by is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRateKey {
    /// The kind counts by the client address and none was given.
    #[error("a rate key of this kind needs the client address")]
    Ip,
    /// The kind counts by the subject and none was given.
    #[error("a rate key of this kind needs the authenticated subject")]
    Subject,
    /// The kind counts by the route and none was given.
    #[error("a rate key of this kind needs the route")]
    Route,
}

/// The key kind with the hash of its parts: the counter of one client, subject or route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateKey {
    kind: RateKeyKind,
    key_hash: String,
}

impl RateKey {
    /// The key of `kind` over the parts it counts by, hashed with `digester`.
    ///
    /// # Errors
    ///
    /// The [`InvalidRateKey`] of the first part the kind needs and `parts` lacks.
    pub fn new(
        kind: RateKeyKind,
        parts: &RateKeyParts<'_>,
        digester: &dyn RequestDigester,
    ) -> Result<Self, InvalidRateKey> {
        let ip = || parts.ip.ok_or(InvalidRateKey::Ip);
        let subject = || parts.subject.ok_or(InvalidRateKey::Subject);
        let route = || parts.route.ok_or(InvalidRateKey::Route);
        let counted: Vec<&str> = match kind {
            RateKeyKind::Ip => vec![ip()?],
            RateKeyKind::Subject => vec![subject()?],
            RateKeyKind::SubjectRoute => vec![subject()?, route()?],
            RateKeyKind::Route => vec![route()?],
        };
        let canonical = counted.iter().fold(kind.as_str().to_owned(), |text, part| {
            format!("{text}|{}:{part}", part.len())
        });
        let key_hash = digester
            .digest(&canonical)
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat();
        Ok(Self { kind, key_hash })
    }

    /// What the key counts by.
    #[must_use]
    pub const fn kind(&self) -> RateKeyKind {
        self.kind
    }

    /// The lowercase hexadecimal hash of the key parts, the `keyHash` of the shared store.
    #[must_use]
    pub fn key_hash(&self) -> &str {
        &self.key_hash
    }
}

#[cfg(test)]
mod tests;
