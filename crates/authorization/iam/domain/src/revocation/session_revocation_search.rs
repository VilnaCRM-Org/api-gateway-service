//! What a search of the session revocations asks for (FR-81).

use std::cmp::Reverse;
use std::time::SystemTime;

use shared_domain::Uuid;

use crate::revocation::revocation_source::RevocationSource;
use crate::revocation::session_revocation::SessionRevocation;
use crate::value_object::identifier::SessionRevocationId;

/// One page of a search: the newest revocations first, in the order of the instant of the
/// revocation and then of its identifier.
///
/// A revocation must meet every condition that is given; a search without conditions keeps every
/// revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevocationSearch {
    /// Only the revocations of this user's sessions.
    pub user: Option<Uuid>,
    /// Only the revocations that this source caused.
    pub source: Option<RevocationSource>,
    /// Only the revocations recorded at or after this instant.
    pub from: Option<SystemTime>,
    /// Only the revocations recorded before this instant.
    pub until: Option<SystemTime>,
    /// The last revocation of the previous page; only older ones are returned. None for the first
    /// page.
    pub after: Option<SessionRevocationId>,
    /// The largest number of revocations to return.
    pub limit: u32,
}

impl SessionRevocationSearch {
    /// Whether the revocation meets the user, source and time conditions of the search.
    #[must_use]
    pub fn matches(&self, revocation: &SessionRevocation) -> bool {
        self.user.is_none_or(|user| user == revocation.user)
            && self.source.is_none_or(|source| source == revocation.source)
            && self.from.is_none_or(|from| revocation.revoked_at >= from)
            && self.until.is_none_or(|until| revocation.revoked_at < until)
    }

    /// The position of a revocation in the newest-first order; a smaller key is newer.
    #[must_use]
    pub const fn order_key(
        revocation: &SessionRevocation,
    ) -> (Reverse<SystemTime>, Reverse<SessionRevocationId>) {
        (Reverse(revocation.revoked_at), Reverse(revocation.id))
    }
}

#[cfg(test)]
mod tests;
