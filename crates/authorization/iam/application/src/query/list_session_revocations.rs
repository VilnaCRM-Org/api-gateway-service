//! Lists session revocations with cursor pagination and filters (FR-81).

use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    RevocationRepository, RevocationSource, SessionRevocation, SessionRevocationId,
    SessionRevocationSearch,
};
use shared_domain::{Query, QueryHandler, Uuid};

use crate::error::IamError;

/// The largest page of session revocations.
pub const MAX_PAGE_SIZE: u32 = 100;

/// Asks for one page of the session revocations that meet the filters, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListSessionRevocationsQuery {
    /// The largest number of revocations of the page; a value outside 1 to [`MAX_PAGE_SIZE`] is
    /// brought into that range.
    pub limit: u32,
    /// The last revocation of the previous page; none for the first page.
    pub after: Option<SessionRevocationId>,
    /// Only the revocations of this user's sessions.
    pub user: Option<Uuid>,
    /// Only the revocations that this source caused.
    pub source: Option<RevocationSource>,
    /// Only the revocations recorded at or after this instant.
    pub from: Option<SystemTime>,
    /// Only the revocations recorded before this instant.
    pub until: Option<SystemTime>,
}

/// One page of session revocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRevocationPage {
    /// The revocations of the page, newest first.
    pub revocations: Vec<SessionRevocation>,
    /// The cursor of the next page: the last revocation of this one; none when no older
    /// revocation follows.
    pub next_after: Option<SessionRevocationId>,
}

impl Query for ListSessionRevocationsQuery {
    type Output = SessionRevocationPage;
    type Error = IamError;
    const NAME: &'static str = "ListSessionRevocationsQuery";
}

/// Handles [`ListSessionRevocationsQuery`].
///
/// It reads one revocation more than the page holds, to know whether an older page follows
/// without a second query.
#[derive(Debug)]
pub struct ListSessionRevocationsQueryHandler {
    revocations: Arc<dyn RevocationRepository>,
}

impl ListSessionRevocationsQueryHandler {
    /// A handler over the revocation repository.
    #[must_use]
    pub const fn new(revocations: Arc<dyn RevocationRepository>) -> Self {
        Self { revocations }
    }

    async fn list(
        &self,
        query: ListSessionRevocationsQuery,
    ) -> Result<SessionRevocationPage, IamError> {
        let limit = query.limit.clamp(1, MAX_PAGE_SIZE);
        let search = SessionRevocationSearch {
            user: query.user,
            source: query.source,
            from: query.from,
            until: query.until,
            after: query.after,
            limit: limit.saturating_add(1),
        };
        let mut revocations = self.revocations.search_session_revocations(&search).await?;
        let size = usize::try_from(limit).unwrap_or(usize::MAX);
        let next_after = revocations
            .get(size.saturating_sub(1))
            .filter(|_last| revocations.len() > size)
            .map(|last| last.id);
        revocations.truncate(size);
        Ok(SessionRevocationPage {
            revocations,
            next_after,
        })
    }
}

#[async_trait::async_trait]
impl QueryHandler<ListSessionRevocationsQuery> for ListSessionRevocationsQueryHandler {
    async fn handle(
        &self,
        query: ListSessionRevocationsQuery,
    ) -> Result<SessionRevocationPage, IamError> {
        self.list(query).await
    }
}

#[cfg(test)]
mod tests;
