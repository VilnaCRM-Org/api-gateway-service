//! Reads the token cut-off of one user with its source and actor (FR-81).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, RevocationRepository, RevocationSource,
    SecurityAuditFilter, SecurityAuditLog, SecurityAuditSearch, SystemComponent, UserTokenCutoff,
};
use shared_domain::{Query, QueryHandler, Uuid};

use crate::error::IamError;

/// The audited action of a cut-off of the tokens of a user.
const CUTOFF_ACTION: &str = "user_tokens.cut_off";

/// The target type of the audit record of that cut-off.
const CUTOFF_TARGET_TYPE: &str = "user";

/// Asks for the cut-off of the tokens of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetUserTokenCutoffQuery {
    /// The user.
    pub user: Uuid,
}

/// A user cut-off with the actor that set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTokenCutoffView {
    /// The cut-off, with its source.
    pub cutoff: UserTokenCutoff,
    /// The actor that set it: `system:user-service` for a cut-off that a User service event
    /// caused, and for an operator cut-off the actor of its audit record; none when the audit
    /// log holds no record of it.
    pub actor: Option<ActorRef>,
}

impl Query for GetUserTokenCutoffQuery {
    type Output = Option<UserTokenCutoffView>;
    type Error = IamError;
    const NAME: &'static str = "GetUserTokenCutoffQuery";
}

/// Handles [`GetUserTokenCutoffQuery`].
///
/// The cut-off row keeps its source and not its actor; the actor of an operator cut-off is the
/// actor of the newest committed audit record of the cut-off of that user.
#[derive(Debug)]
pub struct GetUserTokenCutoffQueryHandler {
    revocations: Arc<dyn RevocationRepository>,
    audit: Arc<dyn SecurityAuditLog>,
}

impl GetUserTokenCutoffQueryHandler {
    /// A handler over the revocation repository and the audit log.
    #[must_use]
    pub const fn new(
        revocations: Arc<dyn RevocationRepository>,
        audit: Arc<dyn SecurityAuditLog>,
    ) -> Self {
        Self { revocations, audit }
    }

    async fn get(
        &self,
        query: GetUserTokenCutoffQuery,
    ) -> Result<Option<UserTokenCutoffView>, IamError> {
        let Some(cutoff) = self.revocations.user_cutoff(query.user).await? else {
            return Ok(None);
        };
        let actor = match cutoff.source {
            RevocationSource::UserService => Some(ActorRef::System(SystemComponent::UserService)),
            RevocationSource::Operator => self.operator_actor(query.user).await?,
        };
        Ok(Some(UserTokenCutoffView { cutoff, actor }))
    }

    /// The actor of the newest committed audit record of the cut-off of `user`.
    async fn operator_actor(&self, user: Uuid) -> Result<Option<ActorRef>, IamError> {
        let filter = SecurityAuditFilter::new()
            .of_action(AuditAction::new(CUTOFF_ACTION)?)
            .with_outcome(AuditOutcome::Committed)
            .about(CUTOFF_TARGET_TYPE, Some(&user.to_string()))?;
        let search = SecurityAuditSearch {
            filter,
            before_seq: None,
            limit: 1,
        };
        let records = self.audit.search(&search).await?;
        Ok(records
            .first()
            .map(|record| record.event().parts().actor.clone()))
    }
}

#[async_trait::async_trait]
impl QueryHandler<GetUserTokenCutoffQuery> for GetUserTokenCutoffQueryHandler {
    async fn handle(
        &self,
        query: GetUserTokenCutoffQuery,
    ) -> Result<Option<UserTokenCutoffView>, IamError> {
        self.get(query).await
    }
}

#[cfg(test)]
mod tests;
