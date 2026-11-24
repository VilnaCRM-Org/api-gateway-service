//! The authorization of a REST request that the gateway matched to a route (FR-4, FR-13, FR-59).

use std::sync::Arc;

use iam_domain::{
    AccessCheck, AccessTarget, DecisionOutcome, DecisionReason, HttpMethod, NormalizedPath,
    PolicySnapshot, PolicyVersion, RestTarget, ServiceName, SubjectId, SubjectRef, TokenRepository,
};
use shared_domain::{Clock, CommandBus, UuidGenerator};

use super::snapshot_reads::{CatalogueCache, LoadedSnapshotReads};
use crate::access_decision_service::AccessDecisionService;
use crate::error::IamError;
use crate::iam_access_guard::{IamAccessGuard, OperationRequest};
use crate::operation_rules::OperationRules;
use crate::principal::Principal;
use crate::service_catalog_loader::ServiceCatalogLoader;

/// The request to authorize, with the one snapshot every read of it uses.
#[derive(Debug, Clone, Copy)]
pub struct RouteRequest<'request> {
    /// The snapshot the request loaded; the decision reads nothing else.
    pub snapshot: &'request Arc<dyn PolicySnapshot>,
    /// The service of the matched route, whose catalogue the operation is looked up in.
    pub service: &'request ServiceName,
    /// The HTTP method.
    pub method: HttpMethod,
    /// The normalised path.
    pub path: &'request NormalizedPath,
    /// The request id, recorded with a refusal of one of IAM's own operations.
    pub request_id: Option<&'request str>,
}

/// What authorizing a request found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// The principal holds what the operation requires; the version is the one of the snapshot.
    Allowed(PolicyVersion),
    /// The principal may not do it; the reason code never names an operation of another service.
    Denied(DecisionReason),
    /// The decision could not be made on the policy that was read: the request fails closed.
    Unavailable,
}

/// Decides the REST requests of the gateway from one loaded snapshot.
///
/// The operation is looked up in the catalogue of the service of the route only, so the answer for
/// an operation that the service does not have is the same whether or not another service has it.
/// A request for one of IAM's own routes (service `iam`) is decided by the rule table of
/// [`IamAccessGuard`], which `iam-control` applies again to what the gateway lets through; every
/// other request is decided by the [`AccessDecisionService`] on the key of the matched operation.
/// Both read the snapshot through [`LoadedSnapshotReads`].
///
/// A row of the decision API whose rule depends on the services that the body names is decided
/// without the body, so a caller needs `iam:validate:*` for it through the gateway.
#[derive(Debug)]
pub struct RequestAuthorizer {
    tokens: Arc<dyn TokenRepository>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn UuidGenerator>,
    commands: Arc<dyn CommandBus>,
    cache: Arc<CatalogueCache>,
}

impl RequestAuthorizer {
    /// An authorizer over the ports of the decision path; `commands` takes the refusals of IAM's
    /// own operations.
    #[must_use]
    pub fn new(
        tokens: Arc<dyn TokenRepository>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
        commands: Arc<dyn CommandBus>,
    ) -> Self {
        Self {
            tokens,
            clock,
            ids,
            commands,
            cache: Arc::new(CatalogueCache::new()),
        }
    }

    /// Decides whether `principal` may send `request`.
    pub async fn authorize(
        &self,
        request: &RouteRequest<'_>,
        principal: &Principal,
    ) -> Authorization {
        let decisions = self.decisions(request.snapshot);
        let version = request.snapshot.version();
        if request.service.is_iam() {
            Self::authorize_iam(decisions, request, principal, &self.commands, version).await
        } else {
            let check = check(request);
            let outcome = decisions
                .decide_for_subject(subject_of(principal), &check)
                .await;
            Self::authorization_of(&outcome, version)
        }
    }

    /// The decision path over `snapshot`, built for one request: its parts are shared handles.
    fn decisions(&self, snapshot: &Arc<dyn PolicySnapshot>) -> Arc<AccessDecisionService> {
        let reads = Arc::new(LoadedSnapshotReads::new(
            Arc::clone(snapshot),
            Arc::clone(&self.cache),
        ));
        Arc::new(AccessDecisionService::new(
            Arc::clone(&self.tokens),
            ServiceCatalogLoader::new(Arc::<LoadedSnapshotReads>::clone(&reads)),
            reads,
            Arc::clone(&self.clock),
            Arc::clone(&self.ids),
        ))
    }

    async fn authorize_iam(
        decisions: Arc<AccessDecisionService>,
        request: &RouteRequest<'_>,
        principal: &Principal,
        commands: &Arc<dyn CommandBus>,
        version: PolicyVersion,
    ) -> Authorization {
        let Some(rule) = OperationRules::resolve(request.method, request.path) else {
            return Authorization::Denied(DecisionReason::PermissionMissing);
        };
        let path = request.path.canonical();
        let operation = OperationRequest {
            method: rule.method.as_str(),
            template: rule.template,
            path: path.as_str(),
            services: &[],
            request_id: request.request_id,
        };
        let guard = IamAccessGuard::new(decisions, Arc::clone(commands));
        Self::guarded(guard.authorize(principal, &operation).await, version)
    }

    /// What the answer of the guard means for the request: a refusal is a denial, and anything
    /// else that is not an allow is a policy that could not be read.
    fn guarded(answer: Result<(), IamError>, version: PolicyVersion) -> Authorization {
        match answer {
            Ok(()) => Authorization::Allowed(version),
            Err(IamError::Forbidden) => Authorization::Denied(DecisionReason::PermissionMissing),
            Err(_unavailable) => Authorization::Unavailable,
        }
    }

    fn authorization_of(outcome: &DecisionOutcome, version: PolicyVersion) -> Authorization {
        if outcome.decision().is_allow() {
            Authorization::Allowed(version)
        } else if outcome.reason() == DecisionReason::Unavailable {
            Authorization::Unavailable
        } else {
            Authorization::Denied(outcome.reason())
        }
    }
}

/// The check of the operation: a REST target on the service of the route, with the path in the
/// form the upstream receives, so that what is decided is what is forwarded.
fn check(request: &RouteRequest<'_>) -> AccessCheck {
    let path = request.path.canonical().as_str().to_owned();
    AccessCheck::new(
        request.service.clone(),
        AccessTarget::Rest(RestTarget::new(request.method, path)),
        None,
        None,
    )
}

/// The subject that the token of the principal proved.
fn subject_of(principal: &Principal) -> SubjectRef {
    match principal.subject() {
        SubjectId::User(id) => SubjectRef::user(*id),
        SubjectId::Service(name) => SubjectRef::service(name.clone()),
    }
}

#[cfg(test)]
mod tests;
