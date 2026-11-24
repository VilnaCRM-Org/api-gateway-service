//! The authorization of IAM's own REST operations (FR-4): the rule table over the decision path.
//!
//! The guard runs after the caller was authenticated. It looks the operation up in the rule table
//! (an operation without a row is refused), decides the catalogue key of the operation and the
//! reserved keys of its row through the [`AccessDecisionService`] for the subject of the caller,
//! and, when the caller lacks one, offers the refusal to the buffer of the audit log through
//! [`RecordRejectedAttemptCommand`] without waiting for the write.

use std::sync::Arc;

use iam_domain::{
    AccessCheck, AccessTarget, AuditAction, AuditReason, AuditTarget, DecisionOutcome,
    DecisionReason, InvalidAccessCheck, InvalidIamValue, InvalidPermissionKey, PermissionKey,
    PermissionsTarget, RequestId, RestTarget, ServiceName, SubjectId, SubjectRef,
};
use shared_domain::CommandBus;

use crate::access_decision_service::AccessDecisionService;
use crate::command::record_rejected_attempt::RecordRejectedAttemptCommand;
use crate::error::IamError;
use crate::operation_rules::{GraphQlRule, OperationRule, OperationRules, Requirement};
use crate::principal::Principal;

/// The audited action of a request for an operation that has no row in the table.
const UNLISTED_ACTION: &str = "operation.unlisted";

/// The audit reason of a caller that lacks a key.
const REASON_FORBIDDEN: &str = "forbidden";

/// The audit reason of an operation that has no row in the table.
const REASON_UNLISTED: &str = "operation_unlisted";

/// The target type of a refused operation.
const TARGET_TYPE: &str = "operation";

/// The authorization of an operation could not be decided; the request fails closed.
#[derive(Debug, thiserror::Error)]
#[error("the authorization of the IAM operation could not be decided")]
pub struct AuthorizationUnavailable;

/// The request an IAM operation was asked to serve.
#[derive(Debug, Clone, Copy)]
pub struct OperationRequest<'request> {
    /// The HTTP method.
    pub method: &'request str,
    /// The path template the router matched, such as `/api/roles/{id}`.
    pub template: &'request str,
    /// The path of the request.
    pub path: &'request str,
    /// The target services that the body of the request names, for a row of the decision API (the
    /// caller rule of FR-12 needs a key for each); empty for every other operation.
    pub services: &'request [String],
    /// The request id, recorded with a refusal.
    pub request_id: Option<&'request str>,
}

/// The GraphQL document an IAM root field was selected in.
#[derive(Debug, Clone, Copy)]
pub struct GraphQlOperationRequest<'request> {
    /// The `{Type}.{field}` coordinates of the IAM-owned root fields the executed operation
    /// selects.
    pub coordinates: &'request [String],
    /// The target services that the arguments of the selected decision fields name; empty when the
    /// document selects none.
    pub services: &'request [String],
    /// The request id, recorded with a refusal.
    pub request_id: Option<&'request str>,
}

/// What a row of a rule table says about an operation: its audited action and what it requires.
struct Row<'services> {
    action: &'static str,
    requirement: Requirement,
    services: &'services [String],
}

/// What a refusal says about the request: the audited action, the target and the reason code.
struct Refusal<'text> {
    action: &'text str,
    target: &'text str,
    reason: &'text str,
}

/// How the keys of an operation were decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allowed,
    Denied,
    Unavailable,
}

impl Verdict {
    fn of(outcome: &DecisionOutcome) -> Self {
        if outcome.decision().is_allow() {
            Self::Allowed
        } else if outcome.reason() == DecisionReason::Unavailable {
            Self::Unavailable
        } else {
            Self::Denied
        }
    }
}

/// Authorizes the callers of IAM's REST operations.
///
/// A failure of the decision path (the policy cannot be read) is an error, never an allow; a
/// refusal is [`IamError::Forbidden`], which maps to 403 and `FORBIDDEN`.
#[derive(Debug)]
pub struct IamAccessGuard {
    decisions: Arc<AccessDecisionService>,
    commands: Arc<dyn CommandBus>,
}

impl IamAccessGuard {
    /// A guard over the decision path and the command bus that records refusals.
    #[must_use]
    pub const fn new(decisions: Arc<AccessDecisionService>, commands: Arc<dyn CommandBus>) -> Self {
        Self {
            decisions,
            commands,
        }
    }

    /// Lets the request through when `principal` holds what the row of the operation requires.
    ///
    /// # Errors
    ///
    /// [`IamError::Forbidden`] when the operation has no row or the caller lacks a key (the
    /// refusal is offered to the audit log), and [`IamError::Storage`] when the policy cannot be
    /// read.
    pub async fn authorize(
        &self,
        principal: &Principal,
        request: &OperationRequest<'_>,
    ) -> Result<(), IamError> {
        let Some(rule) = OperationRules::find(request.method, request.template) else {
            return self
                .refuse_unlisted(principal, request.template, request.request_id)
                .await;
        };
        let check = catalogue_check(rule, request);
        let row = Row {
            action: rule.action,
            requirement: rule.requirement,
            services: request.services,
        };
        self.enforce(principal, &row, &check, request.request_id)
            .await
    }

    /// Lets a GraphQL document through when `principal` holds what the row of every IAM root field
    /// it selects requires; the fields are checked in order and the first refusal is the answer.
    ///
    /// # Errors
    ///
    /// [`IamError::Forbidden`] when a coordinate has no row or the caller lacks a key (the
    /// refusal is offered to the audit log), and [`IamError::Storage`] when the policy cannot be
    /// read.
    pub async fn authorize_graphql(
        &self,
        principal: &Principal,
        request: &GraphQlOperationRequest<'_>,
    ) -> Result<(), IamError> {
        for coordinate in request.coordinates {
            let Some(rule) = OperationRules::find_graphql(coordinate) else {
                return self
                    .refuse_unlisted(principal, coordinate, request.request_id)
                    .await;
            };
            let row = Row {
                action: rule.action,
                requirement: rule.requirement,
                services: request.services,
            };
            self.enforce(principal, &row, &field_check(rule)?, request.request_id)
                .await?;
        }
        Ok(())
    }

    /// Refuses an operation that has no row and offers the refusal to the audit log.
    async fn refuse_unlisted(
        &self,
        principal: &Principal,
        target: &str,
        request_id: Option<&str>,
    ) -> Result<(), IamError> {
        let refusal = Refusal {
            action: UNLISTED_ACTION,
            target,
            reason: REASON_UNLISTED,
        };
        self.refuse(principal, &refusal, request_id).await;
        Err(IamError::Forbidden)
    }

    /// Decides one row: an allow passes, a deny is refused and audited, an undecidable policy is
    /// an error.
    async fn enforce(
        &self,
        principal: &Principal,
        row: &Row<'_>,
        check: &AccessCheck,
        request_id: Option<&str>,
    ) -> Result<(), IamError> {
        match self.row_verdict(principal, row, check).await {
            Verdict::Allowed => Ok(()),
            Verdict::Denied => {
                let refusal = Refusal {
                    action: row.action,
                    target: row.action,
                    reason: REASON_FORBIDDEN,
                };
                self.refuse(principal, &refusal, request_id).await;
                Err(IamError::Forbidden)
            }
            Verdict::Unavailable => Err(IamError::Storage(Box::new(AuthorizationUnavailable))),
        }
    }

    /// Decides a row: by the caller rule when its keys depend on the request, else by its fixed
    /// keys.
    async fn row_verdict(
        &self,
        principal: &Principal,
        row: &Row<'_>,
        check: &AccessCheck,
    ) -> Verdict {
        match row.requirement.caller_rule() {
            Some(rule) => caller::caller_verdict(self, principal, rule, row.services).await,
            None => self.verdict(principal, row.requirement, check).await,
        }
    }

    /// Decides the catalogue key, when the row needs it, then the reserved keys.
    async fn verdict(
        &self,
        principal: &Principal,
        requirement: Requirement,
        check: &AccessCheck,
    ) -> Verdict {
        let subject = subject_of(principal);
        let catalogue = self.catalogue_verdict(&subject, requirement, check).await;
        if catalogue != Verdict::Allowed {
            return catalogue;
        }
        self.reserved_verdict(subject, requirement).await
    }

    /// Decides the catalogue key of the operation; a row without one is allowed.
    async fn catalogue_verdict(
        &self,
        subject: &SubjectRef,
        requirement: Requirement,
        check: &AccessCheck,
    ) -> Verdict {
        if !requirement.needs_catalogue() {
            return Verdict::Allowed;
        }
        let outcome = self
            .decisions
            .decide_for_subject(subject.clone(), check)
            .await;
        Verdict::of(&outcome)
    }

    /// Decides the reserved keys of the row; a row without one is allowed.
    async fn reserved_verdict(&self, subject: SubjectRef, requirement: Requirement) -> Verdict {
        let Ok(keys) = reserved_keys(requirement) else {
            return Verdict::Unavailable;
        };
        if keys.is_empty() {
            return Verdict::Allowed;
        }
        Verdict::of(&self.decisions.decide_reserved(subject, keys).await)
    }

    /// Offers the refusal to the buffer of the audit log; a failure to do so is logged and never
    /// changes the answer to the caller.
    async fn refuse(&self, principal: &Principal, refusal: &Refusal<'_>, request_id: Option<&str>) {
        match rejection(principal, refusal, request_id) {
            Ok(command) => self.offer(command).await,
            Err(error) => log_undescribed(error),
        }
    }

    async fn offer(&self, command: RecordRejectedAttemptCommand) {
        if let Err(error) = self.commands.dispatch(command).await {
            log_not_offered(&error);
        }
    }
}

fn log_undescribed(error: InvalidIamValue) {
    tracing::error!(error = %error, "a refused IAM request could not be described");
}

fn log_not_offered<E: std::fmt::Display>(error: &E) {
    tracing::warn!(error = %error, "a refused IAM request could not be offered");
}

/// The subject that the caller's token proved.
fn subject_of(principal: &Principal) -> SubjectRef {
    match principal.subject() {
        SubjectId::User(id) => SubjectRef::user(*id),
        SubjectId::Service(name) => SubjectRef::service(name.clone()),
    }
}

/// The check of the catalogue key of the operation: a REST check against service `iam`.
fn catalogue_check(rule: &OperationRule, request: &OperationRequest<'_>) -> AccessCheck {
    AccessCheck::new(
        ServiceName::iam().clone(),
        AccessTarget::Rest(RestTarget::new(rule.method, request.path.to_owned())),
        None,
        None,
    )
}

/// The check of the catalogue key of an IAM root field: its permission key against service `iam`.
fn field_check(rule: &GraphQlRule) -> Result<AccessCheck, IamError> {
    let key = format!("gql:iam:{}", rule.coordinate);
    let target = PermissionsTarget::new(vec![key]).map_err(undecidable)?;
    Ok(AccessCheck::new(
        ServiceName::iam().clone(),
        AccessTarget::Permissions(target),
        None,
        None,
    ))
}

/// The error of a check that cannot be built: the request fails closed like an unreadable policy.
fn undecidable(_error: InvalidAccessCheck) -> IamError {
    IamError::Storage(Box::new(AuthorizationUnavailable))
}

/// The reserved keys of the row; a row that names a key that does not parse is a defect.
fn reserved_keys(requirement: Requirement) -> Result<Vec<PermissionKey>, InvalidPermissionKey> {
    requirement
        .reserved()
        .iter()
        .map(|raw| PermissionKey::parse(raw))
        .collect()
}

/// The command that records the refusal of `principal`.
fn rejection(
    principal: &Principal,
    refusal: &Refusal<'_>,
    request_id: Option<&str>,
) -> Result<RecordRejectedAttemptCommand, InvalidIamValue> {
    Ok(RecordRejectedAttemptCommand {
        actor: principal.actor(),
        action: AuditAction::new(refusal.action)?,
        reason: AuditReason::new(refusal.reason)?,
        target: AuditTarget::new(TARGET_TYPE, refusal.target)?,
        request_id: request_id.and_then(|id| RequestId::new(id).ok()),
    })
}

mod caller;

#[cfg(test)]
mod tests;
