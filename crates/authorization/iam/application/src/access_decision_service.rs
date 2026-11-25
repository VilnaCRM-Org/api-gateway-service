//! The decision path of FR-6 and FR-13, shared by every caller of an access check.

use std::sync::Arc;

use iam_domain::{
    AccessCheck, Credential, DecisionId, DecisionOutcome, DecisionPolicy, DecisionReason,
    DecisionRequest, DecisionVerdict, PermissionFlags, PermissionKey, PolicyReadRepository,
    PolicyVersion, ProjectId, RequiredKey, SubjectId, SubjectRef, TokenIdentity, TokenRepository,
};
use shared_domain::{Clock, UuidGenerator};

use crate::access_log::DecisionTrace;
use crate::required_key_resolver::RequiredKeyResolver;
use crate::service_catalog_loader::ServiceCatalogLoader;

/// What a decision knows besides the verdict.
struct Decided {
    verdict: DecisionVerdict,
    subject: Option<SubjectRef>,
    policy_version: Option<PolicyVersion>,
    trace: DecisionTrace,
}

impl Decided {
    const fn of(
        verdict: DecisionVerdict,
        subject: Option<SubjectRef>,
        policy_version: Option<PolicyVersion>,
    ) -> Self {
        Self {
            verdict,
            subject,
            policy_version,
            trace: DecisionTrace {
                permission_key: None,
                flags: PermissionFlags::NONE,
                wildcard: false,
            },
        }
    }

    /// The same decision with what it knows about the key it was made on.
    fn traced(self, trace: DecisionTrace) -> Self {
        Self { trace, ..self }
    }

    /// The outcome with a new decision id, and the trace.
    fn into_traced(self, decision_id: DecisionId) -> (DecisionOutcome, DecisionTrace) {
        let outcome =
            DecisionOutcome::new(self.verdict, decision_id, self.subject, self.policy_version);
        (outcome, self.trace)
    }

    const fn unavailable(subject: Option<SubjectRef>) -> Self {
        Self::of(
            DecisionVerdict::deny(DecisionReason::Unavailable, Vec::new()),
            subject,
            None,
        )
    }
}

/// Decides access checks and never allows on error.
///
/// The subject's token is resolved through the [`TokenRepository`], the catalogue of the target
/// service and the subject's policy are read from the [`PolicyReadRepository`], the required keys
/// are resolved against that catalogue and the [`DecisionPolicy`] decides. An error in the token
/// resolution, the catalogue loading or the policy read is the deny `unavailable`. There is no
/// cache, no stale-grace window and no database fallback here: the gateway feeds the same service
/// from its snapshot, where a stale snapshot is `unavailable` as well.
#[derive(Debug)]
pub struct AccessDecisionService {
    tokens: Arc<dyn TokenRepository>,
    catalogs: ServiceCatalogLoader,
    policy: Arc<dyn PolicyReadRepository>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn UuidGenerator>,
}

impl AccessDecisionService {
    /// A service over its ports; `catalogs` and `policy` read from the same repository.
    #[must_use]
    pub const fn new(
        tokens: Arc<dyn TokenRepository>,
        catalogs: ServiceCatalogLoader,
        policy: Arc<dyn PolicyReadRepository>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            tokens,
            catalogs,
            policy,
            clock,
            ids,
        }
    }

    /// Decides whether the bearer of `credential` may do what `check` names; the outcome carries
    /// a new decision id whatever the result.
    pub async fn decide(&self, credential: &Credential, check: &AccessCheck) -> DecisionOutcome {
        self.decide_with(self.tokens.as_ref(), credential, check)
            .await
    }

    /// Decides like [`Self::decide`] and also returns what the decision knows about the key it
    /// was made on, for the access log.
    pub async fn decide_traced(
        &self,
        credential: &Credential,
        check: &AccessCheck,
    ) -> (DecisionOutcome, DecisionTrace) {
        self.decide_traced_with(self.tokens.as_ref(), credential, check)
            .await
    }

    /// Decides like [`Self::decide`], resolving the credential through `tokens` instead of the
    /// service's own repository; a batch passes a repository that remembers what it resolved.
    pub async fn decide_with(
        &self,
        tokens: &dyn TokenRepository,
        credential: &Credential,
        check: &AccessCheck,
    ) -> DecisionOutcome {
        self.decide_traced_with(tokens, credential, check).await.0
    }

    /// Decides like [`Self::decide_with`] and also returns what the decision knows about the key
    /// it was made on, for the access log.
    pub async fn decide_traced_with(
        &self,
        tokens: &dyn TokenRepository,
        credential: &Credential,
        check: &AccessCheck,
    ) -> (DecisionOutcome, DecisionTrace) {
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        self.decide_check(tokens, credential, check)
            .await
            .into_traced(decision_id)
    }

    /// Decides `check` for a subject that a verified token already proved, without resolving a
    /// credential: the caller of IAM's own API was authenticated before its operation is
    /// authorized.
    pub async fn decide_for_subject(
        &self,
        subject: SubjectRef,
        check: &AccessCheck,
    ) -> DecisionOutcome {
        self.decide_traced_for_subject(subject, check).await.0
    }

    /// Decides like [`Self::decide_for_subject`] and also returns what the decision knows about
    /// the key it was made on, for the access log.
    pub async fn decide_traced_for_subject(
        &self,
        subject: SubjectRef,
        check: &AccessCheck,
    ) -> (DecisionOutcome, DecisionTrace) {
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        self.decide_subject(subject, check)
            .await
            .into_traced(decision_id)
    }

    /// Decides whether `subject` holds every key of `keys` at global scope, from its policy alone:
    /// no token is resolved and no catalogue is read, because a reserved `iam:` key has no
    /// catalogue entry.
    pub async fn decide_reserved(
        &self,
        subject: SubjectRef,
        keys: Vec<PermissionKey>,
    ) -> DecisionOutcome {
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        let required: Vec<RequiredKey> = keys
            .into_iter()
            .map(|key| RequiredKey::new(key, PermissionFlags::NONE))
            .collect();
        let decided = self.decide_policy(subject, &required, None).await;
        DecisionOutcome::new(
            decided.verdict,
            decision_id,
            decided.subject,
            decided.policy_version,
        )
    }

    /// The outcome of a check that could not be decided: the deny `unavailable` with a new decision
    /// id, no subject and no policy version. A caller that fails before the decision path uses it,
    /// so that the failure still answers with a decision.
    #[must_use]
    pub fn unavailable(&self) -> DecisionOutcome {
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        let decided = Decided::unavailable(None);
        DecisionOutcome::new(
            decided.verdict,
            decision_id,
            decided.subject,
            decided.policy_version,
        )
    }

    /// The outcome of a check that cannot be read: the deny `malformed_operation` with a new
    /// decision id, no subject and no policy version.
    #[must_use]
    pub fn malformed(&self) -> DecisionOutcome {
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        DecisionOutcome::new(
            DecisionVerdict::deny(DecisionReason::MalformedOperation, Vec::new()),
            decision_id,
            None,
            None,
        )
    }

    async fn decide_check(
        &self,
        tokens: &dyn TokenRepository,
        credential: &Credential,
        check: &AccessCheck,
    ) -> Decided {
        match tokens.resolve(credential).await {
            Ok(identity) => self.decide_subject(subject_of(&identity), check).await,
            Err(rejection) => Decided::of(
                DecisionVerdict::deny(DecisionReason::from(rejection), Vec::new()),
                None,
                None,
            ),
        }
    }

    async fn decide_subject(&self, subject: SubjectRef, check: &AccessCheck) -> Decided {
        let catalog = match self.catalogs.load(check.service()).await {
            Ok(Some(catalog)) => catalog,
            Ok(None) => {
                return Decided::of(
                    DecisionVerdict::deny(DecisionReason::UnknownService, Vec::new()),
                    Some(subject),
                    None,
                );
            }
            Err(_unavailable) => return Decided::unavailable(Some(subject)),
        };
        let required = match RequiredKeyResolver::resolve(check, &catalog) {
            Ok(required) => required,
            Err(verdict) => {
                return Decided::of(verdict, Some(subject), Some(catalog.policy_version()));
            }
        };
        self.decide_policy(subject, &required, check.project())
            .await
    }

    /// Reads the policy of `subject` and decides `required` against it.
    async fn decide_policy(
        &self,
        subject: SubjectRef,
        required: &[RequiredKey],
        project: Option<ProjectId>,
    ) -> Decided {
        match self.policy.read_subject_policy(&subject).await {
            Ok(policy) => {
                let request = DecisionRequest {
                    assignments: policy.assignments(),
                    role_sets: policy.role_sets(),
                    required,
                    project,
                    now: self.clock.now(),
                };
                let verdict = DecisionPolicy::decide(&request);
                let wildcard = verdict.decision().is_allow()
                    && DecisionPolicy::holds_through_wildcard(&request);
                let trace = DecisionTrace::of_required(required).with_wildcard(wildcard);
                Decided::of(verdict, Some(subject), Some(policy.policy_version())).traced(trace)
            }
            Err(_unavailable) => Decided::unavailable(Some(subject)),
        }
    }
}

/// The subject a verified token proves.
fn subject_of(identity: &TokenIdentity) -> SubjectRef {
    match identity.subject() {
        SubjectId::User(id) => SubjectRef::user(*id),
        SubjectId::Service(name) => SubjectRef::service(name.clone()),
    }
}

#[cfg(test)]
mod tests;
