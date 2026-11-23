//! The decision path of FR-6 and FR-13, shared by every caller of an access check.

use std::sync::Arc;

use iam_domain::{
    AccessCheck, Credential, DecisionId, DecisionOutcome, DecisionPolicy, DecisionReason,
    DecisionRequest, DecisionVerdict, PolicyReadRepository, PolicyVersion, SubjectId, SubjectRef,
    TokenIdentity, TokenRepository,
};
use shared_domain::{Clock, UuidGenerator};

use crate::required_key_resolver::RequiredKeyResolver;
use crate::service_catalog_loader::ServiceCatalogLoader;

/// What a decision knows besides the verdict.
struct Decided {
    verdict: DecisionVerdict,
    subject: Option<SubjectRef>,
    policy_version: Option<PolicyVersion>,
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
        }
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
        let decision_id = DecisionId::from_uuid(self.ids.generate());
        let decided = self.decide_check(credential, check).await;
        DecisionOutcome::new(
            decided.verdict,
            decision_id,
            decided.subject,
            decided.policy_version,
        )
    }

    async fn decide_check(&self, credential: &Credential, check: &AccessCheck) -> Decided {
        match self.tokens.resolve(credential).await {
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
        match self.policy.read_subject_policy(&subject).await {
            Ok(policy) => {
                let verdict = DecisionPolicy::decide(&DecisionRequest {
                    assignments: policy.assignments(),
                    role_sets: policy.role_sets(),
                    required: &required,
                    project: check.project(),
                    now: self.clock.now(),
                });
                Decided::of(verdict, Some(subject), Some(policy.policy_version()))
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
