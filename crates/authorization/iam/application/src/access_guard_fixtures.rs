//! A guard over a fake policy, for the tests of the resolvers that repeat the caller rule.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use iam_domain::{
    AssignmentScope, CompiledRoleSet, GrantStatus, PermissionGrant, PolicyReadRepository,
    RoleAssignment, RoleId, ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
};
use shared_domain::Uuid;
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;

use crate::access_decision_service::AccessDecisionService;
use crate::command::record_rejected_attempt::RecordRejectedAttemptCommand;
use crate::error::IamError;
use crate::fixtures::USER;
use crate::graphql::authorization::CallerRuleCheck;
use crate::iam_access_guard::IamAccessGuard;
use crate::service_catalog_loader::ServiceCatalogLoader;

/// The refusals that a guard offered to the audit log.
pub(crate) type Recorded = Arc<Mutex<Vec<RecordRejectedAttemptCommand>>>;

/// The caller rule over a user (the one of `fixtures::principal`) who holds `grants` globally.
pub(crate) fn caller_check(grants: &[&str]) -> (CallerRuleCheck, Recorded) {
    let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
    let compiled = CompiledRoleSet::compile(
        grants
            .iter()
            .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active)),
    );
    let subject = SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role, AssignmentScope::Global, None)],
        BTreeMap::from([(role, compiled)]),
    );
    let catalog = ServiceCatalog::new(
        ServiceName::iam().clone(),
        seeded_policy_epoch(),
        Vec::new(),
        Vec::new(),
    );
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(
        FakePolicyReadRepository::new()
            .with_catalog(catalog)
            .with_subject(SubjectRef::user(Uuid::parse(USER).unwrap()), subject),
    );
    let decisions = AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(std::time::SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let recorded: Recorded = Arc::default();
    let sink = Arc::clone(&recorded);
    let bus = FakeCommandBus::handling::<RecordRejectedAttemptCommand, _>(move |command| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        Ok::<(), IamError>(())
    });
    let guard = Arc::new(IamAccessGuard::new(Arc::new(decisions), Arc::new(bus)));
    (CallerRuleCheck::new(guard), recorded)
}

/// The audit actions of the refusals that a guard offered, in order.
pub(crate) fn refused_actions(recorded: &Recorded) -> Vec<String> {
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|command| command.action.as_str().to_owned())
        .collect()
}
