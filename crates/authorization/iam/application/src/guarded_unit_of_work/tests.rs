use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::IamUnitOfWork as _;
use iam_domain::{
    ActorRef, AssignmentScope, AuditOutcome, ChangeStatement, CompiledRoleSet, DecisionEffect,
    GraphQlPermission, GuardCheck, IamChange, PermissionFlags, PermissionGrant, PermissionGrantSet,
    PermissionId, PermissionKey, PolicyVersion, ProjectId, RepositoryError, RestPermission,
    RoleAssignment, RoleId, RoleKind, RoleParts, SecurityAuditEvent, ServiceName, SubjectPolicy,
    SubjectRef, SystemComponent, WriteMode,
};
use shared_domain::Uuid;
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::role::{FakeRoleRepository, role};
use test_support::security_audit::FakeSecurityAuditLog;
use test_support::seed::TestRng;
use test_support::unit_of_work::{FakeIamUnitOfWork, audit_parts, iam_change, rebuilt};

use super::{GuardReads, GuardedUnitOfWork};

const ACTOR: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const GRANTOR_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-000000000a01";
const PAYER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-000000000a02";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f10-000000000b01";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> SubjectRef {
    SubjectRef::user(Uuid::parse(ACTOR).unwrap())
}

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn grant(text: &str) -> PermissionGrant {
    PermissionGrant::parse(text).unwrap()
}

/// The policy of an actor that holds `grants` through one assignment in `scope`.
fn policy_of(grants: &[&str], scope: AssignmentScope) -> SubjectPolicy {
    let role_id = RoleId::parse(GRANTOR_ROLE).unwrap();
    let set = CompiledRoleSet::from_active(
        &PermissionGrantSet::new(grants.iter().map(|text| grant(text))).unwrap(),
    );
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role_id, scope, None)],
        BTreeMap::from([(role_id, set)]),
    )
}

/// The stores that the unit of work reads, and what it wrote.
struct World {
    unit: GuardedUnitOfWork,
    committed: Arc<FakeIamUnitOfWork>,
    audit: Arc<FakeSecurityAuditLog>,
}

/// What the stores hold before the unit of work runs.
struct Setup {
    policy: Option<SubjectPolicy>,
    roles: Vec<RoleParts>,
    sensitive: Vec<&'static str>,
    sensitive_graphql: Vec<&'static str>,
    clock: SystemTime,
}

impl Setup {
    /// An actor that holds `grants` at global scope.
    fn holding(grants: &[&str]) -> Self {
        Self::with_policy(policy_of(grants, AssignmentScope::Global))
    }

    fn with_policy(policy: SubjectPolicy) -> Self {
        Self {
            policy: Some(policy),
            roles: Vec::new(),
            sensitive: Vec::new(),
            sensitive_graphql: Vec::new(),
            clock: now(),
        }
    }

    /// A role named Payer with the grants.
    fn with_payer_role(mut self, grants: &[&str]) -> Self {
        let mut parts = role(&mut TestRng::from_seed(7), "Payer", RoleKind::Custom)
            .parts()
            .clone();
        parts.id = RoleId::parse(PAYER_ROLE).unwrap();
        parts.grants = PermissionGrantSet::new(grants.iter().map(|text| grant(text))).unwrap();
        self.roles.push(parts);
        self
    }

    fn with_sensitive_rest_key(mut self, key: &'static str) -> Self {
        self.sensitive.push(key);
        self
    }

    fn with_sensitive_graphql_key(mut self, key: &'static str) -> Self {
        self.sensitive_graphql.push(key);
        self
    }

    /// A clock that reads `clock`.
    const fn at(mut self, clock: SystemTime) -> Self {
        self.clock = clock;
        self
    }

    fn build(self) -> World {
        let rest = FakeRestPermissionRepository::new();
        for (index, key) in self.sensitive.iter().enumerate() {
            let entry = RestPermission::create(
                PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-0000000001{index:02}"))
                    .unwrap(),
                PermissionKey::parse(key).unwrap(),
                PermissionFlags::NONE.with_sensitive(),
            )
            .unwrap();
            rest.insert(&entry).unwrap();
        }
        let graphql = FakeGraphQlPermissionRepository::new();
        for (index, key) in self.sensitive_graphql.iter().enumerate() {
            let entry = GraphQlPermission::create(
                PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-0000000002{index:02}"))
                    .unwrap(),
                PermissionKey::parse(key).unwrap(),
                PermissionFlags::NONE.with_sensitive(),
            )
            .unwrap();
            graphql.insert(&entry).unwrap();
        }
        let policy = self
            .policy
            .map_or_else(FakePolicyReadRepository::failing, |policy| {
                FakePolicyReadRepository::new().with_subject(actor(), policy)
            });
        let committed = Arc::new(FakeIamUnitOfWork::new());
        let audit = Arc::new(FakeSecurityAuditLog::new());
        let unit = GuardedUnitOfWork::new(
            Arc::<FakeIamUnitOfWork>::clone(&committed),
            GuardReads {
                policy: Arc::new(policy),
                roles: Arc::new(FakeRoleRepository::holding(self.roles)),
                rest_permissions: Arc::new(rest),
                graphql_permissions: Arc::new(graphql),
                audit_log: Arc::<FakeSecurityAuditLog>::clone(&audit),
            },
            Arc::new(FixedClock::at(self.clock)),
            Arc::new(SequenceUuidGenerator::starting_at(100)),
        );
        World {
            unit,
            committed,
            audit,
        }
    }
}

/// A change by `actor` that asks for `check`, or for none.
fn change_by(actor: ActorRef, check: Option<GuardCheck>) -> IamChange {
    let base = iam_change(&mut TestRng::from_seed(3), DecisionEffect::Affected, 0);
    let mut parts = audit_parts(&base);
    parts.actor = actor;
    parts.scope = None;
    parts.outcome = AuditOutcome::Committed;
    parts.reason = None;
    let audit = SecurityAuditEvent::record(parts).unwrap();
    let change = rebuilt(&base, |change| change.audit = audit);
    match check {
        Some(check) => change.with_guard(check),
        None => change,
    }
}

fn user_change(check: GuardCheck) -> IamChange {
    change_by(ActorRef::User(Uuid::parse(ACTOR).unwrap()), Some(check))
}

fn grants(texts: &[&str]) -> GuardCheck {
    GuardCheck::Grants(texts.iter().map(|text| grant(text)).collect())
}

fn assignment(subject: &str) -> GuardCheck {
    GuardCheck::Assignment {
        subject: SubjectRef::user(Uuid::parse(subject).unwrap()),
        role_id: RoleId::parse(PAYER_ROLE).unwrap(),
    }
}

fn spec(name: &str, flag_downgrade: bool) -> GuardCheck {
    GuardCheck::Spec {
        service: service(name),
        flag_downgrade,
    }
}

async fn commit(world: &World, change: IamChange) -> Result<(), RepositoryError> {
    world
        .unit
        .commit(change, WriteMode::Published)
        .await
        .map(|_receipt| ())
}

fn assert_refused(world: &World, result: &Result<(), RepositoryError>, reason: &str) {
    assert!(
        matches!(result, Err(RepositoryError::Forbidden)),
        "{result:?}"
    );
    assert_eq!(world.committed.committed(), Vec::<IamChange>::new());
    let recorded = world.audit.recorded();
    let [record] = recorded.as_slice() else {
        panic!("one rejected record expected: {recorded:?}");
    };
    let parts = record.event().parts();
    assert_eq!(parts.outcome, AuditOutcome::Rejected);
    assert_eq!(parts.reason.as_ref().unwrap().as_str(), reason);
    assert_eq!(parts.actor, ActorRef::User(Uuid::parse(ACTOR).unwrap()));
    assert_eq!(parts.occurred_at, now());
}

#[tokio::test]
async fn a_change_that_asks_for_no_check_commits_unchanged() {
    let world = Setup::holding(&[]).build();
    let change = change_by(ActorRef::User(Uuid::parse(ACTOR).unwrap()), None);

    commit(&world, change.clone()).await.unwrap();

    assert_eq!(world.committed.committed(), vec![change]);
    assert_eq!(
        world.audit.recorded(),
        Vec::<iam_domain::StoredSecurityAuditEvent>::new()
    );
}

#[tokio::test]
async fn an_iam_component_acts_without_a_check() {
    let world = Setup::holding(&[]).build();
    let change = change_by(
        ActorRef::System(SystemComponent::Startup),
        Some(spec("iam", false)),
    );

    commit(&world, change).await.unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn a_grant_by_an_actor_that_holds_the_key_of_the_service_commits_with_the_decided_version() {
    let world = Setup::holding(&["iam:grant:core"]).build();

    commit(&world, user_change(grants(&["rest:core:GET /users"])))
        .await
        .unwrap();

    let committed = world.committed.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected");
    };
    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::ExpectPolicyVersion(
            PolicyVersion::new(0).unwrap()
        )]
    );
    assert_eq!(
        world.audit.recorded(),
        Vec::<iam_domain::StoredSecurityAuditEvent>::new()
    );
}

#[tokio::test]
async fn a_grant_key_held_only_at_project_scope_is_refused_and_audited() {
    let project = ProjectId::parse(PROJECT).unwrap();
    let world = Setup::with_policy(policy_of(
        &["iam:grant:core"],
        AssignmentScope::Project(project),
    ))
    .build();

    let result = commit(&world, user_change(grants(&["rest:core:GET /users"]))).await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn a_sensitive_key_without_the_sensitive_grant_key_is_refused() {
    let world = Setup::holding(&["iam:grant:core"])
        .with_sensitive_rest_key("rest:core:POST /users/{}/ban")
        .build();

    let result = commit(
        &world,
        user_change(grants(&["rest:core:POST /users/{}/ban"])),
    )
    .await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn a_sensitive_graphql_key_without_the_sensitive_grant_key_is_refused() {
    let world = Setup::holding(&["iam:grant:core"])
        .with_sensitive_graphql_key("gql:core:Mutation.banUser")
        .build();

    let result = commit(
        &world,
        user_change(grants(&[
            "gql:core:Mutation.banUser",
            "gql:core:Query.users",
        ])),
    )
    .await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn a_sensitive_graphql_key_with_the_sensitive_grant_key_commits() {
    let world = Setup::holding(&["iam:grant:core", "iam:grant:sensitive"])
        .with_sensitive_graphql_key("gql:core:Mutation.banUser")
        .build();

    commit(&world, user_change(grants(&["gql:core:Mutation.banUser"])))
        .await
        .unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn a_reserved_key_among_the_grants_is_checked_without_a_catalogue_read() {
    let world = Setup::holding(&["iam:grant:core"]).build();

    let result = commit(&world, user_change(grants(&["iam:grant:core"]))).await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn a_refusal_whose_record_breaks_an_invariant_is_unavailable_and_commits_nothing() {
    let before_1970 = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();
    let world = Setup::holding(&["iam:grant:billing"])
        .at(before_1970)
        .build();

    let result = commit(&world, user_change(grants(&["rest:core:GET /users"]))).await;

    assert!(
        matches!(result, Err(RepositoryError::Unavailable(_))),
        "{result:?}"
    );
    assert_eq!(world.committed.committed(), Vec::<IamChange>::new());
    assert_eq!(
        world.audit.recorded(),
        Vec::<iam_domain::StoredSecurityAuditEvent>::new()
    );
}

#[tokio::test]
async fn a_sensitive_key_with_the_sensitive_grant_key_commits() {
    let world = Setup::holding(&["iam:grant:core", "iam:grant:sensitive"])
        .with_sensitive_rest_key("rest:core:POST /users/{}/ban")
        .build();

    commit(
        &world,
        user_change(grants(&["rest:core:POST /users/{}/ban"])),
    )
    .await
    .unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn a_wildcard_without_the_wildcard_grant_key_is_refused() {
    let world = Setup::holding(&["iam:grant:*"]).build();

    let result = commit(&world, user_change(grants(&["rest:core:*"]))).await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn assigning_a_role_that_grants_another_service_is_refused() {
    let world = Setup::holding(&["iam:grant:core"])
        .with_payer_role(&["rest:payment:GET /invoices"])
        .build();

    let result = commit(&world, user_change(assignment(SUBJECT))).await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn assigning_a_role_whose_keys_the_actor_may_grant_commits() {
    let world = Setup::holding(&["iam:grant:payment"])
        .with_payer_role(&["rest:payment:GET /invoices"])
        .build();

    commit(&world, user_change(assignment(SUBJECT)))
        .await
        .unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn an_assignment_whose_subject_is_the_actor_is_refused_whatever_it_holds() {
    let world = Setup::holding(&["iam:grant:*", "iam:grant:sensitive", "iam:grant:wildcard"])
        .with_payer_role(&["rest:payment:GET /invoices"])
        .build();

    let result = commit(&world, user_change(assignment(ACTOR))).await;

    assert_refused(&world, &result, "escalation.denied");
}

#[tokio::test]
async fn a_service_principal_cannot_assign_a_role_to_itself() {
    let principal = service("pipeline");
    let policy = FakePolicyReadRepository::new().with_subject(
        SubjectRef::service(principal.clone()),
        policy_of(&["iam:grant:*"], AssignmentScope::Global),
    );
    let committed = Arc::new(FakeIamUnitOfWork::new());
    let audit = Arc::new(FakeSecurityAuditLog::new());
    let unit = GuardedUnitOfWork::new(
        Arc::<FakeIamUnitOfWork>::clone(&committed),
        GuardReads {
            policy: Arc::new(policy),
            roles: Arc::new(FakeRoleRepository::new()),
            rest_permissions: Arc::new(FakeRestPermissionRepository::new()),
            graphql_permissions: Arc::new(FakeGraphQlPermissionRepository::new()),
            audit_log: Arc::<FakeSecurityAuditLog>::clone(&audit),
        },
        Arc::new(FixedClock::at(now())),
        Arc::new(SequenceUuidGenerator::starting_at(100)),
    );
    let check = GuardCheck::Assignment {
        subject: SubjectRef::service(principal.clone()),
        role_id: RoleId::parse(PAYER_ROLE).unwrap(),
    };

    let result = unit
        .commit(
            change_by(ActorRef::Service(principal), Some(check)),
            WriteMode::Published,
        )
        .await;

    assert!(matches!(result, Err(RepositoryError::Forbidden)));
    assert_eq!(committed.committed(), Vec::<IamChange>::new());
    assert_eq!(audit.recorded().len(), 1);
}

#[tokio::test]
async fn a_pipeline_with_the_spec_key_of_a_service_stores_its_version_and_no_other() {
    let world = Setup::holding(&["iam:spec:core"]).build();

    commit(&world, user_change(spec("core", false)))
        .await
        .unwrap();
    let refused = commit(&world, user_change(spec("payment", false))).await;

    assert!(matches!(refused, Err(RepositoryError::Forbidden)));
    assert_eq!(world.committed.committed().len(), 1);
    let recorded = world.audit.recorded();
    let [record] = recorded.as_slice() else {
        panic!("one rejected record expected: {recorded:?}");
    };
    assert_eq!(
        record.event().parts().reason.as_ref().unwrap().as_str(),
        "spec_scope.denied"
    );
}

#[tokio::test]
async fn the_global_spec_key_never_covers_the_iam_service() {
    let world = Setup::holding(&["iam:spec:*"]).build();

    let result = commit(&world, user_change(spec("iam", false))).await;

    assert_refused(&world, &result, "spec_scope.denied");
}

#[tokio::test]
async fn the_iam_spec_key_covers_the_iam_service() {
    let world = Setup::holding(&["iam:spec:iam"]).build();

    commit(&world, user_change(spec("iam", false)))
        .await
        .unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn a_confirmed_flag_downgrade_without_the_sensitive_grant_key_is_refused() {
    let world = Setup::holding(&["iam:spec:core"]).build();

    let result = commit(&world, user_change(spec("core", true))).await;

    assert_refused(&world, &result, "spec_scope.denied");
}

#[tokio::test]
async fn a_confirmed_flag_downgrade_with_the_sensitive_grant_key_commits() {
    let world = Setup::holding(&["iam:spec:core", "iam:grant:sensitive"]).build();

    commit(&world, user_change(spec("core", true)))
        .await
        .unwrap();

    assert_eq!(world.committed.committed().len(), 1);
}

#[tokio::test]
async fn a_policy_that_cannot_be_read_fails_the_change_without_a_refusal_record() {
    let mut setup = Setup::holding(&[]);
    setup.policy = None;
    let world = setup.build();

    let result = commit(&world, user_change(spec("core", false))).await;

    assert!(matches!(result, Err(RepositoryError::Unavailable(_))));
    assert_eq!(world.committed.committed(), Vec::<IamChange>::new());
    assert_eq!(
        world.audit.recorded(),
        Vec::<iam_domain::StoredSecurityAuditEvent>::new()
    );
}

#[tokio::test]
async fn a_refusal_that_cannot_be_recorded_fails_the_change() {
    let committed = Arc::new(FakeIamUnitOfWork::new());
    let unit = GuardedUnitOfWork::new(
        Arc::<FakeIamUnitOfWork>::clone(&committed),
        GuardReads {
            policy: Arc::new(FakePolicyReadRepository::new()),
            roles: Arc::new(FakeRoleRepository::new()),
            rest_permissions: Arc::new(FakeRestPermissionRepository::new()),
            graphql_permissions: Arc::new(FakeGraphQlPermissionRepository::new()),
            audit_log: Arc::new(FakeSecurityAuditLog::failing()),
        },
        Arc::new(FixedClock::at(now())),
        Arc::new(SequenceUuidGenerator::starting_at(100)),
    );

    let result = unit
        .commit(user_change(spec("core", false)), WriteMode::Published)
        .await;

    assert!(matches!(result, Err(RepositoryError::Unavailable(_))));
    assert_eq!(committed.committed(), Vec::<IamChange>::new());
}
