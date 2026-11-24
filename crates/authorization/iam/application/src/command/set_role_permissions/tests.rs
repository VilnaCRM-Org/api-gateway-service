use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, AuditSummary, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    GraphQlPermission, GraphQlPermissionRepository, IamUnitOfWork, IdempotencyKey,
    IdempotencyRequest, PermissionFlags, PermissionGrant, PermissionGrantSet, PermissionId,
    PermissionKey, RequestDigest, RestPermission, RestPermissionRepository, RoleId, RoleKind,
    RoleName, RoleParts, RoleRepository,
};
use shared_application::http::Violation;
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{SetRolePermissionsCommand, SetRolePermissionsCommandHandler, SetRolePermissionsReads};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn grant(text: &str) -> PermissionGrant {
    PermissionGrant::parse(text).unwrap()
}

fn stored(kind: RoleKind, version: i64, grants: &[&str]) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: None,
        kind,
        grants: PermissionGrantSet::new(grants.iter().map(|text| grant(text))).unwrap(),
        version: EntityVersion::new(version).unwrap(),
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

fn command(expected: i64, keys: &[&str]) -> SetRolePermissionsCommand {
    SetRolePermissionsCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        role_id: RoleId::parse(ROLE).unwrap(),
        actor: actor(),
        expected: EntityVersion::new(expected).unwrap(),
        keys: keys.iter().map(|text| (*text).to_owned()).collect(),
        idempotency: None,
    }
}

/// The catalogues of the world: `billing` holds one active and one inactive REST operation and one
/// active GraphQL field; `orders` holds one active REST operation.
struct World {
    graphql: FakeGraphQlPermissionRepository,
    rest: FakeRestPermissionRepository,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

impl World {
    fn new() -> Self {
        let world = Self {
            graphql: FakeGraphQlPermissionRepository::new(),
            rest: FakeRestPermissionRepository::new(),
            unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        };
        world.rest_entry(1, "rest:billing:GET /invoices", true);
        world.rest_entry(2, "rest:billing:DELETE /invoices/{}", false);
        world.rest_entry(3, "rest:orders:GET /orders", true);
        world.graphql_entry(4, "gql:billing:Query.invoices");
        world
    }

    fn rest_entry(&self, number: u8, text: &str, active: bool) {
        let id = PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}"))
            .unwrap();
        let mut entry = RestPermission::create(
            id,
            PermissionKey::parse(text).unwrap(),
            PermissionFlags::NONE,
        )
        .unwrap();
        if !active {
            entry.deactivate();
        }
        self.rest.insert(&entry).unwrap();
    }

    fn graphql_entry(&self, number: u8, text: &str) {
        let id = PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}"))
            .unwrap();
        let entry = GraphQlPermission::create(
            id,
            PermissionKey::parse(text).unwrap(),
            PermissionFlags::NONE,
        )
        .unwrap();
        self.graphql.insert(&entry).unwrap();
    }

    fn handler(
        self,
        roles: Vec<RoleParts>,
    ) -> (SetRolePermissionsCommandHandler, Arc<FakeIamUnitOfWork>) {
        let unit_of_work = Arc::clone(&self.unit_of_work);
        let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::holding(roles));
        let graphql: Arc<dyn GraphQlPermissionRepository> = Arc::new(self.graphql);
        let rest: Arc<dyn RestPermissionRepository> = Arc::new(self.rest);
        let work: Arc<dyn IamUnitOfWork> = self.unit_of_work;
        let handler = SetRolePermissionsCommandHandler::new(
            SetRolePermissionsReads {
                roles,
                graphql_permissions: graphql,
                rest_permissions: rest,
            },
            work,
            Arc::new(FixedClock::at(at())),
            Arc::new(SequenceUuidGenerator::starting_at(1)),
        );
        (handler, unit_of_work)
    }
}

fn violations(error: IamError) -> Vec<Violation> {
    let IamError::Invalid(violations) = error else {
        panic!("invalid values expected: {error:?}");
    };
    violations
}

fn paths(violations: &[Violation]) -> Vec<&str> {
    violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect()
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(SetRolePermissionsCommand::NAME, "SetRolePermissionsCommand");
}

#[tokio::test]
async fn keys_of_two_services_replace_the_grants_in_one_guarded_update_that_affects_decisions() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    handler
        .handle(command(
            1,
            &[
                "rest:orders:GET /orders",
                "gql:billing:Query.invoices",
                "rest:billing:GET /invoices",
            ],
        ))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [ChangeStatement::SaveRole(statement)] = parts.statements.as_slice() else {
        panic!("one role update expected: {:?}", parts.statements);
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    assert_eq!(statement.role().grants.len(), 3);
    assert_eq!(statement.role().version, EntityVersion::new(2).unwrap());
    assert_eq!(statement.role().updated_at, at());
    assert_eq!(statement.actor(), &actor());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.role_permissions.changed"]);
}

#[tokio::test]
async fn the_replacement_carries_the_added_and_the_removed_keys_in_its_event() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(
        RoleKind::Custom,
        3,
        &["rest:orders:GET /orders", "rest:billing:GET /invoices"],
    )]);

    handler
        .handle(command(
            3,
            &["rest:billing:GET /invoices", "gql:billing:Query.invoices"],
        ))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveRole(statement)] = committed[0].parts().statements.as_slice() else {
        panic!("one role update expected");
    };
    let kept: Vec<String> = statement
        .role()
        .grants
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        kept,
        ["rest:billing:GET /invoices", "gql:billing:Query.invoices"]
    );
    let event = format!("{:?}", committed[0].parts().events[0]);
    assert!(event.contains("gql:billing:Query.invoices"), "{event}");
    assert!(event.contains("rest:orders:GET /orders"), "{event}");
}

#[tokio::test]
async fn an_empty_replacement_removes_every_grant() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(
        RoleKind::Custom,
        2,
        &["rest:billing:GET /invoices"],
    )]);

    handler.handle(command(2, &[])).await.unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveRole(statement)] = committed[0].parts().statements.as_slice() else {
        panic!("one role update expected");
    };
    assert!(statement.role().grants.is_empty());
}

#[tokio::test]
async fn a_repeated_key_counts_once() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    handler
        .handle(command(
            1,
            &["rest:billing:GET /invoices", "rest:billing:GET /invoices"],
        ))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let [ChangeStatement::SaveRole(statement)] = committed[0].parts().statements.as_slice() else {
        panic!("one role update expected");
    };
    assert_eq!(statement.role().grants.len(), 1);
}

#[tokio::test]
async fn a_wildcard_of_a_service_with_a_catalogue_is_audited_as_covering_future_elements() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    handler
        .handle(command(1, &["gql:billing:*", "rest:orders:GET *"]))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    let after = audit.after.as_ref().map(AuditSummary::as_str).unwrap();
    assert_eq!(
        after,
        "grants=2 added=2 removed=0 version=2 coversFutureElements=true wildcards=2 [gql:billing:*,rest:orders:GET *]"
    );
}

#[tokio::test]
async fn an_audit_record_that_adds_no_wildcard_does_not_cover_future_elements() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    handler
        .handle(command(1, &["rest:billing:GET /invoices"]))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "role.permissions.set");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "role");
    assert_eq!(audit.target.target_id(), ROLE);
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("grants=0 version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("grants=1 added=1 removed=0 version=2")
    );
}

#[tokio::test]
async fn the_audit_record_lists_the_first_wildcards_and_counts_them_all() {
    let keys: Vec<String> = (0..20)
        .map(|number| format!("gql:billing:Type{number}.*"))
        .collect();
    let texts: Vec<&str> = keys.iter().map(String::as_str).collect();
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    handler.handle(command(1, &texts)).await.unwrap();

    let committed = unit_of_work.committed();
    let after = committed[0].parts().audit.parts().after.as_ref().unwrap();
    assert!(
        after.as_str().contains("wildcards=20 ["),
        "{}",
        after.as_str()
    );
    assert!(after.as_str().contains("gql:billing:Type0.*"));
    assert!(!after.as_str().contains("gql:billing:Type9.*"));
}

#[tokio::test]
async fn a_system_role_is_forbidden_and_nothing_is_committed() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(
        RoleKind::System,
        1,
        &["rest:billing:GET /invoices"],
    )]);

    let error = handler
        .handle(command(1, &["rest:orders:GET /orders"]))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_system_role_is_forbidden_before_its_keys_are_validated() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::System, 1, &[])]);

    let error = handler
        .handle(command(1, &["rest:billing:GET /missing", "not a key"]))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_system_role_is_forbidden_even_with_a_stale_version() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::System, 5, &[])]);

    let error = handler.handle(command(1, &[])).await.unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_idempotency_key_and_digest_travel_with_the_change() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("grant-billing").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let command = SetRolePermissionsCommand {
        idempotency: Some(request.clone()),
        ..command(1, &[])
    };

    handler.handle(command).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn one_violation_names_each_key_that_no_active_catalogue_holds() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    let error = handler
        .handle(command(
            1,
            &[
                "rest:billing:GET /invoices",
                "rest:billing:DELETE /invoices/{}",
                "gql:billing:Query.missing",
                "rest:unknown:GET /x",
                "iam:grant:sensitive",
            ],
        ))
        .await
        .unwrap_err();

    let violations = violations(error);
    assert_eq!(
        paths(&violations),
        ["keys[1]", "keys[2]", "keys[3]", "keys[4]"]
    );
    assert!(
        violations
            .iter()
            .all(|violation| violation.code == "exists")
    );
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_text_that_is_not_a_grant_is_a_violation_of_its_position() {
    let (handler, _unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    let error = handler
        .handle(command(
            1,
            &[
                "rest:billing:GET /invoices",
                "not a key",
                "rest:orders:GET /missing",
            ],
        ))
        .await
        .unwrap_err();

    let violations = violations(error);
    assert_eq!(paths(&violations), ["keys[1]", "keys[2]"]);
    assert_eq!(violations[0].code, "kind");
    assert_eq!(violations[1].code, "exists");
}

#[tokio::test]
async fn a_wildcard_of_a_service_without_a_catalogue_is_a_violation() {
    let (handler, _unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);

    let error = handler
        .handle(command(
            1,
            &["gql:billing:*", "gql:nowhere:*", "rest:nowhere:GET *"],
        ))
        .await
        .unwrap_err();

    let violations = violations(error);
    assert_eq!(paths(&violations), ["keys[1]", "keys[2]"]);
    assert_eq!(
        violations[0].message,
        "This service has no permission catalogue."
    );
}

#[tokio::test]
async fn more_than_five_thousand_keys_are_one_violation_of_the_collection() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 1, &[])]);
    let keys: Vec<String> = (0..=5_000)
        .map(|n| format!("rest:billing:GET /a{n}"))
        .collect();
    let texts: Vec<&str> = keys.iter().map(String::as_str).collect();

    let error = handler.handle(command(1, &texts)).await.unwrap_err();

    let violations = violations(error);
    assert_eq!(paths(&violations), ["keys"]);
    assert_eq!(violations[0].code, "count");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(RoleKind::Custom, 2, &[])]);

    let error = handler.handle(command(1, &[])).await.unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_unknown_role_is_not_found() {
    let (handler, unit_of_work) = World::new().handler(Vec::new());

    let error = handler.handle(command(1, &[])).await.unwrap_err();

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_role_repository_is_a_storage_error() {
    let world = World::new();
    let work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&world.unit_of_work);
    let handler = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles: Arc::new(FakeRoleRepository::failing()),
            graphql_permissions: Arc::new(world.graphql),
            rest_permissions: Arc::new(world.rest),
        },
        work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command(1, &[])).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_catalogue_is_a_storage_error() {
    let world = World::new();
    let work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&world.unit_of_work);
    let roles: Arc<dyn RoleRepository> = Arc::new(FakeRoleRepository::holding(vec![stored(
        RoleKind::Custom,
        1,
        &[],
    )]));
    let rest: Arc<dyn RestPermissionRepository> = Arc::new(FakeRestPermissionRepository::failing());
    let handler = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles: Arc::clone(&roles),
            graphql_permissions: Arc::new(world.graphql),
            rest_permissions: rest,
        },
        Arc::clone(&work),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let wildcard = handler
        .handle(command(1, &["rest:billing:*"]))
        .await
        .unwrap_err();
    let exact = handler
        .handle(command(1, &["rest:billing:GET /invoices"]))
        .await
        .unwrap_err();
    let graphql: Arc<dyn GraphQlPermissionRepository> =
        Arc::new(FakeGraphQlPermissionRepository::failing());
    let failing_graphql = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles,
            graphql_permissions: Arc::clone(&graphql),
            rest_permissions: Arc::new(world.rest),
        },
        work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let by_graphql = failing_graphql
        .handle(command(1, &["gql:billing:Query.invoices"]))
        .await
        .unwrap_err();
    let graphql_wildcard = failing_graphql
        .handle(command(1, &["rest:nowhere:*"]))
        .await;

    assert!(matches!(wildcard, IamError::Storage(_)));
    assert!(matches!(exact, IamError::Storage(_)));
    assert!(matches!(by_graphql, IamError::Storage(_)));
    assert!(matches!(graphql_wildcard, Err(IamError::Storage(_))));
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_error() {
    let world = World::new();
    let handler = SetRolePermissionsCommandHandler::new(
        SetRolePermissionsReads {
            roles: Arc::new(FakeRoleRepository::holding(vec![stored(
                RoleKind::Custom,
                1,
                &[],
            )])),
            graphql_permissions: Arc::new(world.graphql),
            rest_permissions: Arc::new(world.rest),
        },
        Arc::new(FakeIamUnitOfWork::failing()),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command(1, &[])).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn the_replacement_asks_for_the_escalation_check_of_the_added_grants_only() {
    let (handler, unit_of_work) = World::new().handler(vec![stored(
        RoleKind::Custom,
        1,
        &["rest:orders:GET /orders"],
    )]);

    handler
        .handle(command(
            1,
            &["rest:orders:GET /orders", "rest:billing:GET /invoices"],
        ))
        .await
        .unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Grants(vec![
            PermissionGrant::parse("rest:billing:GET /invoices").unwrap()
        ]))
    );
}
