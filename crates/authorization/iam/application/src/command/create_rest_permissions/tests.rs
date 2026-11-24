use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, ChangeId, ChangeStatement, ContentHash, DecisionEffect, EntityVersion,
    GrantRecord, GrantStatus, HttpMethod, IdempotencyKey, IdempotencyRequest, OpenApiSpec,
    OpenApiSpecContent, OpenApiSpecParts, OpenApiSpecStatement, PathTemplate, PermissionFlags,
    PermissionId, PermissionKey, PermissionKeyKind, PolicyVersion, RequestDigest, RestOperation,
    RestOperationSet, RestPermission, RoleId, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{
    CreateRestPermissionsCommand, CreateRestPermissionsCommandHandler, RestActivationReads,
};
use crate::error::{Confirmation, IamError};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const PLAIN: PermissionFlags = PermissionFlags::NONE;

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn spec_id(number: u8) -> SpecId {
    SpecId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-1234567890{number:02x}")).unwrap()
}

fn role_id(number: u8) -> RoleId {
    RoleId::parse(&format!("0190f2a8-7b3c-7d4e-8f11-1234567890{number:02x}")).unwrap()
}

fn key(text: &str) -> PermissionKey {
    PermissionKey::parse(text).unwrap()
}

fn operations(items: &[(HttpMethod, &str, PermissionFlags)]) -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for (method, path, flags) in items {
        set.insert(RestOperation {
            method: *method,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: *flags,
        })
        .unwrap();
    }
    set
}

fn spec(
    number: u8,
    status: SpecStatus,
    items: &[(HttpMethod, &str, PermissionFlags)],
) -> OpenApiSpecStatement {
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(number),
        content: OpenApiSpecContent {
            service: service(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            operations: operations(items),
        },
        status,
        uploaded_by: actor(),
        created_at: at(),
        activated_at: (status != SpecStatus::Draft).then_some(at()),
        retired_at: None,
    });
    OpenApiSpecStatement::insert(&spec, format!("document {number}"))
}

fn command(number: u8) -> CreateRestPermissionsCommand {
    CreateRestPermissionsCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        actor: actor(),
        spec_id: spec_id(number),
        renames: Vec::new(),
        confirm_orphans: false,
        confirm_flag_downgrade: false,
        idempotency: None,
    }
}

fn grant(role: u8, text: &str, status: GrantStatus) -> GrantRecord {
    GrantRecord {
        role: role_id(role),
        key: key(text),
        status,
    }
}

/// The doubles of one scenario.
struct World {
    specs: FakeOpenApiSpecRepository,
    permissions: FakeRestPermissionRepository,
    roles: FakeRoleRepository,
    epochs: FakePolicyEpochRepository,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

impl World {
    fn new(specs: &[OpenApiSpecStatement]) -> Self {
        let repository = FakeOpenApiSpecRepository::new();
        for statement in specs {
            repository.save(statement).unwrap();
        }
        Self {
            specs: repository,
            permissions: FakeRestPermissionRepository::new(),
            roles: FakeRoleRepository::new(),
            epochs: FakePolicyEpochRepository::new(),
            unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        }
    }

    fn stored_entry(&self, number: u8, text: &str, flags: PermissionFlags, active: bool) {
        let id = PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}"))
            .unwrap();
        let mut entry = RestPermission::create(id, key(text), flags).unwrap();
        if !active {
            entry.deactivate();
        }
        self.permissions.insert(&entry).unwrap();
    }

    fn handler(self) -> (CreateRestPermissionsCommandHandler, Arc<FakeIamUnitOfWork>) {
        let unit_of_work = Arc::clone(&self.unit_of_work);
        let reads = RestActivationReads {
            specs: Arc::new(self.specs),
            permissions: Arc::new(self.permissions),
            roles: Arc::new(self.roles),
            policy_epochs: Arc::new(self.epochs),
        };
        let handler = CreateRestPermissionsCommandHandler::new(
            reads,
            self.unit_of_work,
            Arc::new(FixedClock::at(at())),
            Arc::new(SequenceUuidGenerator::starting_at(1)),
        );
        (handler, unit_of_work)
    }
}

fn catalogue_statement(unit_of_work: &FakeIamUnitOfWork) -> iam_domain::CatalogueStatementParts {
    let committed = unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let [
        ChangeStatement::ExpectPolicyVersion(_),
        ChangeStatement::ApplyCatalogue(statement),
    ] = change.parts().statements.as_slice()
    else {
        panic!("the guard and the catalogue statement expected");
    };
    statement.parts().clone()
}

fn event_types(unit_of_work: &FakeIamUnitOfWork) -> Vec<String> {
    unit_of_work.committed()[0]
        .parts()
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str().to_owned())
        .collect()
}

const INVOICES: (HttpMethod, &str, PermissionFlags) = (HttpMethod::Get, "/invoices", PLAIN);
const PAY: (HttpMethod, &str, PermissionFlags) =
    (HttpMethod::Post, "/invoices/{id}/pay", SENSITIVE);
const ORDERS: (HttpMethod, &str, PermissionFlags) = (HttpMethod::Get, "/orders", PLAIN);

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(
        CreateRestPermissionsCommand::NAME,
        "CreateRestPermissionsCommand"
    );
}

#[tokio::test]
async fn a_draft_is_activated_with_the_keys_of_its_operations_as_one_change() {
    let world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES, PAY])]);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let committed = unit_of_work.committed();
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command(1).change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    assert_eq!(parts.audit.parts().outcome, AuditOutcome::Committed);
    assert_eq!(parts.audit.parts().action.as_str(), "openapi_spec.activate");
    assert_eq!(parts.audit.parts().target.target_type(), "openapi_spec");
    assert_eq!(unit_of_work.policy_version(), 1);
    assert_eq!(
        parts.statements[0],
        ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(0).unwrap())
    );
    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.kind, PermissionKeyKind::Rest);
    assert_eq!(statement.service, service());
    assert_eq!(statement.transition.spec_id, spec_id(1));
    assert_eq!(statement.transition.from, SpecStatus::Draft);
    assert_eq!(statement.transition.to, SpecStatus::Active);
    assert_eq!(statement.transition.activated_at, Some(at()));
    assert_eq!(statement.at, at());
    let created: Vec<(String, PermissionFlags)> = statement
        .created
        .iter()
        .map(|entry| (entry.key.to_string(), entry.flags))
        .collect();
    assert_eq!(
        created,
        vec![
            ("rest:billing:GET /invoices".to_owned(), PLAIN),
            ("rest:billing:POST /invoices/{}/pay".to_owned(), SENSITIVE),
        ]
    );
    assert_eq!(statement.reflagged, Vec::<iam_domain::EntryFlags>::new());
    assert_eq!(statement.reactivated, Vec::<PermissionKey>::new());
    assert_eq!(statement.deactivated, Vec::<PermissionKey>::new());
    assert_eq!(statement.orphaned, Vec::<iam_domain::OrphanedGrant>::new());
    assert_eq!(event_types(&unit_of_work), ["iam.rest_permissions.created"]);
}

#[tokio::test]
async fn the_new_entries_get_identifiers_from_the_generator() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Draft, &[INVOICES, ORDERS])]).handler();

    handler.handle(command(1)).await.unwrap();

    let ids: std::collections::BTreeSet<PermissionId> = catalogue_statement(&unit_of_work)
        .created
        .iter()
        .map(|entry| entry.id)
        .collect();
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn an_active_version_is_a_no_op_that_commits_nothing() {
    let (handler, unit_of_work) = World::new(&[spec(1, SpecStatus::Active, &[INVOICES])]).handler();

    handler.handle(command(1)).await.unwrap();

    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
    assert_eq!(unit_of_work.policy_version(), 0);
}

#[tokio::test]
async fn an_unknown_version_is_not_found() {
    let (handler, unit_of_work) = World::new(&[]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_retired_version_cannot_be_activated() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Retired, &[INVOICES])]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_second_active_version_creates_only_the_keys_the_first_lacks() {
    let world = World::new(&[
        spec(1, SpecStatus::Active, &[INVOICES]),
        spec(2, SpecStatus::Draft, &[INVOICES, ORDERS]),
    ]);
    world.stored_entry(1, "rest:billing:GET /invoices", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(2)).await.unwrap();

    let created: Vec<String> = catalogue_statement(&unit_of_work)
        .created
        .iter()
        .map(|entry| entry.key.to_string())
        .collect();
    assert_eq!(created, ["rest:billing:GET /orders"]);
}

#[tokio::test]
async fn a_key_that_gains_a_flag_in_a_second_version_is_a_flag_change_that_is_not_a_downgrade() {
    let world = World::new(&[
        spec(
            1,
            SpecStatus::Active,
            &[(HttpMethod::Post, "/invoices/{id}/pay", PLAIN)],
        ),
        spec(2, SpecStatus::Draft, &[PAY]),
    ]);
    world.stored_entry(1, "rest:billing:POST /invoices/{}/pay", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(2)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.reflagged.len(), 1);
    assert_eq!(
        statement.reflagged[0].key,
        key("rest:billing:POST /invoices/{}/pay")
    );
    assert_eq!(statement.reflagged[0].flags, SENSITIVE);
    assert_eq!(statement.created, Vec::<iam_domain::EntryInsert>::new());
}

#[tokio::test]
async fn several_flag_changes_are_reflagged_in_key_order() {
    let sensitive_orders = (HttpMethod::Get, "/orders", SENSITIVE);
    let plain_pay = (HttpMethod::Post, "/invoices/{id}/pay", PLAIN);
    let world = World::new(&[
        spec(1, SpecStatus::Active, &[ORDERS, plain_pay]),
        spec(2, SpecStatus::Draft, &[sensitive_orders, PAY]),
    ]);
    world.stored_entry(1, "rest:billing:GET /orders", PLAIN, true);
    world.stored_entry(2, "rest:billing:POST /invoices/{}/pay", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(2)).await.unwrap();

    let reflagged: Vec<String> = catalogue_statement(&unit_of_work)
        .reflagged
        .iter()
        .map(|entry| entry.key.to_string())
        .collect();
    assert_eq!(
        reflagged,
        [
            "rest:billing:GET /orders",
            "rest:billing:POST /invoices/{}/pay"
        ]
    );
}

fn downgrading_world() -> World {
    let world = World::new(&[spec(
        1,
        SpecStatus::Draft,
        &[(HttpMethod::Post, "/invoices/{id}/pay", PLAIN)],
    )]);
    world.stored_entry(1, "rest:billing:POST /invoices/{}/pay", SENSITIVE, false);
    world
}

#[tokio::test]
async fn a_flag_downgrade_without_confirmation_lists_its_keys_and_commits_nothing() {
    let (handler, unit_of_work) = downgrading_world().handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    let IamError::ConfirmationRequired(Confirmation::FlagDowngrade, items) = error else {
        panic!("a flag downgrade confirmation expected: {error:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].property_path, "rest:billing:POST /invoices/{}/pay");
    assert_eq!(items[0].code, "flag_downgrade");
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_confirmed_flag_downgrade_reactivates_the_entry_with_its_new_flags() {
    let (handler, unit_of_work) = downgrading_world().handler();
    let confirmed = CreateRestPermissionsCommand {
        confirm_flag_downgrade: true,
        ..command(1)
    };

    handler.handle(confirmed).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(
        statement.reactivated,
        [key("rest:billing:POST /invoices/{}/pay")]
    );
    assert_eq!(statement.reflagged.len(), 1);
    assert_eq!(statement.reflagged[0].flags, PLAIN);
    assert_eq!(statement.created, Vec::<iam_domain::EntryInsert>::new());
    assert_eq!(event_types(&unit_of_work), ["iam.rest_permissions.created"]);
}

fn orphaning_world() -> World {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.roles = FakeRoleRepository::new().with_grant_records(vec![
        grant(1, "rest:billing:GET /old", GrantStatus::Active),
        grant(2, "rest:billing:GET /old", GrantStatus::Active),
        grant(2, "rest:billing:GET /gone", GrantStatus::Orphaned),
    ]);
    world
}

#[tokio::test]
async fn an_activation_that_orphans_grants_without_confirmation_lists_them() {
    let (handler, unit_of_work) = orphaning_world().handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    let IamError::ConfirmationRequired(Confirmation::Orphans, items) = error else {
        panic!("an orphan confirmation expected: {error:?}");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].property_path, "rest:billing:GET /old");
    assert_eq!(items[0].code, "orphaned_grant");
    assert!(items[0].message.contains(&role_id(1).to_string()));
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_confirmed_orphaning_activation_orphans_the_grants_and_records_both_events() {
    let (handler, unit_of_work) = orphaning_world().handler();
    let confirmed = CreateRestPermissionsCommand {
        confirm_orphans: true,
        ..command(1)
    };

    handler.handle(confirmed).await.unwrap();

    let orphaned: Vec<(RoleId, String)> = catalogue_statement(&unit_of_work)
        .orphaned
        .iter()
        .map(|grant| (grant.role, grant.key.to_string()))
        .collect();
    assert_eq!(
        orphaned,
        vec![
            (role_id(1), "rest:billing:GET /old".to_owned()),
            (role_id(2), "rest:billing:GET /old".to_owned()),
        ]
    );
    assert_eq!(
        event_types(&unit_of_work),
        ["iam.rest_permissions.created", "iam.permissions.orphaned"]
    );
}

#[tokio::test]
async fn a_rename_moves_the_grants_of_the_old_key_instead_of_orphaning_them() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.roles = FakeRoleRepository::new().with_grant_records(vec![grant(
        1,
        "rest:billing:GET /bills",
        GrantStatus::Active,
    )]);
    let (handler, unit_of_work) = world.handler();
    let renaming = CreateRestPermissionsCommand {
        renames: vec![(
            key("rest:billing:GET /bills"),
            key("rest:billing:GET /invoices"),
        )],
        ..command(1)
    };

    handler.handle(renaming).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.orphaned, Vec::<iam_domain::OrphanedGrant>::new());
    assert_eq!(statement.renames.len(), 1);
    assert_eq!(statement.renames[0].from, key("rest:billing:GET /bills"));
    assert_eq!(statement.renames[0].to, key("rest:billing:GET /invoices"));
    assert_eq!(statement.renames[0].roles, [role_id(1)]);
    assert_eq!(event_types(&unit_of_work), ["iam.rest_permissions.created"]);
}

#[tokio::test]
async fn a_rename_to_a_key_the_version_lacks_is_a_violation_of_renames() {
    let (handler, unit_of_work) = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]).handler();
    let renaming = CreateRestPermissionsCommand {
        renames: vec![(
            key("rest:billing:GET /bills"),
            key("rest:billing:GET /missing"),
        )],
        ..command(1)
    };

    let error = handler.handle(renaming).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a violation expected: {error:?}");
    };
    assert_eq!(violations[0].property_path, "renames");
    assert_eq!(violations[0].code, "rename");
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_rename_that_is_not_well_formed_is_a_violation_of_renames() {
    let (handler, _unit_of_work) = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]).handler();
    let renaming = CreateRestPermissionsCommand {
        renames: vec![(
            key("rest:billing:GET /invoices"),
            key("rest:billing:GET /invoices"),
        )],
        ..command(1)
    };

    let error = handler.handle(renaming).await.unwrap_err();

    assert!(matches!(error, IamError::Invalid(_)));
}

#[tokio::test]
async fn the_idempotency_key_is_kept_in_the_change_and_its_audit_record() {
    let (handler, unit_of_work) = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]).handler();
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("activate-1").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let keyed = CreateRestPermissionsCommand {
        idempotency: Some(request.clone()),
        ..command(1)
    };

    handler.handle(keyed).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn a_failing_version_repository_is_a_storage_failure() {
    let mut world = World::new(&[]);
    world.specs = FakeOpenApiSpecRepository::failing();
    let (handler, _unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_policy_epoch_is_a_storage_failure() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.epochs = FakePolicyEpochRepository::failing();
    let (handler, unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn a_failing_entry_repository_is_a_storage_failure() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.permissions = FakeRestPermissionRepository::failing();
    let (handler, _unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_role_repository_is_a_storage_failure() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.roles = FakeRoleRepository::failing();
    let (handler, _unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    world.unit_of_work = Arc::new(FakeIamUnitOfWork::failing());
    let (handler, _unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[tokio::test]
async fn a_policy_version_that_moved_since_it_was_read_refuses_the_change() {
    let mut world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]);
    let epoch = test_support::policy_epoch::seeded_policy_epoch();
    world.epochs = FakePolicyEpochRepository::holding(
        iam_domain::PolicyEpoch::new(
            PolicyVersion::new(5).unwrap(),
            epoch.digest(),
            epoch.log_epoch(),
            epoch.relay_epoch(),
            epoch.catalog_epoch(),
        )
        .unwrap(),
    );
    let (handler, unit_of_work) = world.handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(
        unit_of_work.committed(),
        Vec::<iam_domain::IamChange>::new()
    );
}

#[tokio::test]
async fn an_activation_asks_for_the_specification_scope_check_of_its_service() {
    let world = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES, PAY])]);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Spec {
            service: ServiceName::new("billing").unwrap(),
            flag_downgrade: false,
        })
    );
}

#[tokio::test]
async fn a_confirmed_flag_downgrade_asks_for_the_check_that_includes_the_downgrade() {
    let (handler, unit_of_work) = downgrading_world().handler();
    let confirmed = CreateRestPermissionsCommand {
        confirm_flag_downgrade: true,
        ..command(1)
    };

    handler.handle(confirmed).await.unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Spec {
            service: ServiceName::new("billing").unwrap(),
            flag_downgrade: true,
        })
    );
}
