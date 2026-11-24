use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, ChangeId, ChangeStatement, ContentHash, DecisionEffect, EntityVersion,
    GrantRecord, GrantStatus, HttpMethod, IdempotencyKey, IdempotencyRequest, OpenApiSpec,
    OpenApiSpecContent, OpenApiSpecParts, OpenApiSpecStatement, PathTemplate, PermissionFlags,
    PermissionId, PermissionKey, PermissionKeyKind, PolicyVersion, RequestDigest, RestOperation,
    RestOperationSet, RestPermission, RoleId, ServiceName, SpecId, SpecStatus, SystemComponent,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::openapi_spec::FakeOpenApiSpecRepository;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::rest_permission::FakeRestPermissionRepository;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{RetireOpenApiSpecCommand, RetireOpenApiSpecCommandHandler};
use crate::command::create_rest_permissions::RestActivationReads;
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
    spec_of(service(), number, status, items)
}

fn spec_of(
    service: ServiceName,
    number: u8,
    status: SpecStatus,
    items: &[(HttpMethod, &str, PermissionFlags)],
) -> OpenApiSpecStatement {
    let spec = OpenApiSpec::restore(OpenApiSpecParts {
        id: spec_id(number),
        content: OpenApiSpecContent {
            service,
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

fn command(number: u8) -> RetireOpenApiSpecCommand {
    RetireOpenApiSpecCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        actor: actor(),
        spec_id: spec_id(number),
        confirm_orphans: false,
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

    fn handler(self) -> (RetireOpenApiSpecCommandHandler, Arc<FakeIamUnitOfWork>) {
        let unit_of_work = Arc::clone(&self.unit_of_work);
        let reads = RestActivationReads {
            specs: Arc::new(self.specs),
            permissions: Arc::new(self.permissions),
            roles: Arc::new(self.roles),
            policy_epochs: Arc::new(self.epochs),
        };
        let handler = RetireOpenApiSpecCommandHandler::new(
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

fn keys(keys: &[PermissionKey]) -> Vec<String> {
    keys.iter().map(ToString::to_string).collect()
}

const INVOICES: (HttpMethod, &str, PermissionFlags) = (HttpMethod::Get, "/invoices", PLAIN);
const PAY: (HttpMethod, &str, PermissionFlags) =
    (HttpMethod::Post, "/invoices/{id}/pay", SENSITIVE);

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(RetireOpenApiSpecCommand::NAME, "RetireOpenApiSpecCommand");
}

#[tokio::test]
async fn an_active_version_is_retired_and_its_entries_are_deactivated_as_one_change() {
    let world = World::new(&[spec(1, SpecStatus::Active, &[INVOICES, PAY])]);
    world.stored_entry(1, "rest:billing:GET /invoices", PLAIN, true);
    world.stored_entry(2, "rest:billing:POST /invoices/{}/pay", SENSITIVE, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let committed = unit_of_work.committed();
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command(1).change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    assert_eq!(parts.audit.parts().outcome, AuditOutcome::Committed);
    assert_eq!(parts.audit.parts().action.as_str(), "openapi_spec.retire");
    assert_eq!(parts.audit.parts().target.target_type(), "openapi_spec");
    assert_eq!(
        parts.audit.parts().target.target_id(),
        spec_id(1).to_string()
    );
    assert_eq!(
        parts.audit.parts().after.as_ref().unwrap().as_str(),
        "service=billing status=retired deactivated=2 orphaned=0"
    );
    assert_eq!(unit_of_work.policy_version(), 1);
    assert_eq!(
        parts.statements[0],
        ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(0).unwrap())
    );
    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.kind, PermissionKeyKind::Rest);
    assert_eq!(statement.service, service());
    assert_eq!(statement.transition.from, SpecStatus::Active);
    assert_eq!(statement.transition.to, SpecStatus::Retired);
    assert_eq!(statement.transition.activated_at, Some(at()));
    assert_eq!(statement.transition.retired_at, Some(at()));
    assert_eq!(
        keys(&statement.deactivated),
        [
            "rest:billing:GET /invoices",
            "rest:billing:POST /invoices/{}/pay"
        ]
    );
    assert_eq!(statement.orphaned.len(), 0);
    assert_eq!(event_types(&unit_of_work), ["iam.openapi_spec.retired"]);
}

#[tokio::test]
async fn keys_that_another_active_version_holds_stay_active() {
    let world = World::new(&[
        spec(1, SpecStatus::Active, &[INVOICES, PAY]),
        spec(2, SpecStatus::Active, &[INVOICES]),
    ]);
    world.stored_entry(1, "rest:billing:GET /invoices", PLAIN, true);
    world.stored_entry(2, "rest:billing:POST /invoices/{}/pay", SENSITIVE, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(
        keys(&statement.deactivated),
        ["rest:billing:POST /invoices/{}/pay"]
    );
}

#[tokio::test]
async fn a_key_whose_flags_follow_the_remaining_versions_is_reflagged() {
    let world = World::new(&[
        spec(1, SpecStatus::Active, &[PAY]),
        spec(
            2,
            SpecStatus::Active,
            &[(HttpMethod::Post, "/invoices/{id}/pay", PLAIN)],
        ),
    ]);
    world.stored_entry(1, "rest:billing:POST /invoices/{}/pay", SENSITIVE, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.reflagged.len(), 1);
    assert_eq!(statement.reflagged[0].flags, PLAIN);
    assert_eq!(statement.deactivated.len(), 0);
}

fn orphaning_world() -> World {
    let mut world = World::new(&[spec(1, SpecStatus::Active, &[INVOICES])]);
    world.stored_entry(1, "rest:billing:GET /invoices", PLAIN, true);
    world.roles = FakeRoleRepository::new().with_grant_records(vec![
        grant(1, "rest:billing:GET /invoices", GrantStatus::Active),
        grant(2, "rest:billing:GET /invoices", GrantStatus::Active),
    ]);
    world
}

#[tokio::test]
async fn a_retirement_that_orphans_grants_without_confirmation_lists_them_and_commits_nothing() {
    let (handler, unit_of_work) = orphaning_world().handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    let IamError::ConfirmationRequired(Confirmation::Orphans, items) = error else {
        panic!("an orphan confirmation expected: {error:?}");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].property_path, "rest:billing:GET /invoices");
    assert_eq!(items[0].code, "orphaned_grant");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_confirmed_retirement_orphans_the_grants_and_records_both_events() {
    let (handler, unit_of_work) = orphaning_world().handler();
    let confirmed = RetireOpenApiSpecCommand {
        confirm_orphans: true,
        ..command(1)
    };

    handler.handle(confirmed).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.orphaned.len(), 2);
    assert_eq!(statement.orphaned[0].role, role_id(1));
    assert_eq!(statement.orphaned[1].role, role_id(2));
    assert_eq!(
        event_types(&unit_of_work),
        ["iam.openapi_spec.retired", "iam.permissions.orphaned"]
    );
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_change_and_its_audit_record() {
    let (handler, unit_of_work) = World::new(&[spec(1, SpecStatus::Active, &[INVOICES])]).handler();
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("retire-1").unwrap(),
        request_digest: RequestDigest::new(&[7; 32]).unwrap(),
    };
    let keyed = RetireOpenApiSpecCommand {
        idempotency: Some(request.clone()),
        ..command(1)
    };

    handler.handle(keyed).await.unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request));
    assert_eq!(
        committed[0]
            .parts()
            .audit
            .parts()
            .idempotency_key
            .as_ref()
            .unwrap()
            .as_str(),
        "retire-1"
    );
}

#[tokio::test]
async fn an_unknown_version_is_not_found() {
    let (handler, unit_of_work) = World::new(&[]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_iam_version_is_forbidden_to_any_actor_but_the_startup_registration() {
    let iam = || {
        spec_of(
            ServiceName::iam().clone(),
            1,
            SpecStatus::Active,
            &[(HttpMethod::Get, "/me", PLAIN)],
        )
    };

    let (handler, unit_of_work) = World::new(&[iam()]).handler();
    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);

    let (handler, unit_of_work) = World::new(&[iam()]).handler();
    let operator = RetireOpenApiSpecCommand {
        actor: ActorRef::System(SystemComponent::Bootstrap),
        ..command(1)
    };
    let error = handler.handle(operator).await.unwrap_err();

    assert!(matches!(error, IamError::Forbidden), "{error:?}");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_startup_registration_may_retire_an_iam_version() {
    let (handler, unit_of_work) = World::new(&[spec_of(
        ServiceName::iam().clone(),
        1,
        SpecStatus::Active,
        &[(HttpMethod::Get, "/me", PLAIN)],
    )])
    .handler();
    let startup = RetireOpenApiSpecCommand {
        actor: ActorRef::System(SystemComponent::Startup),
        ..command(1)
    };

    handler.handle(startup).await.unwrap();

    assert_eq!(unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_draft_cannot_be_retired() {
    let (handler, unit_of_work) = World::new(&[spec(1, SpecStatus::Draft, &[INVOICES])]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_retired_version_cannot_be_retired_again() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Retired, &[INVOICES])]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_retirement_asks_for_the_specification_scope_check_of_its_service() {
    let world = World::new(&[spec(1, SpecStatus::Active, &[INVOICES, PAY])]);
    world.stored_entry(1, "rest:billing:GET /invoices", PLAIN, true);
    world.stored_entry(2, "rest:billing:POST /invoices/{}/pay", SENSITIVE, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Spec {
            service: service(),
            flag_downgrade: false,
        })
    );
}
