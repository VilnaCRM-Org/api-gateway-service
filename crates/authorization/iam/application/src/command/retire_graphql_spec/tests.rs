use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, ChangeId, ChangeStatement, ContentHash, DecisionEffect, EntityVersion,
    GqlName, GrantRecord, GrantStatus, GraphQlCoordinate, GraphQlField, GraphQlPermission,
    GraphQlSpec, GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecStatement, GraphQlTypeGraph,
    IdempotencyKey, IdempotencyRequest, PermissionFlags, PermissionId, PermissionKey,
    PermissionKeyKind, PolicyVersion, RequestDigest, RoleId, ServiceName, SpecId, SpecStatus,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::graphql_permission::FakeGraphQlPermissionRepository;
use test_support::graphql_spec::FakeGraphQlSpecRepository;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::FakePolicyEpochRepository;
use test_support::role::FakeRoleRepository;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{RetireGraphQlSpecCommand, RetireGraphQlSpecCommandHandler};
use crate::command::create_graphql_permissions::ActivationReads;
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

fn type_graph(fields: &[(&str, PermissionFlags)]) -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        fields.iter().map(|(text, flags)| {
            (
                GraphQlCoordinate::parse(text).unwrap(),
                GraphQlField {
                    return_type: GqlName::parse("String").unwrap(),
                    flags: *flags,
                },
            )
        }),
        [],
    )
    .unwrap()
}

fn spec(
    number: u8,
    status: SpecStatus,
    fields: &[(&str, PermissionFlags)],
) -> GraphQlSpecStatement {
    let spec = GraphQlSpec::restore(GraphQlSpecParts {
        id: spec_id(number),
        content: GraphQlSpecContent {
            service: service(),
            content_hash: ContentHash::new(&[number; 32]).unwrap(),
            type_graph: type_graph(fields),
        },
        status,
        uploaded_by: actor(),
        created_at: at(),
        activated_at: (status != SpecStatus::Draft).then_some(at()),
        retired_at: None,
    });
    GraphQlSpecStatement::insert(&spec, format!("sdl {number}"))
}

fn command(number: u8) -> RetireGraphQlSpecCommand {
    RetireGraphQlSpecCommand {
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
    specs: FakeGraphQlSpecRepository,
    permissions: FakeGraphQlPermissionRepository,
    roles: FakeRoleRepository,
    epochs: FakePolicyEpochRepository,
    unit_of_work: Arc<FakeIamUnitOfWork>,
}

impl World {
    fn new(specs: &[GraphQlSpecStatement]) -> Self {
        let repository = FakeGraphQlSpecRepository::new();
        for statement in specs {
            repository.save(statement).unwrap();
        }
        Self {
            specs: repository,
            permissions: FakeGraphQlPermissionRepository::new(),
            roles: FakeRoleRepository::new(),
            epochs: FakePolicyEpochRepository::new(),
            unit_of_work: Arc::new(FakeIamUnitOfWork::new()),
        }
    }

    fn stored_entry(&self, number: u8, text: &str, flags: PermissionFlags, active: bool) {
        let id = PermissionId::parse(&format!("0190f2a8-7b3c-7d4e-8f12-1234567890{number:02x}"))
            .unwrap();
        let mut entry = GraphQlPermission::create(id, key(text), flags).unwrap();
        if !active {
            entry.deactivate();
        }
        self.permissions.insert(&entry).unwrap();
    }

    fn handler(self) -> (RetireGraphQlSpecCommandHandler, Arc<FakeIamUnitOfWork>) {
        let unit_of_work = Arc::clone(&self.unit_of_work);
        let reads = ActivationReads {
            specs: Arc::new(self.specs),
            permissions: Arc::new(self.permissions),
            roles: Arc::new(self.roles),
            policy_epochs: Arc::new(self.epochs),
        };
        let handler = RetireGraphQlSpecCommandHandler::new(
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

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(RetireGraphQlSpecCommand::NAME, "RetireGraphQlSpecCommand");
}

#[tokio::test]
async fn an_active_version_is_retired_and_its_entries_are_deactivated_as_one_change() {
    let world = World::new(&[spec(
        1,
        SpecStatus::Active,
        &[("Query.invoices", PLAIN), ("Mutation.pay", SENSITIVE)],
    )]);
    world.stored_entry(1, "gql:billing:Query.invoices", PLAIN, true);
    world.stored_entry(2, "gql:billing:Mutation.pay", SENSITIVE, true);
    world.stored_entry(3, "gql:billing:__introspection", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let committed = unit_of_work.committed();
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, command(1).change_id);
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    assert_eq!(parts.audit.parts().outcome, AuditOutcome::Committed);
    assert_eq!(parts.audit.parts().action.as_str(), "graphql_spec.retire");
    assert_eq!(parts.audit.parts().target.target_type(), "graphql_spec");
    assert_eq!(
        parts.audit.parts().target.target_id(),
        spec_id(1).to_string()
    );
    assert_eq!(
        parts.audit.parts().before.as_ref().unwrap().as_str(),
        "status=active"
    );
    assert_eq!(
        parts.audit.parts().after.as_ref().unwrap().as_str(),
        "service=billing status=retired deactivated=3 orphaned=0"
    );
    assert_eq!(unit_of_work.policy_version(), 1);
    assert_eq!(
        parts.statements[0],
        ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(0).unwrap())
    );
    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.kind, PermissionKeyKind::Gql);
    assert_eq!(statement.service, service());
    assert_eq!(statement.transition.spec_id, spec_id(1));
    assert_eq!(statement.transition.from, SpecStatus::Active);
    assert_eq!(statement.transition.to, SpecStatus::Retired);
    assert_eq!(statement.transition.activated_at, Some(at()));
    assert_eq!(statement.transition.retired_at, Some(at()));
    assert_eq!(statement.at, at());
    assert_eq!(
        keys(&statement.deactivated),
        [
            "gql:billing:Mutation.pay",
            "gql:billing:Query.invoices",
            "gql:billing:__introspection"
        ]
    );
    assert_eq!(statement.created.len(), 0);
    assert_eq!(statement.reflagged.len(), 0);
    assert_eq!(statement.reactivated.len(), 0);
    assert_eq!(statement.orphaned.len(), 0);
    assert_eq!(statement.renames.len(), 0);
    assert_eq!(event_types(&unit_of_work), ["iam.graphql_spec.retired"]);
}

#[tokio::test]
async fn keys_that_another_active_version_holds_stay_active() {
    let world = World::new(&[
        spec(
            1,
            SpecStatus::Active,
            &[("Query.invoices", PLAIN), ("Mutation.pay", PLAIN)],
        ),
        spec(2, SpecStatus::Active, &[("Query.invoices", PLAIN)]),
    ]);
    world.stored_entry(1, "gql:billing:Query.invoices", PLAIN, true);
    world.stored_entry(2, "gql:billing:Mutation.pay", PLAIN, true);
    world.stored_entry(3, "gql:billing:__introspection", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(keys(&statement.deactivated), ["gql:billing:Mutation.pay"]);
    assert_eq!(statement.reflagged.len(), 0);
}

#[tokio::test]
async fn an_entry_that_is_inactive_already_is_not_deactivated_again() {
    let world = World::new(&[spec(1, SpecStatus::Active, &[("Query.invoices", PLAIN)])]);
    world.stored_entry(1, "gql:billing:Query.invoices", PLAIN, true);
    world.stored_entry(2, "gql:billing:Query.old", PLAIN, false);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(keys(&statement.deactivated), ["gql:billing:Query.invoices"]);
}

#[tokio::test]
async fn a_key_whose_flags_follow_the_remaining_versions_is_reflagged() {
    let world = World::new(&[
        spec(1, SpecStatus::Active, &[("Mutation.pay", SENSITIVE)]),
        spec(2, SpecStatus::Active, &[("Mutation.pay", PLAIN)]),
    ]);
    world.stored_entry(1, "gql:billing:Mutation.pay", SENSITIVE, true);
    world.stored_entry(2, "gql:billing:__introspection", PLAIN, true);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    assert_eq!(statement.reflagged.len(), 1);
    assert_eq!(statement.reflagged[0].key, key("gql:billing:Mutation.pay"));
    assert_eq!(statement.reflagged[0].flags, PLAIN);
    assert_eq!(statement.deactivated.len(), 0);
    assert_eq!(event_types(&unit_of_work), ["iam.graphql_spec.retired"]);
}

fn orphaning_world() -> World {
    let mut world = World::new(&[spec(1, SpecStatus::Active, &[("Query.invoices", PLAIN)])]);
    world.stored_entry(1, "gql:billing:Query.invoices", PLAIN, true);
    world.stored_entry(2, "gql:billing:__introspection", PLAIN, true);
    world.roles = FakeRoleRepository::new().with_grant_records(vec![
        grant(1, "gql:billing:Query.invoices", GrantStatus::Active),
        grant(2, "gql:billing:Query.invoices", GrantStatus::Active),
        grant(2, "gql:billing:Query.gone", GrantStatus::Orphaned),
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
    assert_eq!(items[0].property_path, "gql:billing:Query.invoices");
    assert_eq!(items[0].code, "orphaned_grant");
    assert!(items[0].message.contains(&role_id(1).to_string()));
    assert!(items[1].message.contains(&role_id(2).to_string()));
    assert_eq!(unit_of_work.committed().len(), 0);
    assert_eq!(unit_of_work.policy_version(), 0);
}

#[tokio::test]
async fn a_confirmed_retirement_orphans_the_grants_and_records_both_events() {
    let (handler, unit_of_work) = orphaning_world().handler();
    let confirmed = RetireGraphQlSpecCommand {
        confirm_orphans: true,
        ..command(1)
    };

    handler.handle(confirmed).await.unwrap();

    let statement = catalogue_statement(&unit_of_work);
    let orphaned: Vec<(RoleId, String)> = statement
        .orphaned
        .iter()
        .map(|grant| (grant.role, grant.key.to_string()))
        .collect();
    assert_eq!(
        orphaned,
        vec![
            (role_id(1), "gql:billing:Query.invoices".to_owned()),
            (role_id(2), "gql:billing:Query.invoices".to_owned()),
        ]
    );
    assert_eq!(
        event_types(&unit_of_work),
        ["iam.graphql_spec.retired", "iam.permissions.orphaned"]
    );
    let audit = unit_of_work.committed()[0].parts().audit.clone();
    assert_eq!(
        audit.parts().after.as_ref().unwrap().as_str(),
        "service=billing status=retired deactivated=2 orphaned=2"
    );
}

#[tokio::test]
async fn grants_of_keys_that_another_version_still_holds_are_not_orphaned() {
    let mut world = World::new(&[
        spec(1, SpecStatus::Active, &[("Query.invoices", PLAIN)]),
        spec(2, SpecStatus::Active, &[("Query.invoices", PLAIN)]),
    ]);
    world.roles = FakeRoleRepository::new().with_grant_records(vec![grant(
        1,
        "gql:billing:Query.invoices",
        GrantStatus::Active,
    )]);
    let (handler, unit_of_work) = world.handler();

    handler.handle(command(1)).await.unwrap();

    assert_eq!(catalogue_statement(&unit_of_work).orphaned.len(), 0);
    assert_eq!(event_types(&unit_of_work), ["iam.graphql_spec.retired"]);
}

#[tokio::test]
async fn the_idempotency_key_reaches_the_change_and_its_audit_record() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Active, &[("Query.invoices", PLAIN)])]).handler();
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("retire-1").unwrap(),
        request_digest: RequestDigest::new(&[7; 32]).unwrap(),
    };
    let keyed = RetireGraphQlSpecCommand {
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
async fn a_draft_cannot_be_retired() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Draft, &[("Query.invoices", PLAIN)])]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_retired_version_cannot_be_retired_again() {
    let (handler, unit_of_work) =
        World::new(&[spec(1, SpecStatus::Retired, &[("Query.invoices", PLAIN)])]).handler();

    let error = handler.handle(command(1)).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(unit_of_work.committed().len(), 0);
}
