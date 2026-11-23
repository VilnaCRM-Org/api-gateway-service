use std::time::SystemTime;

use shared_domain::Uuid;

use super::ChangeStatement;
use crate::role::statement::RoleStatement;
use crate::role::{Role, RoleFields, RoleStamp};
use crate::state::key::StateKey;
use crate::user_role::statement::UserRoleStatement;
use crate::user_role::{UserRole, UserRoleAssignment, UserRoleStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::role_name::RoleName;
use crate::value_object::subject::SubjectRef;

#[test]
fn an_expected_policy_version_holds_only_for_that_version() {
    let statement = ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(4).unwrap());

    assert!(statement.holds(PolicyVersion::new(4).unwrap()));
    assert!(!statement.holds(PolicyVersion::new(5).unwrap()));
}

#[test]
fn a_role_write_holds_under_every_locked_version() {
    let actor = ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap());
    let role = Role::create(
        RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
        RoleFields::new("Billing".to_owned(), None).unwrap(),
        RoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor.clone(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    let statement = ChangeStatement::SaveRole(Box::new(RoleStatement::insert(&role, actor)));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

#[test]
fn an_assignment_write_holds_under_every_locked_version() {
    let user_role = UserRole::assign(
        UserRoleAssignment {
            id: UserRoleId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706").unwrap(),
            subject: SubjectRef::user(Uuid::parse("9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b").unwrap()),
            role_id: RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
            role_name: RoleName::new("Billing".to_owned()).unwrap(),
            scope: AssignmentScope::Global,
            expires_at: None,
            privileged: None,
        },
        UserRoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    )
    .unwrap();
    let statement = ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::insert(&user_role)));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

#[test]
fn a_specification_write_holds_under_every_locked_version() {
    use crate::graphql_spec::statement::GraphQlSpecStatement;
    use crate::graphql_spec::{GraphQlSpec, GraphQlSpecContent, SpecStamp};
    use crate::value_object::content_hash::ContentHash;
    use crate::value_object::graphql_type_graph::GraphQlTypeGraph;
    use crate::value_object::identifier::SpecId;
    use crate::value_object::service_name::ServiceName;

    let spec = GraphQlSpec::load(
        SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
        GraphQlSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[0x11; 32]).unwrap(),
            type_graph: GraphQlTypeGraph::default(),
        },
        SpecStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    let statement = ChangeStatement::SaveGraphQlSpec(Box::new(GraphQlSpecStatement::insert(
        &spec,
        String::new(),
    )));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

#[test]
fn an_openapi_specification_write_holds_under_every_locked_version() {
    use crate::graphql_spec::SpecStamp;
    use crate::openapi_spec::statement::OpenApiSpecStatement;
    use crate::openapi_spec::{OpenApiSpec, OpenApiSpecContent};
    use crate::value_object::content_hash::ContentHash;
    use crate::value_object::identifier::SpecId;
    use crate::value_object::rest_operation_set::RestOperationSet;
    use crate::value_object::service_name::ServiceName;

    let spec = OpenApiSpec::load(
        SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
        OpenApiSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[0x11; 32]).unwrap(),
            operations: RestOperationSet::new(),
        },
        SpecStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    let statement = ChangeStatement::SaveOpenApiSpec(Box::new(OpenApiSpecStatement::insert(
        &spec,
        String::new(),
    )));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

#[test]
fn a_catalogue_write_holds_under_every_locked_version() {
    use crate::catalogue_statement::{CatalogueStatement, CatalogueStatementParts, SpecTransition};
    use crate::value_object::identifier::SpecId;
    use crate::value_object::permission_key::PermissionKeyKind;
    use crate::value_object::service_name::ServiceName;
    use crate::value_object::spec_status::SpecStatus;

    let statement = ChangeStatement::ApplyCatalogue(Box::new(
        CatalogueStatement::new(CatalogueStatementParts {
            kind: PermissionKeyKind::Rest,
            service: ServiceName::new("billing").unwrap(),
            transition: SpecTransition {
                spec_id: SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
                from: SpecStatus::Draft,
                to: SpecStatus::Active,
                activated_at: Some(SystemTime::UNIX_EPOCH),
                retired_at: None,
            },
            created: Vec::new(),
            reflagged: Vec::new(),
            reactivated: Vec::new(),
            deactivated: Vec::new(),
            orphaned: Vec::new(),
            renames: Vec::new(),
            at: SystemTime::UNIX_EPOCH,
        })
        .unwrap(),
    ));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap())
}

fn role_statement() -> ChangeStatement {
    let role = Role::create(
        RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
        RoleFields::new("Billing".to_owned(), None).unwrap(),
        RoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    ChangeStatement::SaveRole(Box::new(RoleStatement::insert(&role, actor())))
}

#[test]
fn a_role_write_changes_the_state_of_its_role() {
    let keys = role_statement().state_keys();

    assert_eq!(
        keys,
        [StateKey::Role(
            RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap()
        )]
    );
    assert_eq!(role_statement().catalogue_service(), None);
}

#[test]
fn an_assignment_write_changes_the_state_of_its_subject() {
    let subject = SubjectRef::user(Uuid::parse("9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b").unwrap());
    let user_role = UserRole::assign(
        UserRoleAssignment {
            id: UserRoleId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706").unwrap(),
            subject: subject.clone(),
            role_id: RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
            role_name: RoleName::new("Billing".to_owned()).unwrap(),
            scope: AssignmentScope::Global,
            expires_at: None,
            privileged: None,
        },
        UserRoleStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    )
    .unwrap();
    let statement = ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::insert(&user_role)));

    assert_eq!(statement.state_keys(), [StateKey::Subject(subject)]);
}

#[test]
fn a_guard_changes_no_state() {
    let guard = ChangeStatement::ExpectPolicyVersion(PolicyVersion::new(4).unwrap());

    assert_eq!(guard.state_keys().len(), 0);
    assert_eq!(guard.catalogue_service(), None);
}

#[test]
fn an_activation_changes_the_roles_it_orphans_or_moves_and_names_its_service() {
    use crate::catalogue_statement::{CatalogueStatement, CatalogueStatementParts, SpecTransition};
    use crate::policy::catalogue_activation::{KeyRename, OrphanedGrant};
    use crate::value_object::identifier::SpecId;
    use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};
    use crate::value_object::service_name::ServiceName;
    use crate::value_object::spec_status::SpecStatus;

    let key = |text: &str| PermissionKey::parse(text).unwrap();
    let orphaned = RoleId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706").unwrap();
    let moved = RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap();
    let statement = CatalogueStatement::new(CatalogueStatementParts {
        kind: PermissionKeyKind::Gql,
        service: ServiceName::new("billing").unwrap(),
        transition: SpecTransition {
            spec_id: SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
            from: SpecStatus::Draft,
            to: SpecStatus::Active,
            activated_at: Some(SystemTime::UNIX_EPOCH),
            retired_at: None,
        },
        created: Vec::new(),
        reflagged: Vec::new(),
        reactivated: Vec::new(),
        deactivated: Vec::new(),
        orphaned: vec![OrphanedGrant {
            role: orphaned,
            key: key("gql:billing:Query.old"),
        }],
        renames: vec![KeyRename {
            from: key("gql:billing:Query.a"),
            to: key("gql:billing:Query.b"),
            roles: vec![moved],
        }],
        at: SystemTime::UNIX_EPOCH,
    })
    .unwrap();
    let statement = ChangeStatement::ApplyCatalogue(Box::new(statement));

    assert_eq!(
        statement.state_keys(),
        [StateKey::Role(orphaned), StateKey::Role(moved)]
    );
    assert_eq!(
        statement.catalogue_service(),
        Some(&ServiceName::new("billing").unwrap())
    );
}
