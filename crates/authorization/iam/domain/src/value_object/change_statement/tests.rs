use std::time::SystemTime;

use shared_domain::Uuid;

use super::ChangeStatement;
use crate::bulk_operation::statement::BulkProgressStatement;
use crate::bulk_operation::{BulkKind, BulkOperation};
use crate::gateway_statement::GatewayPrecondition;
use crate::resync::{EpochChange, Republication, ResyncStart};
use crate::role::statement::RoleStatement;
use crate::role::{Role, RoleFields, RoleStamp};
use crate::state::key::StateKey;
use crate::user_role::statement::UserRoleStatement;
use crate::user_role::{UserRole, UserRoleAssignment, UserRoleStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::BulkOperationId;
use crate::value_object::identifier::UpstreamId;
use crate::value_object::identifier::{RoleId, UserRoleId};
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::role_name::RoleName;
use crate::value_object::service_name::ServiceName;
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

fn upstream_statement() -> ChangeStatement {
    use crate::upstream::settings::{UpstreamFields, UpstreamProtocol, UpstreamSettingsDraft};
    use crate::upstream::statement::UpstreamStatement;
    use crate::upstream::{Upstream, UpstreamStamp};
    use crate::value_object::identifier::UpstreamId;

    let fields = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
            namespace: "platform".to_owned(),
            service_name: "core-service".to_owned(),
            catalog_service: "core".to_owned(),
            port: 8080,
            protocol: UpstreamProtocol::Http1,
            forward_credentials: false,
            connect_timeout_ms: 1_000,
            response_timeout_ms: 30_000,
            concurrency_limit: 256,
            retry_budget_percent: 20,
            outlier_threshold: 5,
        },
    )
    .unwrap();
    let upstream = Upstream::create(
        UpstreamId::parse("5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d").unwrap(),
        fields,
        false,
        UpstreamStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    ChangeStatement::from(UpstreamStatement::insert(&upstream))
}

fn route_statement() -> ChangeStatement {
    use crate::route::Route;
    use crate::route::fixtures::{fields, stamp};
    use crate::route::statement::RouteStatement;
    use crate::value_object::http_method::HttpMethod;
    use crate::value_object::identifier::RouteId;

    let route = Route::create(
        RouteId::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        fields("api.example.com", "/users", &[HttpMethod::Get]),
        false,
        stamp(10),
    );
    ChangeStatement::from(RouteStatement::insert(&route))
}

fn rate_policy_statement() -> ChangeStatement {
    use crate::rate_policy::fields::{
        RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields,
    };
    use crate::rate_policy::statement::RatePolicyStatement;
    use crate::rate_policy::{RatePolicy, RatePolicyStamp};
    use crate::value_object::identifier::RatePolicyId;

    let fields = RatePolicyFields::new(RatePolicyDraft {
        name: "per-ip".to_owned(),
        key_kind: RateKeyKind::Ip,
        limit: 100,
        period_seconds: 60,
        burst: 10,
        fallback: RateFallback::Divided,
    })
    .unwrap();
    let policy = RatePolicy::create(
        RatePolicyId::parse("6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e").unwrap(),
        fields,
        RatePolicyStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    );
    ChangeStatement::from(RatePolicyStatement::insert(&policy))
}

#[test]
fn a_gateway_configuration_write_holds_under_every_locked_version() {
    for statement in [
        upstream_statement(),
        route_statement(),
        rate_policy_statement(),
    ] {
        assert!(statement.holds(PolicyVersion::new(1).unwrap()));
        assert!(statement.holds(PolicyVersion::new(9).unwrap()));
    }
}

#[test]
fn an_upstream_write_changes_the_state_of_the_upstream_named_by_it() {
    use crate::value_object::upstream_name::UpstreamName;

    let statement = upstream_statement();

    assert_eq!(
        statement.state_keys(),
        [StateKey::Upstream(UpstreamName::new("core").unwrap())]
    );
    assert_eq!(statement.catalogue_service(), None);
}

#[test]
fn a_route_write_changes_the_state_of_its_route() {
    use crate::value_object::identifier::RouteId;

    let statement = route_statement();

    assert_eq!(
        statement.state_keys(),
        [StateKey::Route(
            RouteId::parse("00000000-0000-7000-8000-000000000001").unwrap()
        )]
    );
    assert_eq!(statement.catalogue_service(), None);
}

#[test]
fn a_rate_policy_write_changes_the_state_of_its_rate_policy() {
    use crate::value_object::identifier::RatePolicyId;

    let statement = rate_policy_statement();

    assert_eq!(
        statement.state_keys(),
        [StateKey::RatePolicy(
            RatePolicyId::parse("6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e").unwrap()
        )]
    );
    assert_eq!(statement.catalogue_service(), None);
}

#[test]
fn a_bulk_progress_write_holds_everywhere_and_names_no_state_key_or_service() {
    let operation = BulkOperation::pending(
        BulkOperationId::parse("01890a5d-ac96-774b-bcce-b302099a8058").unwrap(),
        BulkKind::RoleDeletion,
        3,
        ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap();
    let statement = ChangeStatement::SaveBulkProgress(Box::new(
        BulkProgressStatement::after_chunk(&operation, 0),
    ));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert!(statement.holds(PolicyVersion::new(9).unwrap()));
    assert_eq!(statement.state_keys().len(), 0);
    assert_eq!(statement.catalogue_service(), None);
}

#[test]
fn a_resync_start_changes_no_entity_and_holds_under_every_locked_version() {
    let change = EpochChange::new(LogEpoch::ZERO, PolicyVersion::new(9).unwrap()).unwrap();
    let operation = BulkOperation::pending(
        BulkOperationId::parse("0190f2a8-7b3c-7d4e-8f10-000000000001").unwrap(),
        BulkKind::Resync,
        3,
        ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap();
    let statement = ChangeStatement::StartResync(Box::new(ResyncStart::new(
        change.clone(),
        operation.parts().clone(),
    )));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert_eq!(statement.state_keys().len(), 0);
    assert_eq!(statement.epoch_change(), Some(&change));
    assert_eq!(statement.republished_keys().len(), 0);
    assert_eq!(statement.republished_services().len(), 0);
}

#[test]
fn a_republication_names_the_keys_and_the_services_it_writes_again() {
    let key = StateKey::Role(RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap());
    let service = ServiceName::new("billing").unwrap();
    let statement = ChangeStatement::RepublishState(Box::new(Republication::new(
        vec![key.clone()],
        vec![service.clone()],
    )));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert_eq!(statement.state_keys(), vec![key.clone()]);
    assert_eq!(statement.republished_keys(), [key]);
    assert_eq!(statement.republished_services(), [service]);
    assert_eq!(statement.epoch_change(), None);
    assert_eq!(statement.catalogue_service(), None);
}

#[test]
fn a_gateway_precondition_is_checked_by_the_storage_and_changes_no_entity() {
    let statement = ChangeStatement::from(GatewayPrecondition::UpstreamUnreferenced(
        UpstreamId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890cf").unwrap()),
    ));

    assert!(statement.holds(PolicyVersion::new(1).unwrap()));
    assert_eq!(statement.state_keys().len(), 0);
    assert!(statement.catalogue_service().is_none());
    assert_eq!(statement.republished_services().len(), 0);
    assert!(statement.epoch_change().is_none());
    assert_eq!(statement.republished_keys().len(), 0);
}
