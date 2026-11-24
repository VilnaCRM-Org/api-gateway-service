//! Values and doubles that the tests of the effective permissions of a user of the REST and GraphQL
//! adapters share.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, CompiledRoleSet, EffectivePermissionComposer, EffectivePermissionFilter,
    GrantStatus, PermissionGrant, PolicyVersion, ProjectId, RoleAssignment, RoleId, RoleName,
    SubjectRef,
};
use serde_json::{Value, json};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::fixtures::USER;
use crate::http::IamState;
use crate::query::get_user_role_permissions::{
    GetUserRolePermissionsQuery, UserRolePermissionsView,
};

/// The first granting role, whose assignment is global and expires.
pub(crate) const ROLE_A: &str = "0190f2a8-7b3c-7d4e-8f10-0000000000a1";
/// The second granting role, whose assignment is scoped to [`PROJECT`].
pub(crate) const ROLE_B: &str = "0190f2a8-7b3c-7d4e-8f10-0000000000b2";
/// The project of the second assignment.
pub(crate) const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f20-0000000000c3";
/// The expiry of the first assignment.
pub(crate) const EXPIRY: &str = "2027-01-15T08:00:00Z";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The queries the double was asked.
pub(crate) type Asked = Arc<Mutex<Vec<GetUserRolePermissionsQuery>>>;

/// The queries the double recorded, in order.
pub(crate) fn recorded(log: &Asked) -> Vec<GetUserRolePermissionsQuery> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn compiled(grants: &[&str]) -> CompiledRoleSet {
    CompiledRoleSet::compile(
        grants
            .iter()
            .map(|text| (PermissionGrant::parse(text).unwrap(), GrantStatus::Active)),
    )
}

/// The view that every answer holds: the key `rest:billing:GET /invoices` granted by both roles and
/// the wildcard `gql:billing:*` granted by the first, at the policy version 7.
pub(crate) fn view() -> UserRolePermissionsView {
    let role_a = RoleId::parse(ROLE_A).unwrap();
    let role_b = RoleId::parse(ROLE_B).unwrap();
    let expiry = humantime::parse_rfc3339(EXPIRY).unwrap();
    let assignments = [
        RoleAssignment::new(role_a, AssignmentScope::Global, Some(expiry)),
        RoleAssignment::new(
            role_b,
            AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap()),
            None,
        ),
    ];
    let sets = BTreeMap::from([
        (
            role_a,
            compiled(&["rest:billing:GET /invoices", "gql:billing:*"]),
        ),
        (role_b, compiled(&["rest:billing:GET /invoices"])),
    ]);
    let read_model = EffectivePermissionComposer::compose(
        PolicyVersion::new(7).unwrap(),
        &assignments,
        &sets,
        &EffectivePermissionFilter::default(),
        SystemTime::UNIX_EPOCH,
    );
    UserRolePermissionsView {
        subject: SubjectRef::user(Uuid::parse(USER).unwrap()),
        read_model,
        role_names: BTreeMap::from([
            (
                role_a,
                Some(RoleName::new("Billing reader".to_owned()).unwrap()),
            ),
            (role_b, None),
        ]),
    }
}

/// The JSON that [`view`] has on the wire, over REST and over GraphQL alike.
pub(crate) fn view_json() -> Value {
    json!({
        "userId": USER,
        "policyVersion": 7,
        "permissions": [
            {
                "key": "rest:billing:GET /invoices",
                "kind": "rest",
                "service": "billing",
                "wildcard": false,
                "roles": [{ "id": ROLE_A, "name": "Billing reader" }, { "id": ROLE_B }],
                "scopes": ["all"],
                "expiresAt": "2027-01-15T08:00:00.000000Z"
            },
            {
                "key": "gql:billing:*",
                "kind": "gql",
                "service": "billing",
                "wildcard": true,
                "roles": [{ "id": ROLE_A, "name": "Billing reader" }],
                "scopes": ["all"],
                "expiresAt": "2027-01-15T08:00:00.000000Z"
            }
        ]
    })
}

/// The state over a query bus that answers the read with `answer` and records the queries, with
/// the bus to read back what it was asked.
pub(crate) fn scenario(
    answer: Result<UserRolePermissionsView, Refusal>,
) -> (IamState, Arc<FakeQueryBus>, Asked) {
    let asked: Asked = Arc::default();
    let log = Arc::clone(&asked);
    let queries = Arc::new(FakeQueryBus::answering(
        move |query: GetUserRolePermissionsQuery| {
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(query);
            answer.clone().map_err(|refusal| refusal())
        },
    ));
    let commands = Arc::new(FakeCommandBus::unregistered());
    let command_bus: Arc<dyn CommandBus> = commands;
    let query_bus: Arc<dyn QueryBus> = Arc::<FakeQueryBus>::clone(&queries);
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, queries, asked)
}
