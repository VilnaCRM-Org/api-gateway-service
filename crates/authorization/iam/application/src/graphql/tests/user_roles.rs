use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{
    ActorRef, AssignmentScope, ProjectId, RoleId, SubjectKind, SubjectRef, UserRoleId,
};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;

use crate::error::IamError;
use crate::fixtures::{ROLE, USER, principal, recorded};
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::principal::Principal;
use crate::query::list_user_roles::{ListUserRolesQuery, UserRolePage};
use crate::user_role_fixtures::{
    Answers, PROJECT, SUBJECT, USER_ROLE, receipt, receipt_at, scenario, user_role,
};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const ASSIGN: &str = "mutation($input: AssignUserRoleInput!) { assignUserRole(input: $input) \
    { id subject { kind id } roleId roleName scope { kind projectId } expiresAt version \
    createdAt updatedAt } }";
const UPDATE: &str = "mutation($input: UpdateUserRoleInput!) { updateUserRole(input: $input) \
    { id roleName expiresAt version } }";
const REVOKE: &str = "mutation($input: RevokeUserRoleInput!) { revokeUserRole(input: $input) \
    { id version policyVersion } }";
const USER_ROLE_BY_ID: &str = "query($id: ID!) { userRole(id: $id) { id roleName version } }";
const USER_ROLES: &str = "query($first: Int, $after: String, $filter: UserRoleFilter) \
    { userRoles(first: $first, after: $after, filter: $filter) \
    { items { id roleName version } nextCursor } }";

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, IamMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Refused,
    Valid,
}

async fn run(
    schema: &IamSchema,
    caller: Caller,
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    match caller {
        Caller::Absent => {}
        Caller::Refused => request = request.data(None::<Principal>),
        Caller::Valid => request = request.data(Some(principal())),
    }
    schema.execute(request).await
}

fn error_code(response: &async_graphql::Response) -> Option<Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

fn violation_paths(response: &async_graphql::Response) -> Vec<String> {
    let violations = response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("violations"))
        .cloned();
    let Some(Value::List(list)) = violations else {
        return Vec::new();
    };
    list.into_iter()
        .filter_map(|violation| match violation {
            Value::Object(members) => members.get("propertyPath").map(ToString::to_string),
            Value::Null
            | Value::Number(_)
            | Value::String(_)
            | Value::Boolean(_)
            | Value::Binary(_)
            | Value::Enum(_)
            | Value::List(_) => None,
        })
        .collect()
}

fn assigned() -> serde_json::Value {
    json!({ "input": {
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
    } })
}

#[tokio::test]
async fn an_assignment_returns_the_same_data_as_over_rest() {
    let (state, commands, _queries, asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, assigned()).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "assignUserRole": {
            "id": USER_ROLE,
            "subject": { "kind": "user", "id": SUBJECT },
            "roleId": ROLE,
            "roleName": "Billing",
            "scope": { "kind": "global", "projectId": null },
            "expiresAt": null,
            "version": 1,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:01:00.000000Z",
        } })
    );
    assert_eq!(commands.dispatched(), ["AssignUserRoleCommand"]);
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(
        sent[0].subject,
        SubjectRef::user(Uuid::parse(SUBJECT).unwrap())
    );
    assert_eq!(sent[0].role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(sent[0].scope, AssignmentScope::Global);
    assert_eq!(sent[0].expires_at, None);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_service_subject_at_project_scope_with_an_expiry_reaches_the_command() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "subject": { "kind": "service", "id": "billing-worker" },
        "roleId": ROLE,
        "scope": { "kind": "project", "projectId": PROJECT },
        "expiresAt": "2027-01-15T08:00:00Z",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].subject.to_string(), "service:billing-worker");
    assert_eq!(
        sent[0].scope,
        AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
    );
    assert!(sent[0].expires_at.is_some());
}

#[tokio::test]
async fn the_idempotency_key_of_the_input_travels_with_the_command() {
    let (state, _commands, queries, asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
        "idempotencyKey": "assign-billing",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        queries.asked(),
        [
            "GetIdempotentReplayQuery",
            "GetChangeReceiptQuery",
            "GetUserRoleQuery"
        ]
    );
    let sent = recorded(&asked.commands);
    assert_eq!(
        sent[0]
            .idempotency
            .as_ref()
            .map(|request| request.key.as_str()),
        Some("assign-billing")
    );
}

#[tokio::test]
async fn a_replayed_assignment_returns_the_original_result_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt(None))),
        ..Answers::default()
    };
    let (state, commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": {
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
        "idempotencyKey": "assign-billing",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn an_invalid_idempotency_key_is_a_validation_failure_naming_the_key() {
    let (state, commands, _queries, _asked) = scenario(Answers::default());
    let variables = json!({ "input": {
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
        "idempotencyKey": "not valid",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), ["\"idempotencyKey\""]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::kind(json!({"subject": {"kind": "robot", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}}), "\"subject.kind\"")]
#[case::user_id(json!({"subject": {"kind": "user", "id": "x"}, "roleId": ROLE, "scope": {"kind": "global"}}), "\"subject.id\"")]
#[case::role_id(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": "x", "scope": {"kind": "global"}}), "\"roleId\"")]
#[case::scope(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "project"}}), "\"scope.projectId\"")]
#[case::expiry(json!({"subject": {"kind": "user", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}, "expiresAt": "soon"}), "\"expiresAt\"")]
#[case::empty_kind(json!({"subject": {"kind": "", "id": SUBJECT}, "roleId": ROLE, "scope": {"kind": "global"}}), "\"subject.kind\"")]
#[tokio::test]
async fn an_invalid_value_is_a_validation_failure_with_its_violation(
    #[case] input: serde_json::Value,
    #[case] property: &str,
) {
    let (state, commands, _queries, _asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        ASSIGN,
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::conflict(Answers { command: Err(|| IamError::Conflict), ..Answers::default() }, "CONFLICT")]
#[case::mismatch(
    Answers { replay: Err(|| IamError::IdempotencyMismatch), ..Answers::default() },
    "VALIDATION_FAILED"
)]
#[case::unknown_role(
    Answers {
        command: Err(|| IamError::Invalid(vec![shared_application::http::Violation {
            property_path: "roleId".to_owned(),
            message: "This role does not exist.".to_owned(),
            code: "exists".to_owned(),
        }])),
        ..Answers::default()
    },
    "VALIDATION_FAILED"
)]
#[case::storage(
    Answers { command: Err(|| IamError::Storage("disk on fire".into())), ..Answers::default() },
    "INTERNAL_SERVER_ERROR"
)]
#[tokio::test]
async fn a_refused_assignment_has_the_code_of_its_error(
    #[case] answers: Answers,
    #[case] expected: &str,
) {
    let (state, _commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": {
        "subject": { "kind": "user", "id": SUBJECT },
        "roleId": ROLE,
        "scope": { "kind": "global" },
        "idempotencyKey": "k",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, ASSIGN, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[rstest]
#[case::refused(Caller::Refused)]
#[case::absent(Caller::Absent)]
#[tokio::test]
async fn every_assignment_field_needs_an_authenticated_caller(#[case] caller: Caller) {
    let (state, commands, queries, _asked) = scenario(Answers::default());
    let schema = schema(Some(state));

    let assign = run(&schema, Caller::Absent, ASSIGN, assigned()).await;
    let read = run(&schema, caller, USER_ROLE_BY_ID, json!({ "id": USER_ROLE })).await;
    let list = run(&schema, Caller::Refused, USER_ROLES, json!({})).await;

    for response in [assign, read, list] {
        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    }
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_schema_without_the_state_answers_an_internal_error() {
    let response = run(&schema(None), Caller::Valid, ASSIGN, assigned()).await;
    let read = run(
        &schema(None),
        Caller::Valid,
        USER_ROLE_BY_ID,
        json!({ "id": USER_ROLE }),
    )
    .await;

    for response in [response, read] {
        assert_eq!(
            error_code(&response),
            Some(code_of("INTERNAL_SERVER_ERROR"))
        );
    }
}

#[tokio::test]
async fn a_stored_assignment_is_read_by_id() {
    let answers = Answers {
        user_role: Ok(Some(user_role(3))),
        ..Answers::default()
    };
    let (state, _commands, _queries, asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        USER_ROLE_BY_ID,
        json!({ "id": USER_ROLE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "userRole": { "id": USER_ROLE, "roleName": "Billing", "version": 3 } })
    );
    assert_eq!(
        recorded(&asked.user_roles),
        [UserRoleId::parse(USER_ROLE).unwrap()]
    );
}

#[tokio::test]
async fn an_unknown_assignment_is_null() {
    let answers = Answers {
        user_role: Ok(None),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        USER_ROLE_BY_ID,
        json!({ "id": USER_ROLE }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "userRole": null })
    );
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_validation_failure() {
    let (state, _commands, queries, _asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        USER_ROLE_BY_ID,
        json!({ "id": "x" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), ["\"id\""]);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_assignment_read_is_an_internal_error() {
    let answers = Answers {
        user_role: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        USER_ROLE_BY_ID,
        json!({ "id": USER_ROLE }),
    )
    .await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[tokio::test]
async fn the_list_without_arguments_asks_for_the_first_page_of_thirty() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, USER_ROLES, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "userRoles": { "items": [], "nextCursor": null } })
    );
    assert_eq!(
        recorded(&asked.lists),
        [ListUserRolesQuery {
            limit: 30,
            after: None,
            subject_kind: None,
            subject_id: None,
            role_id: None,
            project_id: None,
            include_expired: false,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_every_filter_and_the_cursor_to_the_query() {
    let (state, _commands, _queries, asked) = scenario(Answers::default());
    let variables = json!({
        "first": 5,
        "after": USER_ROLE,
        "filter": {
            "subjectKind": "service",
            "subjectId": "billing-worker",
            "roleId": ROLE,
            "projectId": PROJECT,
            "includeExpired": true,
        },
    });

    let response = run(&schema(Some(state)), Caller::Valid, USER_ROLES, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&asked.lists),
        [ListUserRolesQuery {
            limit: 5,
            after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
            subject_kind: Some(SubjectKind::Service),
            subject_id: Some("billing-worker".to_owned()),
            role_id: Some(RoleId::parse(ROLE).unwrap()),
            project_id: Some(ProjectId::parse(PROJECT).unwrap()),
            include_expired: true,
        }]
    );
}

#[tokio::test]
async fn a_page_of_assignments_is_listed_with_its_cursor() {
    let answers = Answers {
        page: Ok(UserRolePage {
            user_roles: vec![user_role(2)],
            next_after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
        }),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(&schema(Some(state)), Caller::Valid, USER_ROLES, json!({})).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "userRoles": {
            "items": [{ "id": USER_ROLE, "roleName": "Billing", "version": 2 }],
            "nextCursor": USER_ROLE,
        } })
    );
}

#[rstest]
#[case::limit(json!({ "first": 0 }), "\"limit\"")]
#[case::large_limit(json!({ "first": 101 }), "\"limit\"")]
#[case::cursor(json!({ "after": "x" }), "\"after\"")]
#[case::kind(json!({ "filter": { "subjectKind": "robot" } }), "\"subjectKind\"")]
#[case::role(json!({ "filter": { "roleId": "x" } }), "\"roleId\"")]
#[case::project(json!({ "filter": { "projectId": "x" } }), "\"projectId\"")]
#[tokio::test]
async fn an_invalid_argument_is_a_validation_failure_naming_it(
    #[case] variables: serde_json::Value,
    #[case] property: &str,
) {
    let (state, _commands, queries, _asked) = scenario(Answers::default());

    let response = run(&schema(Some(state)), Caller::Valid, USER_ROLES, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(violation_paths(&response), [property]);
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_failing_assignment_list_is_an_internal_error() {
    let answers = Answers {
        page: Err(|| IamError::Storage("disk on fire".into())),
        ..Answers::default()
    };
    let (state, _commands, _queries, _asked) = scenario(answers);

    let response = run(&schema(Some(state)), Caller::Valid, USER_ROLES, json!({})).await;

    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_assignment_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::{InputType as _, Name};

    use crate::graphql::user_role::{AssignUserRoleInput, UserRoleFilterInput};

    let object = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };
    let text = |value: &str| Value::String(value.to_owned());
    let assignment = object(vec![
        (
            "subject",
            object(vec![("kind", text("user")), ("id", text(USER))]),
        ),
        ("roleId", text(ROLE)),
        (
            "scope",
            object(vec![("kind", text("project")), ("projectId", text("p-1"))]),
        ),
    ]);
    let filter = object(vec![
        ("subjectKind", text("service")),
        ("includeExpired", Value::Boolean(true)),
    ]);

    let parsed = AssignUserRoleInput::parse(Some(assignment)).unwrap();
    let parsed_filter = UserRoleFilterInput::parse(Some(filter)).unwrap();

    assert_eq!(parsed.subject.kind, "user");
    assert_eq!(parsed.subject.id, USER);
    assert_eq!(parsed.role_id, ROLE);
    assert_eq!(parsed.scope.kind, "project");
    assert_eq!(parsed.scope.project_id.as_deref(), Some("p-1"));
    assert_eq!(parsed_filter.subject_kind.as_deref(), Some("service"));
    assert_eq!(parsed_filter.include_expired, Some(true));
    assert!(AssignUserRoleInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(UserRoleFilterInput::parse(Some(Value::Boolean(true))).is_err());
    let wrong_subject = object(vec![
        ("subject", Value::Boolean(true)),
        ("roleId", text(ROLE)),
        ("scope", object(vec![("kind", text("global"))])),
    ]);
    let wrong_scope = object(vec![
        (
            "subject",
            object(vec![("kind", text("user")), ("id", text(USER))]),
        ),
        ("roleId", text(ROLE)),
        ("scope", Value::Boolean(true)),
    ]);
    assert!(AssignUserRoleInput::parse(Some(wrong_subject)).is_err());
    assert!(AssignUserRoleInput::parse(Some(wrong_scope)).is_err());
    let subject = || object(vec![("kind", text("user")), ("id", text(USER))]);
    let scope = || object(vec![("kind", text("project")), ("projectId", text("p-1"))]);
    for field in ["kind", "id"] {
        let mut fields = vec![("kind", text("user")), ("id", text(USER))];
        fields.push((field, Value::Boolean(true)));
        let wrong = object(vec![
            ("subject", object(fields)),
            ("roleId", text(ROLE)),
            ("scope", scope()),
        ]);
        assert!(
            AssignUserRoleInput::parse(Some(wrong)).is_err(),
            "subject {field}"
        );
    }
    for field in ["kind", "projectId"] {
        let mut fields = vec![("kind", text("project")), ("projectId", text("p-1"))];
        fields.push((field, Value::Boolean(true)));
        let wrong = object(vec![
            ("subject", subject()),
            ("roleId", text(ROLE)),
            ("scope", object(fields)),
        ]);
        assert!(
            AssignUserRoleInput::parse(Some(wrong)).is_err(),
            "scope {field}"
        );
    }
    for field in ["roleId", "expiresAt", "idempotencyKey"] {
        let wrong = object(vec![
            ("subject", subject()),
            ("roleId", text(ROLE)),
            ("scope", scope()),
            (field, Value::Boolean(true)),
        ]);
        assert!(AssignUserRoleInput::parse(Some(wrong)).is_err(), "{field}");
    }
    for field in [
        "subjectKind",
        "subjectId",
        "roleId",
        "projectId",
        "includeExpired",
    ] {
        let wrong = object(vec![(field, Value::List(Vec::new()))]);
        assert!(UserRoleFilterInput::parse(Some(wrong)).is_err(), "{field}");
    }
}

fn updated(version: i64) -> Answers {
    Answers {
        receipt: receipt_at(version, Some(5)),
        user_role: Ok(Some(user_role(version))),
        ..Answers::default()
    }
}

#[tokio::test]
async fn an_updated_assignment_returns_its_data_and_dispatches_the_command() {
    let (state, commands, queries, asked) = scenario(updated(2));
    let variables = json!({ "input": {
        "id": USER_ROLE,
        "expectedVersion": 1,
        "expiresAt": "2027-01-15T08:00:00Z",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, UPDATE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "updateUserRole": {
            "id": USER_ROLE,
            "roleName": "Billing",
            "expiresAt": null,
            "version": 2,
        } })
    );
    assert_eq!(commands.dispatched(), ["UpdateUserRoleCommand"]);
    assert_eq!(
        queries.asked(),
        ["GetChangeReceiptQuery", "GetUserRoleQuery"]
    );
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].actor, ActorRef::User(Uuid::parse(USER).unwrap()));
    assert_eq!(sent[0].user_role_id, UserRoleId::parse(USER_ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert!(sent[0].expires_at.is_some());
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_null_expiry_clears_the_expiry_and_the_key_travels_with_the_command() {
    let (state, _commands, _queries, asked) = scenario(updated(2));
    let variables = json!({ "input": {
        "id": USER_ROLE,
        "expectedVersion": 1,
        "expiresAt": null,
        "idempotencyKey": "clear-billing",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, UPDATE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].expires_at, None);
    assert_eq!(
        sent[0]
            .idempotency
            .as_ref()
            .map(|request| request.key.as_str()),
        Some("clear-billing")
    );
}

#[rstest]
#[case::missing_expiry(json!({ "id": USER_ROLE, "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[case::invalid_expiry(json!({ "id": USER_ROLE, "expectedVersion": 1, "expiresAt": "soon" }), "VALIDATION_FAILED")]
#[case::missing_version(json!({ "id": USER_ROLE, "expiresAt": null }), "PRECONDITION_REQUIRED")]
#[case::stale_version(json!({ "id": USER_ROLE, "expectedVersion": 0, "expiresAt": null }), "PRECONDITION_FAILED")]
#[case::bad_id(json!({ "id": "x", "expectedVersion": 1, "expiresAt": null }), "VALIDATION_FAILED")]
#[case::bad_key(json!({ "id": USER_ROLE, "expectedVersion": 1, "expiresAt": null, "idempotencyKey": "" }), "VALIDATION_FAILED")]
#[tokio::test]
async fn an_invalid_update_input_is_refused_before_any_command(
    #[case] input: serde_json::Value,
    #[case] expected: &str,
) {
    let (state, commands, _queries, _asked) = scenario(updated(2));

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        UPDATE,
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[tokio::test]
async fn a_missing_expiry_is_a_violation_of_expires_at() {
    let (state, _commands, _queries, _asked) = scenario(updated(2));
    let variables = json!({ "input": { "id": USER_ROLE, "expectedVersion": 1 } });

    let response = run(&schema(Some(state)), Caller::Valid, UPDATE, variables).await;

    assert_eq!(violation_paths(&response), ["\"expiresAt\""]);
}

#[rstest]
#[case::stale(Answers { update: Err(|| IamError::PreconditionFailed), ..updated(2) }, "PRECONDITION_FAILED")]
#[case::unknown(Answers { update: Err(|| IamError::NotFound), ..updated(2) }, "NOT_FOUND")]
#[case::conflict(Answers { update: Err(|| IamError::Conflict), ..updated(2) }, "CONFLICT")]
#[case::last_administrator(Answers { update: Err(|| IamError::LastAdministrator), ..updated(2) }, "LAST_ADMINISTRATOR")]
#[case::past_expiry(
    Answers {
        update: Err(|| IamError::invalid_property("expiresAt", "in the past", "future")),
        ..updated(2)
    },
    "VALIDATION_FAILED"
)]
#[case::replay_mismatch(
    Answers { replay: Err(|| IamError::IdempotencyMismatch), ..updated(2) },
    "VALIDATION_FAILED"
)]
#[tokio::test]
async fn a_refused_update_has_the_code_of_its_error(
    #[case] answers: Answers,
    #[case] expected: &str,
) {
    let (state, _commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": {
        "id": USER_ROLE,
        "expectedVersion": 1,
        "expiresAt": "2027-01-15T08:00:00Z",
        "idempotencyKey": "k",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, UPDATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[tokio::test]
async fn a_revoked_assignment_returns_its_final_version_and_the_policy_version() {
    let (state, commands, queries, asked) = scenario(updated(2));
    let variables = json!({ "input": { "id": USER_ROLE, "expectedVersion": 1 } });

    let response = run(&schema(Some(state)), Caller::Valid, REVOKE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "revokeUserRole": { "id": USER_ROLE, "version": 2, "policyVersion": 5 } })
    );
    assert_eq!(commands.dispatched(), ["RevokeUserRoleCommand"]);
    assert_eq!(queries.asked(), ["GetChangeReceiptQuery"]);
    let sent = recorded(&asked.revocations);
    assert_eq!(sent[0].user_role_id, UserRoleId::parse(USER_ROLE).unwrap());
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].idempotency, None);
}

#[tokio::test]
async fn a_replayed_revocation_returns_the_original_result_without_a_command() {
    let answers = Answers {
        replay: Ok(Some(receipt_at(2, None))),
        ..updated(2)
    };
    let (state, commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": {
        "id": USER_ROLE,
        "expectedVersion": 1,
        "idempotencyKey": "revoke-billing",
    } });

    let response = run(&schema(Some(state)), Caller::Valid, REVOKE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "revokeUserRole": { "id": USER_ROLE, "version": 2, "policyVersion": null } })
    );
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::missing_version(json!({ "id": USER_ROLE }), "PRECONDITION_REQUIRED")]
#[case::stale_version(json!({ "id": USER_ROLE, "expectedVersion": 0 }), "PRECONDITION_FAILED")]
#[case::bad_id(json!({ "id": "x", "expectedVersion": 1 }), "VALIDATION_FAILED")]
#[tokio::test]
async fn an_invalid_revocation_input_is_refused_before_any_command(
    #[case] input: serde_json::Value,
    #[case] expected: &str,
) {
    let (state, commands, _queries, _asked) = scenario(updated(2));

    let response = run(
        &schema(Some(state)),
        Caller::Valid,
        REVOKE,
        json!({ "input": input }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
}

#[rstest]
#[case::stale(Answers { revoke: Err(|| IamError::PreconditionFailed), ..updated(2) }, "PRECONDITION_FAILED")]
#[case::unknown(Answers { revoke: Err(|| IamError::NotFound), ..updated(2) }, "NOT_FOUND")]
#[case::last_administrator(Answers { revoke: Err(|| IamError::LastAdministrator), ..updated(2) }, "LAST_ADMINISTRATOR")]
#[case::storage(
    Answers { revoke: Err(|| IamError::Storage("disk on fire".into())), ..updated(2) },
    "INTERNAL_SERVER_ERROR"
)]
#[tokio::test]
async fn a_refused_revocation_has_the_code_of_its_error(
    #[case] answers: Answers,
    #[case] expected: &str,
) {
    let (state, _commands, _queries, _asked) = scenario(answers);
    let variables = json!({ "input": { "id": USER_ROLE, "expectedVersion": 1 } });

    let response = run(&schema(Some(state)), Caller::Valid, REVOKE, variables).await;

    assert_eq!(error_code(&response), Some(code_of(expected)));
}

#[rstest]
#[case::refused(Caller::Refused)]
#[case::absent(Caller::Absent)]
#[tokio::test]
async fn the_change_fields_need_an_authenticated_caller(#[case] caller: Caller) {
    let (state, commands, queries, _asked) = scenario(updated(2));
    let schema = schema(Some(state));

    let update = run(
        &schema,
        caller,
        UPDATE,
        json!({ "input": { "id": USER_ROLE, "expectedVersion": 1, "expiresAt": null } }),
    )
    .await;
    let revoke = run(
        &schema,
        Caller::Absent,
        REVOKE,
        json!({ "input": { "id": USER_ROLE, "expectedVersion": 1 } }),
    )
    .await;

    for response in [update, revoke] {
        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    }
    assert_eq!(commands.dispatched(), Vec::<&str>::new());
    assert_eq!(queries.asked(), Vec::<&str>::new());
}

#[test]
fn the_update_and_revocation_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::{InputType as _, MaybeUndefined, Name};

    use crate::graphql::user_role::{RevokeUserRoleInput, UpdateUserRoleInput};

    let object = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };
    let update = object(vec![
        ("id", Value::String(USER_ROLE.to_owned())),
        ("expectedVersion", Value::from(3)),
        ("expiresAt", Value::Null),
        ("idempotencyKey", Value::String("clear".to_owned())),
    ]);
    let revoke = object(vec![
        ("id", Value::String(USER_ROLE.to_owned())),
        ("expectedVersion", Value::from(4)),
    ]);

    let parsed_update = UpdateUserRoleInput::parse(Some(update)).unwrap();
    let parsed_revoke = RevokeUserRoleInput::parse(Some(revoke)).unwrap();

    assert_eq!(parsed_update.id.as_str(), USER_ROLE);
    assert_eq!(parsed_update.expected_version, Some(3));
    assert!(matches!(parsed_update.expires_at, MaybeUndefined::Null));
    assert_eq!(parsed_update.idempotency_key.as_deref(), Some("clear"));
    assert_eq!(parsed_revoke.id.as_str(), USER_ROLE);
    assert_eq!(parsed_revoke.expected_version, Some(4));
    assert!(UpdateUserRoleInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(RevokeUserRoleInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["expectedVersion", "expiresAt", "idempotencyKey"] {
        let wrong = object(vec![
            ("id", Value::String(USER_ROLE.to_owned())),
            (field, Value::List(Vec::new())),
        ]);
        assert!(UpdateUserRoleInput::parse(Some(wrong)).is_err(), "{field}");
    }
    for field in ["expectedVersion", "idempotencyKey"] {
        let wrong = object(vec![
            ("id", Value::String(USER_ROLE.to_owned())),
            (field, Value::List(Vec::new())),
        ]);
        assert!(RevokeUserRoleInput::parse(Some(wrong)).is_err(), "{field}");
    }
}
