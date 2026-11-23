use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, EntityVersion, ProjectId, RoleId, RoleName,
    ServiceName, SubjectKind, SubjectRef, UserRoleId, UserRoleParts,
};
use rstest::rstest;
use serde_json::{Value, json};
use shared_domain::Uuid;
use validator::Validate as _;

use super::{
    AssignUserRoleRequest, ListUserRolesParams, ScopeDto, SubjectDto, UserRolePageResponse,
    UserRoleResponse,
};
use crate::error::IamError;
use crate::query::get_user_role::UserRoleView;
use crate::query::list_user_roles::{ListUserRolesQuery, UserRolePage};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const USER_ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ce";
const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cf";

fn request(body: &Value) -> AssignUserRoleRequest {
    serde_json::from_value(body.clone()).unwrap()
}

fn global_user() -> Value {
    json!({
        "subject": { "kind": "user", "id": USER },
        "roleId": ROLE,
        "scope": { "kind": "global" },
    })
}

fn violations(error: IamError) -> Vec<(String, String)> {
    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| (violation.property_path, violation.code))
        .collect()
}

#[test]
fn a_global_user_assignment_parses_into_its_values() {
    let parsed = request(&global_user()).parse().unwrap();

    assert_eq!(parsed.subject, SubjectRef::user(Uuid::parse(USER).unwrap()));
    assert_eq!(parsed.role_id, RoleId::parse(ROLE).unwrap());
    assert_eq!(parsed.scope, AssignmentScope::Global);
    assert_eq!(parsed.expires_at, None);
}

#[test]
fn a_project_service_assignment_with_an_expiry_parses_into_its_values() {
    let body = json!({
        "subject": { "kind": "service", "id": "billing-worker" },
        "roleId": ROLE,
        "scope": { "kind": "project", "projectId": PROJECT },
        "expiresAt": "2027-01-15T08:00:00Z",
    });

    let parsed = request(&body).parse().unwrap();

    assert_eq!(
        parsed.subject,
        SubjectRef::service(ServiceName::new("billing-worker").unwrap())
    );
    assert_eq!(
        parsed.scope,
        AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
    );
    assert_eq!(parsed.expires_at, Some(at(1_800_000_000)));
}

#[rstest]
#[case::subject_kind(
    json!({"subject": {"kind": "robot", "id": USER}, "roleId": ROLE, "scope": {"kind": "global"}}),
    &[("subject.kind", "choice")]
)]
#[case::user_id(
    json!({"subject": {"kind": "user", "id": "nope"}, "roleId": ROLE, "scope": {"kind": "global"}}),
    &[("subject.id", "uuid")]
)]
#[case::service_name(
    json!({"subject": {"kind": "service", "id": "Billing Worker"}, "roleId": ROLE, "scope": {"kind": "global"}}),
    &[("subject.id", "pattern")]
)]
#[case::role_id(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": "nope", "scope": {"kind": "global"}}),
    &[("roleId", "uuid")]
)]
#[case::scope_kind(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "galaxy"}}),
    &[("scope.kind", "choice")]
)]
#[case::project_missing(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "project"}}),
    &[("scope.projectId", "required")]
)]
#[case::project_unexpected(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "global", "projectId": PROJECT}}),
    &[("scope.projectId", "forbidden")]
)]
#[case::project_not_a_uuid(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "project", "projectId": "nope"}}),
    &[("scope.projectId", "uuid")]
)]
#[case::expiry(
    json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "global"}, "expiresAt": "tomorrow"}),
    &[("expiresAt", "format")]
)]
#[case::everything(
    json!({"subject": {"kind": "robot", "id": USER}, "roleId": "nope", "scope": {"kind": "galaxy"}, "expiresAt": "x"}),
    &[("subject.kind", "choice"), ("roleId", "uuid"), ("scope.kind", "choice"), ("expiresAt", "format")]
)]
fn an_invalid_value_is_a_violation_of_its_property(
    #[case] body: Value,
    #[case] expected: &[(&str, &str)],
) {
    let error = request(&body).parse().unwrap_err();

    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(path, code)| ((*path).to_owned(), (*code).to_owned()))
        .collect();
    assert_eq!(violations(error), expected);
}

#[test]
fn the_request_refuses_unknown_and_missing_members() {
    let unknown = json!({
        "subject": { "kind": "user", "id": USER },
        "roleId": ROLE,
        "scope": { "kind": "global" },
        "extra": 1,
    });
    let unknown_subject = json!({
        "subject": { "kind": "user", "id": USER, "extra": 1 },
        "roleId": ROLE,
        "scope": { "kind": "global" },
    });
    let unknown_scope = json!({
        "subject": { "kind": "user", "id": USER },
        "roleId": ROLE,
        "scope": { "kind": "global", "extra": 1 },
    });
    let missing = json!({ "roleId": ROLE, "scope": { "kind": "global" } });

    for body in [unknown, unknown_subject, unknown_scope, missing] {
        assert!(serde_json::from_value::<AssignUserRoleRequest>(body).is_err());
    }
}

#[rstest]
#[case::empty_kind(json!({"subject": {"kind": "", "id": USER}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.kind")]
#[case::empty_id(json!({"subject": {"kind": "user", "id": ""}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.id")]
#[case::long_id(json!({"subject": {"kind": "user", "id": "a".repeat(256)}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.id")]
#[case::long_kind(json!({"subject": {"kind": "a".repeat(21), "id": USER}, "roleId": ROLE, "scope": {"kind": "global"}}), "subject.kind")]
#[case::empty_role(json!({"subject": {"kind": "user", "id": USER}, "roleId": "", "scope": {"kind": "global"}}), "roleId")]
#[case::empty_scope(json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": ""}}), "scope.kind")]
#[case::long_expiry(json!({"subject": {"kind": "user", "id": USER}, "roleId": ROLE, "scope": {"kind": "global"}, "expiresAt": "2".repeat(41)}), "expiresAt")]
fn the_members_keep_their_lengths(#[case] body: Value, #[case] property: &str) {
    let errors = request(&body).validate().unwrap_err();

    let problem = shared_application::http::Problem::from(errors);
    let paths: Vec<&str> = problem
        .violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, [property]);
}

#[test]
fn a_valid_request_passes_the_validation() {
    assert!(request(&global_user()).validate().is_ok());
}

#[test]
fn the_canonical_form_tells_one_request_from_another() {
    let base = request(&global_user());
    let other_role = AssignUserRoleRequest {
        role_id: PROJECT.to_owned(),
        ..base.clone()
    };
    let other_scope = AssignUserRoleRequest {
        scope: ScopeDto {
            kind: "project".to_owned(),
            project_id: Some(PROJECT.to_owned()),
        },
        ..base.clone()
    };
    let other_subject = AssignUserRoleRequest {
        subject: SubjectDto {
            kind: "service".to_owned(),
            id: "billing".to_owned(),
        },
        ..base.clone()
    };
    let other_expiry = AssignUserRoleRequest {
        expires_at: Some("2027-01-15T08:00:00Z".to_owned()),
        ..base.clone()
    };

    let forms: Vec<String> = [
        base.clone(),
        other_role,
        other_scope,
        other_subject,
        other_expiry,
    ]
    .iter()
    .map(AssignUserRoleRequest::canonical_form)
    .collect();

    assert_eq!(base.canonical_form(), forms[0]);
    for (index, form) in forms.iter().enumerate() {
        assert!(form.starts_with("user_role.assign:"));
        for other in &forms[index + 1..] {
            assert_ne!(form, other);
        }
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn view(
    expires_at: Option<SystemTime>,
    scope: AssignmentScope,
    role_name: Option<&str>,
) -> UserRoleView {
    UserRoleView {
        user_role: UserRoleParts {
            id: UserRoleId::parse(USER_ROLE).unwrap(),
            subject: SubjectRef::user(Uuid::parse(USER).unwrap()),
            role_id: RoleId::parse(ROLE).unwrap(),
            scope,
            expires_at: expires_at.map(AssignmentExpiry::restore),
            version: EntityVersion::new(3).unwrap(),
            created_by: ActorRef::User(Uuid::parse(USER).unwrap()),
            created_at: at(1_800_000_000),
            updated_at: at(1_800_000_060),
            revoked_at: None,
        },
        role_name: role_name.map(|name| RoleName::new(name.to_owned()).unwrap()),
    }
}

#[test]
fn a_global_assignment_without_an_expiry_is_answered_without_those_members() {
    let response = UserRoleResponse::from(view(None, AssignmentScope::Global, Some("Billing")));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "id": USER_ROLE,
            "subject": { "kind": "user", "id": USER },
            "roleId": ROLE,
            "roleName": "Billing",
            "scope": { "kind": "global" },
            "version": 3,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:01:00.000000Z",
        })
    );
}

#[test]
fn a_project_assignment_with_an_expiry_is_answered_with_both() {
    let scope = AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap());

    let response = UserRoleResponse::from(view(Some(at(1_800_003_600)), scope, None));

    let body = serde_json::to_value(response).unwrap();
    assert_eq!(
        body["scope"],
        json!({ "kind": "project", "projectId": PROJECT })
    );
    assert_eq!(body["expiresAt"], "2027-01-15T09:00:00.000000Z");
    assert_eq!(body["roleName"], Value::Null);
}

#[test]
fn a_service_subject_is_answered_with_its_name() {
    let mut service = view(None, AssignmentScope::Global, Some("Billing"));
    service.user_role.subject = SubjectRef::service(ServiceName::new("billing-worker").unwrap());

    let body = serde_json::to_value(UserRoleResponse::from(service)).unwrap();

    assert_eq!(
        body["subject"],
        json!({ "kind": "service", "id": "billing-worker" })
    );
}

#[test]
fn a_page_names_its_cursor_only_when_another_page_follows() {
    let items = vec![view(None, AssignmentScope::Global, Some("Billing"))];
    let more = UserRolePage {
        user_roles: items.clone(),
        next_after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
    };
    let last = UserRolePage {
        user_roles: items,
        next_after: None,
    };

    let more = serde_json::to_value(UserRolePageResponse::from(more)).unwrap();
    let last = serde_json::to_value(UserRolePageResponse::from(last)).unwrap();

    assert_eq!(more["nextCursor"], USER_ROLE);
    assert_eq!(more["items"].as_array().map(Vec::len), Some(1));
    assert!(last.get("nextCursor").is_none());
}

fn params() -> ListUserRolesParams {
    ListUserRolesParams::default()
}

#[test]
fn the_list_parameters_default_to_the_first_page_of_thirty_without_expired_rows() {
    let query = params().into_query().unwrap();

    assert_eq!(
        query,
        ListUserRolesQuery {
            limit: 30,
            after: None,
            subject_kind: None,
            subject_id: None,
            role_id: None,
            project_id: None,
            include_expired: false,
        }
    );
}

#[rstest]
#[case::zero(0, false)]
#[case::one(1, true)]
#[case::hundred(100, true)]
#[case::over(101, false)]
#[case::negative(-1, false)]
fn the_limit_is_between_one_and_one_hundred(#[case] limit: i32, #[case] valid: bool) {
    let parameters = ListUserRolesParams { limit, ..params() };

    assert_eq!(parameters.validate().is_ok(), valid);
}

#[test]
fn the_subject_id_has_at_most_255_characters() {
    let long = ListUserRolesParams {
        subject_id: Some("a".repeat(256)),
        ..params()
    };
    let longest = ListUserRolesParams {
        subject_id: Some("a".repeat(255)),
        ..params()
    };

    assert!(long.validate().is_err());
    assert!(longest.validate().is_ok());
}

#[test]
fn valid_parameters_become_the_query() {
    let parameters = ListUserRolesParams {
        limit: 7,
        after: Some(USER_ROLE.to_owned()),
        subject_kind: Some("service".to_owned()),
        subject_id: Some("billing-worker".to_owned()),
        role_id: Some(ROLE.to_owned()),
        project_id: Some(PROJECT.to_owned()),
        include_expired: true,
    };

    let query = parameters.into_query().unwrap();

    assert_eq!(
        query,
        ListUserRolesQuery {
            limit: 7,
            after: Some(UserRoleId::parse(USER_ROLE).unwrap()),
            subject_kind: Some(SubjectKind::Service),
            subject_id: Some("billing-worker".to_owned()),
            role_id: Some(RoleId::parse(ROLE).unwrap()),
            project_id: Some(ProjectId::parse(PROJECT).unwrap()),
            include_expired: true,
        }
    );
}

#[rstest]
#[case::after(ListUserRolesParams { after: Some("x".to_owned()), ..ListUserRolesParams::default() }, &[("after", "uuid")])]
#[case::kind(ListUserRolesParams { subject_kind: Some("robot".to_owned()), ..ListUserRolesParams::default() }, &[("subjectKind", "choice")])]
#[case::role(ListUserRolesParams { role_id: Some("x".to_owned()), ..ListUserRolesParams::default() }, &[("roleId", "uuid")])]
#[case::project(ListUserRolesParams { project_id: Some("x".to_owned()), ..ListUserRolesParams::default() }, &[("projectId", "uuid")])]
#[case::all(
    ListUserRolesParams {
        after: Some("x".to_owned()),
        subject_kind: Some("robot".to_owned()),
        role_id: Some("x".to_owned()),
        project_id: Some("x".to_owned()),
        ..ListUserRolesParams::default()
    },
    &[("after", "uuid"), ("subjectKind", "choice"), ("roleId", "uuid"), ("projectId", "uuid")]
)]
fn an_invalid_cursor_kind_role_or_project_is_a_violation_each(
    #[case] parameters: ListUserRolesParams,
    #[case] expected: &[(&str, &str)],
) {
    let error = parameters.into_query().unwrap_err();

    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(path, code)| ((*path).to_owned(), (*code).to_owned()))
        .collect();
    assert_eq!(violations(error), expected);
}
