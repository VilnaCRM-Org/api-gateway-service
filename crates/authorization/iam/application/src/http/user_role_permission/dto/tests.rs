use std::collections::BTreeSet;

use iam_domain::{ProjectId, ScopeSet};
use rstest::rstest;

use super::{SCOPE_ALL, UserRolePermissionsParams, UserRolePermissionsResponse, scope_texts};
use crate::error::IamError;
use crate::fixtures::USER;
use crate::user_role_permission_fixtures::{PROJECT, view, view_json};

fn params(project: Option<&str>, service: Option<&str>) -> UserRolePermissionsParams {
    UserRolePermissionsParams {
        project_id: project.map(str::to_owned),
        service: service.map(str::to_owned),
    }
}

fn paths(error: IamError) -> Vec<String> {
    let IamError::Invalid(violations) = error else {
        panic!("expected violations, got {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| violation.property_path)
        .collect()
}

#[test]
fn the_view_has_the_wire_shape_of_the_read_model() {
    let response = UserRolePermissionsResponse::from(&view());

    assert_eq!(serde_json::to_value(response).unwrap(), view_json());
}

#[test]
fn scopes_are_all_or_the_project_ids_in_order() {
    let first = ProjectId::parse(PROJECT).unwrap();
    let second = ProjectId::parse("0190f2a8-7b3c-7d4e-8f20-0000000000c4").unwrap();

    assert_eq!(scope_texts(&ScopeSet::All), [SCOPE_ALL]);
    assert_eq!(
        scope_texts(&ScopeSet::Projects(BTreeSet::from([second, first]))),
        [first.to_string(), second.to_string()]
    );
    assert_eq!(scope_texts(&ScopeSet::empty()), Vec::<String>::new());
}

#[test]
fn valid_parameters_make_the_query_of_the_user() {
    let query = params(Some(PROJECT), Some("billing"))
        .into_query(USER)
        .unwrap();

    assert_eq!(query.subject.id().to_string(), USER);
    assert_eq!(query.project, Some(ProjectId::parse(PROJECT).unwrap()));
    assert_eq!(query.service.unwrap().as_str(), "billing");
}

#[test]
fn no_parameters_make_an_unfiltered_query() {
    let query = params(None, None).into_query(USER).unwrap();

    assert_eq!(query.project, None);
    assert_eq!(query.service, None);
}

#[rstest]
#[case::user("nope", None, None, &["userId"])]
#[case::project(USER, Some("nope"), None, &["projectId"])]
#[case::service(USER, None, Some("Not A Service"), &["service"])]
#[case::all("nope", Some("nope"), Some("Not A Service"), &["userId", "projectId", "service"])]
fn every_invalid_value_is_a_violation_of_its_property(
    #[case] user: &str,
    #[case] project: Option<&str>,
    #[case] service: Option<&str>,
    #[case] expected: &[&str],
) {
    let error = params(project, service).into_query(user).unwrap_err();

    assert_eq!(paths(error), expected);
}
