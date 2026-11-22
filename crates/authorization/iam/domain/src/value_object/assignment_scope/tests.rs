use rstest::rstest;

use super::AssignmentScope;
use crate::error::InvalidIamValue;
use crate::value_object::identifier::ProjectId;

fn project() -> ProjectId {
    ProjectId::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap()
}

#[test]
fn a_global_scope_has_no_project() {
    let scope = AssignmentScope::from_parts("global", None).unwrap();

    assert_eq!(scope, AssignmentScope::Global);
    assert_eq!(scope.kind(), "global");
    assert_eq!(scope.project_id(), None);
}

#[test]
fn a_project_scope_has_its_project() {
    let scope = AssignmentScope::from_parts("project", Some(project())).unwrap();

    assert_eq!(scope, AssignmentScope::Project(project()));
    assert_eq!(scope.kind(), "project");
    assert_eq!(scope.project_id(), Some(project()));
}

#[test]
fn a_project_scope_without_a_project_id_is_rejected() {
    assert_eq!(
        AssignmentScope::from_parts("project", None),
        Err(InvalidIamValue::ScopeProjectMissing)
    );
}

#[test]
fn a_global_scope_with_a_project_id_is_rejected() {
    assert_eq!(
        AssignmentScope::from_parts("global", Some(project())),
        Err(InvalidIamValue::ScopeProjectUnexpected)
    );
}

#[rstest]
#[case("")]
#[case("Global")]
#[case("tenant")]
fn an_unknown_kind_is_rejected(#[case] kind: &str) {
    assert_eq!(
        AssignmentScope::from_parts(kind, Some(project())),
        Err(InvalidIamValue::ScopeKind)
    );
    assert_eq!(
        AssignmentScope::from_parts(kind, None),
        Err(InvalidIamValue::ScopeKind)
    );
}

#[test]
fn the_text_form_round_trips_both_scopes() {
    let project_scope = AssignmentScope::Project(project());

    assert_eq!(AssignmentScope::Global.to_string(), "global");
    assert_eq!(
        project_scope.to_string(),
        "project:0190f2a8-7b3c-7d4e-8f00-123456789abc"
    );
    assert_eq!(
        AssignmentScope::parse("global"),
        Ok(AssignmentScope::Global)
    );
    assert_eq!(
        AssignmentScope::parse(&project_scope.to_string()),
        Ok(project_scope)
    );
}

#[rstest]
#[case("")]
#[case("Global")]
#[case("global:")]
#[case("project")]
#[case("tenant:0190f2a8-7b3c-7d4e-8f00-123456789abc")]
fn an_unknown_text_form_is_rejected(#[case] text: &str) {
    assert_eq!(
        AssignmentScope::parse(text),
        Err(InvalidIamValue::ScopeKind)
    );
}

#[test]
fn a_project_text_form_without_a_uuid_is_rejected() {
    assert_eq!(
        AssignmentScope::parse("project:not-a-uuid"),
        Err(InvalidIamValue::Identifier)
    );
}
