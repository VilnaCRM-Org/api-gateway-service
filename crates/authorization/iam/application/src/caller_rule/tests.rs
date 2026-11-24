use iam_domain::{ServiceName, SubjectId};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;

use super::{CallerRule, target_services};

fn service(name: &str) -> SubjectId {
    SubjectId::Service(ServiceName::new(name).unwrap())
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

fn named(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn only_a_decision_request_has_to_be_read() {
    assert!(CallerRule::Validate.names_services());
    assert!(!CallerRule::ResolveToken.names_services());
}

#[test]
fn a_validation_needs_each_named_service_once_in_order() {
    let required = CallerRule::Validate
        .required_services(&service("core"), &named(&["payment", "core", "payment"]));

    assert_eq!(required, Some(named(&["core", "payment"])));
}

#[test]
fn a_validation_that_names_no_service_is_admitted_by_the_wildcard_alone() {
    assert_eq!(CallerRule::Validate.required_services(&user(), &[]), None);
}

#[test]
fn a_service_resolving_a_token_needs_the_key_of_its_own_name_whatever_the_request_names() {
    let required =
        CallerRule::ResolveToken.required_services(&service("core"), &named(&["payment"]));

    assert_eq!(required, Some(named(&["core"])));
}

#[test]
fn a_user_resolving_a_token_is_admitted_by_the_wildcard_alone() {
    assert_eq!(
        CallerRule::ResolveToken.required_services(&user(), &[]),
        None
    );
}

#[rstest]
#[case::single(json!({"service": "core", "request_id": "r"}), &["core"])]
#[case::batch(json!({"checks": [{"service": "core"}, {"service": "payment"}]}), &["core", "payment"])]
#[case::list_of_inputs(json!([{"service": "core"}, {"service": "payment"}]), &["core", "payment"])]
#[case::an_item_without_a_text_service_is_unreadable(json!({"checks": [{"service": 5}, {}, "x", {"service": "core"}]}), &["", "", "", "core"])]
#[case::a_scalar_is_unreadable(json!("core"), &[""])]
#[case::an_object_without_a_service_is_unreadable(json!({"credential": "t"}), &[""])]
#[case::a_null_item_is_unreadable(json!([null, {"service": "core"}]), &["", "core"])]
#[case::a_batch_of_no_check_names_nothing(json!({"checks": []}), &[])]
fn the_services_of_a_json_value_are_those_its_checks_name(
    #[case] value: serde_json::Value,
    #[case] expected: &[&str],
) {
    let value = async_graphql::Value::from_json(value).unwrap();

    assert_eq!(target_services(&value), named(expected));
}

#[test]
fn an_unreadable_service_is_admitted_by_the_wildcard_alone() {
    let unreadable = named(&["core", ""]);

    let validating = CallerRule::Validate.required_services(&service("core"), &unreadable);
    let resolving = CallerRule::ResolveToken.required_services(&service("core"), &named(&[""]));

    assert_eq!(validating, Some(named(&["", "core"])));
    assert_eq!(resolving, None);
}
