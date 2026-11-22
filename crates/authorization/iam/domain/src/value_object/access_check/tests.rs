use rstest::rstest;

use super::{AccessCheck, AccessTarget, GraphQlTarget, PermissionsTarget, RestTarget};
use crate::error::InvalidAccessCheck;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::ProjectId;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;

fn keys(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("gql:orders:Query.field{index}"))
        .collect()
}

#[rstest]
#[case(1)]
#[case(2)]
#[case(100)]
fn a_permissions_target_takes_one_to_one_hundred_keys(#[case] count: usize) {
    let target = PermissionsTarget::new(keys(count)).unwrap();

    assert_eq!(target.keys(), keys(count).as_slice());
}

#[rstest]
#[case(0)]
#[case(101)]
fn a_permissions_target_refuses_no_key_or_more_than_one_hundred(#[case] count: usize) {
    assert_eq!(
        PermissionsTarget::new(keys(count)),
        Err(InvalidAccessCheck::PermissionCount)
    );
}

#[test]
fn a_rest_target_keeps_the_method_and_the_raw_path() {
    let target = RestTarget::new(HttpMethod::Get, String::from("/api/orders/7?x=1"));

    assert_eq!(target.method(), HttpMethod::Get);
    assert_eq!(target.path(), "/api/orders/7?x=1");
}

#[test]
fn a_graphql_target_keeps_the_document_and_the_operation_name() {
    let named = GraphQlTarget::new(String::from("query A { a }"), Some(String::from("A")));
    let anonymous = GraphQlTarget::new(String::from("{ a }"), None);

    assert_eq!(named.document(), "query A { a }");
    assert_eq!(named.operation_name(), Some("A"));
    assert_eq!(anonymous.document(), "{ a }");
    assert_eq!(anonymous.operation_name(), None);
}

#[test]
fn a_check_keeps_its_service_target_project_and_minimum_version() {
    let service = ServiceName::new("orders").unwrap();
    let project = ProjectId::parse("00000000-0000-7000-8000-0000000000aa").unwrap();
    let version = PolicyVersion::new(3).unwrap();
    let target = AccessTarget::Permissions(PermissionsTarget::new(keys(1)).unwrap());
    let check = AccessCheck::new(
        service.clone(),
        target.clone(),
        Some(project),
        Some(version),
    );

    assert_eq!(check.service(), &service);
    assert_eq!(check.target(), &target);
    assert_eq!(check.project(), Some(project));
    assert_eq!(check.min_policy_version(), Some(version));
}

#[test]
fn a_check_may_name_no_project_and_no_minimum_version() {
    let target = AccessTarget::Rest(RestTarget::new(HttpMethod::Post, String::from("/a")));
    let check = AccessCheck::new(ServiceName::new("orders").unwrap(), target, None, None);

    assert_eq!(check.project(), None);
    assert_eq!(check.min_policy_version(), None);
}
