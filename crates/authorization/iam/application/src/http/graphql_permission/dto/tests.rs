use iam_domain::{GqlName, PermissionId, ServiceName};
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{
    GraphQlPermissionPageResponse, GraphQlPermissionResponse, ListGraphQlPermissionsParams,
};
use crate::error::IamError;
use crate::graphql_permission_fixtures::{PERMISSION, ROLE, VERSION, view, view_of};
use crate::query::get_graphql_permissions::{GetGraphQlPermissionsQuery, GraphQlPermissionPage};

fn params() -> ListGraphQlPermissionsParams {
    ListGraphQlPermissionsParams::default()
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
fn a_field_entry_is_rendered_with_its_type_field_flags_versions_and_roles() {
    let response = GraphQlPermissionResponse::from(view());

    assert_eq!(response.id, PERMISSION);
    assert_eq!(response.key, "gql:billing:Mutation.pay");
    assert_eq!(response.service, "billing");
    assert_eq!(response.type_name, "Mutation");
    assert_eq!(response.field, "pay");
    assert!(response.flags.sensitive);
    assert!(!response.flags.audit_always);
    assert!(response.active);
    assert_eq!(response.versions, [VERSION]);
    assert_eq!(response.roles, [ROLE]);
}

#[test]
fn the_type_is_serialised_as_type() {
    let body = serde_json::to_value(GraphQlPermissionResponse::from(view())).unwrap();

    assert_eq!(body["type"], json!("Mutation"));
    assert!(body.get("typeName").is_none());
    assert_eq!(body["flags"]["auditAlways"], json!(false));
}

#[test]
fn the_introspection_entry_names_the_introspection_as_type_and_field() {
    let response = GraphQlPermissionResponse::from(view_of("gql:billing:__introspection"));

    assert_eq!(response.type_name, "__introspection");
    assert_eq!(response.field, "__introspection");
}

#[test]
fn a_key_that_is_not_a_graphql_field_shows_the_introspection_name() {
    let response = GraphQlPermissionResponse::from(view_of("rest:billing:GET /invoices"));

    assert_eq!(response.type_name, "__introspection");
}

#[test]
fn a_page_response_lists_its_items_and_names_the_cursor_of_the_next_page() {
    let page = GraphQlPermissionPageResponse::from(GraphQlPermissionPage {
        permissions: vec![view()],
        next_after: Some(PermissionId::parse(PERMISSION).unwrap()),
    });
    let last = GraphQlPermissionPageResponse::from(GraphQlPermissionPage {
        permissions: Vec::new(),
        next_after: None,
    });

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some(PERMISSION));
    assert_eq!(last.items, Vec::new());
    assert_eq!(last.next_cursor, None);
    assert!(
        serde_json::to_value(&last)
            .unwrap()
            .get("nextCursor")
            .is_none()
    );
}

#[test]
fn the_list_parameters_default_to_the_first_page_of_thirty_without_filters() {
    let query = params().into_query().unwrap();

    assert_eq!(
        query,
        GetGraphQlPermissionsQuery {
            limit: 30,
            after: None,
            service: None,
            type_name: None,
            active: None,
            sensitive: None,
            key_prefix: None,
        }
    );
}

#[test]
fn the_list_parameters_become_the_query_filters() {
    let query = ListGraphQlPermissionsParams {
        limit: 5,
        after: Some(PERMISSION.to_owned()),
        service: Some("billing".to_owned()),
        type_name: Some("Query".to_owned()),
        active: Some(false),
        sensitive: Some(true),
        key_prefix: Some("gql:billing:".to_owned()),
    }
    .into_query()
    .unwrap();

    assert_eq!(
        query,
        GetGraphQlPermissionsQuery {
            limit: 5,
            after: Some(PermissionId::parse(PERMISSION).unwrap()),
            service: Some(ServiceName::new("billing").unwrap()),
            type_name: Some(GqlName::parse("Query").unwrap()),
            active: Some(false),
            sensitive: Some(true),
            key_prefix: Some("gql:billing:".to_owned()),
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
    let parameters = ListGraphQlPermissionsParams { limit, ..params() };

    assert_eq!(parameters.validate().is_ok(), valid);
}

#[rstest]
#[case::service(ListGraphQlPermissionsParams { service: Some("a".repeat(64)), ..params() }, ListGraphQlPermissionsParams { service: Some("a".repeat(63)), ..params() })]
#[case::type_name(ListGraphQlPermissionsParams { type_name: Some("a".repeat(256)), ..params() }, ListGraphQlPermissionsParams { type_name: Some("a".repeat(255)), ..params() })]
#[case::key_prefix(ListGraphQlPermissionsParams { key_prefix: Some("a".repeat(513)), ..params() }, ListGraphQlPermissionsParams { key_prefix: Some("a".repeat(512)), ..params() })]
fn a_text_filter_has_a_longest_value(
    #[case] too_long: ListGraphQlPermissionsParams,
    #[case] longest: ListGraphQlPermissionsParams,
) {
    assert!(too_long.validate().is_err());
    assert!(longest.validate().is_ok());
}

#[test]
fn every_invalid_filter_is_a_violation_of_its_own_parameter() {
    let error = ListGraphQlPermissionsParams {
        after: Some("not-a-uuid".to_owned()),
        service: Some("Not A Service".to_owned()),
        type_name: Some("1Bad".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [
            ("after".to_owned(), "uuid".to_owned()),
            ("service".to_owned(), "pattern".to_owned()),
            ("type".to_owned(), "pattern".to_owned()),
        ]
    );
}

#[test]
fn a_single_invalid_type_is_one_violation() {
    let error = ListGraphQlPermissionsParams {
        type_name: Some("1Bad".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [("type".to_owned(), "pattern".to_owned())]
    );
}

#[test]
fn the_list_parameters_refuse_unknown_members_and_read_the_type_member() {
    let parsed = serde_json::from_value::<ListGraphQlPermissionsParams>(
        json!({"type": "Query", "keyPrefix": "gql:"}),
    );
    let unknown = serde_json::from_value::<ListGraphQlPermissionsParams>(json!({"colour": 1}));

    assert_eq!(parsed.unwrap().type_name.as_deref(), Some("Query"));
    assert!(unknown.is_err());
}
