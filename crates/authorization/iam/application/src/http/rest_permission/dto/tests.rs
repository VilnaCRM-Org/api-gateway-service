use iam_domain::{HttpMethod, PermissionId, ServiceName};
use rstest::rstest;
use serde_json::json;
use validator::Validate as _;

use super::{ListRestPermissionsParams, RestPermissionPageResponse, RestPermissionResponse};
use crate::error::IamError;
use crate::query::get_rest_permissions::{GetRestPermissionsQuery, RestPermissionPage};
use crate::rest_permission_fixtures::{PERMISSION, ROLE, VERSION, view, view_of};

fn params() -> ListRestPermissionsParams {
    ListRestPermissionsParams::default()
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
fn an_entry_is_rendered_with_its_method_template_flags_versions_and_roles() {
    let response = RestPermissionResponse::from(view());

    assert_eq!(response.id, PERMISSION);
    assert_eq!(response.key, "rest:billing:POST /api/invoices/{}/pay");
    assert_eq!(response.service, "billing");
    assert_eq!(response.method, "POST");
    assert_eq!(response.template, "/api/invoices/{}/pay");
    assert!(response.flags.sensitive);
    assert!(!response.flags.audit_always);
    assert!(response.active);
    assert_eq!(response.versions, [VERSION]);
    assert_eq!(response.roles, [ROLE]);
}

#[test]
fn the_entry_is_serialised_in_camel_case() {
    let body = serde_json::to_value(RestPermissionResponse::from(view())).unwrap();

    assert_eq!(body["flags"]["auditAlways"], json!(false));
    assert_eq!(body["template"], json!("/api/invoices/{}/pay"));
}

#[test]
fn a_key_that_is_not_a_rest_key_shows_an_empty_method_and_template() {
    let response = RestPermissionResponse::from(view_of("gql:billing:Query.invoices"));

    assert_eq!(response.method, "");
    assert_eq!(response.template, "");
}

#[test]
fn a_page_response_lists_its_items_and_names_the_cursor_of_the_next_page() {
    let page = RestPermissionPageResponse::from(RestPermissionPage {
        permissions: vec![view()],
        next_after: Some(PermissionId::parse(PERMISSION).unwrap()),
    });
    let last = RestPermissionPageResponse::from(RestPermissionPage {
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
        GetRestPermissionsQuery {
            limit: 30,
            after: None,
            service: None,
            method: None,
            active: None,
            sensitive: None,
            template_prefix: None,
        }
    );
}

#[test]
fn the_list_parameters_become_the_query_filters() {
    let query = ListRestPermissionsParams {
        limit: 5,
        after: Some(PERMISSION.to_owned()),
        service: Some("billing".to_owned()),
        method: Some("DELETE".to_owned()),
        active: Some(false),
        sensitive: Some(true),
        template_prefix: Some("/api/".to_owned()),
    }
    .into_query()
    .unwrap();

    assert_eq!(
        query,
        GetRestPermissionsQuery {
            limit: 5,
            after: Some(PermissionId::parse(PERMISSION).unwrap()),
            service: Some(ServiceName::new("billing").unwrap()),
            method: Some(HttpMethod::Delete),
            active: Some(false),
            sensitive: Some(true),
            template_prefix: Some("/api/".to_owned()),
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
    let parameters = ListRestPermissionsParams { limit, ..params() };

    assert_eq!(parameters.validate().is_ok(), valid);
}

#[rstest]
#[case::service(ListRestPermissionsParams { service: Some("a".repeat(64)), ..params() }, ListRestPermissionsParams { service: Some("a".repeat(63)), ..params() })]
#[case::method(ListRestPermissionsParams { method: Some("a".repeat(8)), ..params() }, ListRestPermissionsParams { method: Some("a".repeat(7)), ..params() })]
#[case::template_prefix(ListRestPermissionsParams { template_prefix: Some("a".repeat(2049)), ..params() }, ListRestPermissionsParams { template_prefix: Some("a".repeat(2048)), ..params() })]
fn a_text_filter_has_a_longest_value(
    #[case] too_long: ListRestPermissionsParams,
    #[case] longest: ListRestPermissionsParams,
) {
    assert!(too_long.validate().is_err());
    assert!(longest.validate().is_ok());
}

#[test]
fn every_invalid_filter_is_a_violation_of_its_own_parameter() {
    let error = ListRestPermissionsParams {
        after: Some("not-a-uuid".to_owned()),
        service: Some("Not A Service".to_owned()),
        method: Some("get".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [
            ("after".to_owned(), "uuid".to_owned()),
            ("service".to_owned(), "pattern".to_owned()),
            ("method".to_owned(), "choice".to_owned()),
        ]
    );
}

#[test]
fn a_single_invalid_method_is_one_violation() {
    let error = ListRestPermissionsParams {
        method: Some("FETCH".to_owned()),
        ..params()
    }
    .into_query()
    .unwrap_err();

    assert_eq!(
        violations(error),
        [("method".to_owned(), "choice".to_owned())]
    );
}

#[test]
fn the_list_parameters_refuse_unknown_members_and_read_the_template_prefix_member() {
    let parsed = serde_json::from_value::<ListRestPermissionsParams>(
        json!({"method": "GET", "templatePrefix": "/api"}),
    );
    let unknown = serde_json::from_value::<ListRestPermissionsParams>(json!({"colour": 1}));

    assert_eq!(parsed.unwrap().template_prefix.as_deref(), Some("/api"));
    assert!(unknown.is_err());
}
