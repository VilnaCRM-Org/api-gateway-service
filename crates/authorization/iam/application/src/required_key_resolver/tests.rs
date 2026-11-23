use iam_domain::{
    AccessCheck, AccessTarget, DecisionReason, DecisionVerdict, GqlName, GraphQlCoordinate,
    GraphQlField, GraphQlTarget, GraphQlTypeGraph, HttpMethod, PathTemplate, PermissionFlags,
    PermissionsTarget, RestOperation, RestOperationSet, RestTarget, ServiceCatalog, ServiceName,
};
use rstest::rstest;
use test_support::policy_epoch::seeded_policy_epoch;

use super::RequiredKeyResolver;

fn service() -> ServiceName {
    ServiceName::new("orders").unwrap()
}

fn operation(method: HttpMethod, template: &str, flags: PermissionFlags) -> RestOperation {
    RestOperation {
        method,
        template: PathTemplate::from_openapi_path(template).unwrap(),
        label: None,
        flags,
    }
}

fn operations() -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for item in [
        operation(HttpMethod::Get, "/api/orders", PermissionFlags::NONE),
        operation(
            HttpMethod::Get,
            "/api/orders/{id}",
            PermissionFlags::NONE.with_audit_always(),
        ),
        operation(HttpMethod::Get, "/api/orders/batch", PermissionFlags::NONE),
        operation(
            HttpMethod::Delete,
            "/api/orders/{id}",
            PermissionFlags::NONE.with_sensitive(),
        ),
    ] {
        set.insert(item).unwrap();
    }
    set
}

fn type_graph() -> GraphQlTypeGraph {
    let field = |coordinate: &str, flags: PermissionFlags| {
        (
            GraphQlCoordinate::parse(coordinate).unwrap(),
            GraphQlField {
                return_type: GqlName::parse("Order").unwrap(),
                flags,
            },
        )
    };
    GraphQlTypeGraph::new(
        [
            field("Query.order", PermissionFlags::NONE),
            field(
                "Mutation.cancelOrder",
                PermissionFlags::NONE.with_sensitive(),
            ),
        ],
        [],
    )
    .unwrap()
}

fn catalog() -> ServiceCatalog {
    ServiceCatalog::new(
        service(),
        seeded_policy_epoch(),
        vec![operations()],
        vec![type_graph()],
    )
}

fn rest_check(method: HttpMethod, path: &str) -> AccessCheck {
    AccessCheck::new(
        service(),
        AccessTarget::Rest(RestTarget::new(method, path.to_owned())),
        None,
        None,
    )
}

fn keys_check(keys: &[&str]) -> AccessCheck {
    let keys = keys.iter().map(|&key| key.to_owned()).collect();
    AccessCheck::new(
        service(),
        AccessTarget::Permissions(PermissionsTarget::new(keys).unwrap()),
        None,
        None,
    )
}

fn resolved(check: &AccessCheck) -> Vec<(String, PermissionFlags)> {
    RequiredKeyResolver::resolve(check, &catalog())
        .unwrap()
        .iter()
        .map(|required| (required.key().to_string(), required.flags()))
        .collect()
}

fn refused(check: &AccessCheck) -> DecisionVerdict {
    RequiredKeyResolver::resolve(check, &catalog()).unwrap_err()
}

#[rstest]
#[case(HttpMethod::Get, "/api/orders", "rest:orders:GET /api/orders")]
#[case(HttpMethod::Get, "/api/orders/42", "rest:orders:GET /api/orders/{}")]
#[case(
    HttpMethod::Get,
    "/api/orders/batch",
    "rest:orders:GET /api/orders/batch"
)]
#[case(HttpMethod::Get, "/api/orders/?page=2", "rest:orders:GET /api/orders")]
fn a_rest_target_resolves_to_the_key_of_its_template(
    #[case] method: HttpMethod,
    #[case] path: &str,
    #[case] expected: &str,
) {
    let keys = resolved(&rest_check(method, path));

    assert_eq!(keys.len(), 1);
    assert_eq!(keys.first().map(|(key, _)| key.as_str()), Some(expected));
}

#[test]
fn a_rest_key_carries_the_flags_of_its_operation() {
    let keys = resolved(&rest_check(HttpMethod::Delete, "/api/orders/42"));

    assert_eq!(
        keys,
        vec![(
            "rest:orders:DELETE /api/orders/{}".to_owned(),
            PermissionFlags::NONE.with_sensitive()
        )]
    );
}

#[rstest]
#[case(HttpMethod::Get, "/api/unknown")]
#[case(HttpMethod::Post, "/api/orders")]
#[case(HttpMethod::Put, "/api/orders/42")]
fn a_rest_target_that_no_operation_matches_is_an_unknown_operation(
    #[case] method: HttpMethod,
    #[case] path: &str,
) {
    let verdict = refused(&rest_check(method, path));

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
    assert_eq!(verdict.denied(), Vec::<String>::new());
}

#[rstest]
#[case("api/orders")]
#[case("/api/../orders")]
#[case("/api/%zz")]
fn a_malformed_rest_path_is_a_malformed_operation(#[case] path: &str) {
    let verdict = refused(&rest_check(HttpMethod::Get, path));

    assert_eq!(verdict.reason(), DecisionReason::MalformedOperation);
}

#[test]
fn a_service_without_a_rest_version_has_no_rest_operation() {
    let catalog = ServiceCatalog::new(service(), seeded_policy_epoch(), Vec::new(), Vec::new());

    let verdict =
        RequiredKeyResolver::resolve(&rest_check(HttpMethod::Get, "/api/orders"), &catalog)
            .unwrap_err();

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
}

#[test]
fn known_permission_keys_resolve_in_request_order_with_their_flags() {
    let keys = resolved(&keys_check(&[
        "rest:orders:DELETE /api/orders/{}",
        "gql:orders:Query.order",
        "gql:orders:Mutation.cancelOrder",
        "gql:orders:__introspection",
    ]));

    assert_eq!(
        keys,
        vec![
            (
                "rest:orders:DELETE /api/orders/{}".to_owned(),
                PermissionFlags::NONE.with_sensitive()
            ),
            ("gql:orders:Query.order".to_owned(), PermissionFlags::NONE),
            (
                "gql:orders:Mutation.cancelOrder".to_owned(),
                PermissionFlags::NONE.with_sensitive()
            ),
            (
                "gql:orders:__introspection".to_owned(),
                PermissionFlags::NONE
            ),
        ]
    );
}

#[test]
fn reserved_keys_are_accepted_without_a_catalogue_entry() {
    let keys = resolved(&keys_check(&["iam:validate:*", "iam:grant:sensitive"]));

    assert_eq!(
        keys,
        vec![
            ("iam:validate:*".to_owned(), PermissionFlags::NONE),
            ("iam:grant:sensitive".to_owned(), PermissionFlags::NONE),
        ]
    );
}

#[test]
fn the_maximum_number_of_keys_resolves() {
    let raw: Vec<String> = (0..PermissionsTarget::MAX_KEYS)
        .map(|_| "gql:orders:Query.order".to_owned())
        .collect();
    let refs: Vec<&str> = raw.iter().map(String::as_str).collect();

    assert_eq!(
        resolved(&keys_check(&refs)).len(),
        PermissionsTarget::MAX_KEYS
    );
}

#[rstest]
#[case("rest:orders:GET /api/missing")]
#[case("gql:orders:Query.missing")]
#[case("rest:billing:GET /api/orders")]
#[case("gql:billing:Query.order")]
#[case("iam:cache:flush")]
#[case("not a key")]
fn an_unknown_key_is_an_unknown_operation_that_lists_it(#[case] unknown: &str) {
    let verdict = refused(&keys_check(&["gql:orders:Query.order", unknown]));

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
    assert_eq!(verdict.denied(), [unknown.to_owned()]);
}

#[test]
fn every_offending_key_is_listed_once_in_request_order() {
    let verdict = refused(&keys_check(&[
        "gql:billing:Query.order",
        "gql:orders:Query.order",
        "gql:orders:Query.missing",
        "gql:billing:Query.order",
    ]));

    assert_eq!(
        verdict.denied(),
        [
            "gql:billing:Query.order".to_owned(),
            "gql:orders:Query.missing".to_owned()
        ]
    );
}

#[test]
fn a_service_without_a_graphql_version_has_no_graphql_key_not_even_introspection() {
    let catalog = ServiceCatalog::new(
        service(),
        seeded_policy_epoch(),
        vec![operations()],
        Vec::new(),
    );

    let verdict =
        RequiredKeyResolver::resolve(&keys_check(&["gql:orders:__introspection"]), &catalog)
            .unwrap_err();

    assert_eq!(verdict.denied(), ["gql:orders:__introspection".to_owned()]);
}

fn document_field(
    coordinate: &str,
    return_type: &str,
    flags: PermissionFlags,
) -> (GraphQlCoordinate, GraphQlField) {
    (
        GraphQlCoordinate::parse(coordinate).unwrap(),
        GraphQlField {
            return_type: GqlName::parse(return_type).unwrap(),
            flags,
        },
    )
}

/// The first active version: orders can be read, cancelled and priced.
fn first_version() -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        [
            document_field("Query.order", "Order", PermissionFlags::NONE),
            document_field(
                "Mutation.cancelOrder",
                "Order",
                PermissionFlags::NONE.with_sensitive(),
            ),
            document_field("Order.id", "ID", PermissionFlags::NONE),
            document_field(
                "Order.total",
                "Int",
                PermissionFlags::NONE.with_audit_always(),
            ),
        ],
        [],
    )
    .unwrap()
}

/// The second active version: it adds refunds and keeps the order query.
fn second_version() -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        [
            document_field("Query.order", "Order", PermissionFlags::NONE),
            document_field("Query.refund", "Refund", PermissionFlags::NONE),
            document_field("Refund.id", "ID", PermissionFlags::NONE),
        ],
        [],
    )
    .unwrap()
}

fn document_catalog(versions: Vec<GraphQlTypeGraph>) -> ServiceCatalog {
    ServiceCatalog::new(
        service(),
        seeded_policy_epoch(),
        vec![operations()],
        versions,
    )
}

fn document_check(document: &str, operation_name: Option<&str>) -> AccessCheck {
    AccessCheck::new(
        service(),
        AccessTarget::GraphQl(GraphQlTarget::new(
            document.to_owned(),
            operation_name.map(str::to_owned),
        )),
        None,
        None,
    )
}

fn document_keys(
    document: &str,
    operation_name: Option<&str>,
    versions: Vec<GraphQlTypeGraph>,
) -> Vec<(String, PermissionFlags)> {
    RequiredKeyResolver::resolve(
        &document_check(document, operation_name),
        &document_catalog(versions),
    )
    .unwrap()
    .iter()
    .map(|required| (required.key().to_string(), required.flags()))
    .collect()
}

fn document_refusal(
    document: &str,
    operation_name: Option<&str>,
    versions: Vec<GraphQlTypeGraph>,
) -> DecisionVerdict {
    RequiredKeyResolver::resolve(
        &document_check(document, operation_name),
        &document_catalog(versions),
    )
    .unwrap_err()
}

#[test]
fn a_document_requires_the_key_of_every_coordinate_it_selects_with_its_flags() {
    let keys = document_keys("{ order { id total } }", None, vec![first_version()]);

    assert_eq!(
        keys,
        [
            ("gql:orders:Order.id".to_owned(), PermissionFlags::NONE),
            (
                "gql:orders:Order.total".to_owned(),
                PermissionFlags::NONE.with_audit_always()
            ),
            ("gql:orders:Query.order".to_owned(), PermissionFlags::NONE),
        ]
    );
}

#[test]
fn a_mutation_requires_its_sensitive_key() {
    let keys = document_keys(
        "mutation { cancelOrder { id } }",
        None,
        vec![first_version()],
    );

    assert!(keys.contains(&(
        "gql:orders:Mutation.cancelOrder".to_owned(),
        PermissionFlags::NONE.with_sensitive()
    )));
}

#[test]
fn the_named_operation_is_the_one_that_is_resolved() {
    let document = "query A { order { id } } mutation B { cancelOrder { id } }";

    let keys = document_keys(document, Some("B"), vec![first_version()]);

    assert!(
        keys.iter()
            .any(|(key, _)| key == "gql:orders:Mutation.cancelOrder")
    );
    assert!(keys.iter().all(|(key, _)| key != "gql:orders:Query.order"));
}

#[test]
fn introspection_requires_the_introspection_key_without_flags() {
    let keys = document_keys(
        "{ __schema { queryType { name } } order { id } }",
        None,
        vec![first_version()],
    );

    assert!(keys.contains(&(
        "gql:orders:__introspection".to_owned(),
        PermissionFlags::NONE
    )));
    assert!(keys.iter().any(|(key, _)| key == "gql:orders:Query.order"));
}

#[test]
fn a_document_is_read_against_the_union_of_the_active_versions() {
    let keys = document_keys(
        "{ order { id } refund { id } }",
        None,
        vec![first_version(), second_version()],
    );

    let names: Vec<&str> = keys.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        names,
        [
            "gql:orders:Order.id",
            "gql:orders:Query.order",
            "gql:orders:Query.refund",
            "gql:orders:Refund.id",
        ]
    );
}

#[test]
fn a_field_of_a_new_version_is_unknown_until_that_version_is_active() {
    let verdict = document_refusal("{ refund { id } }", None, vec![first_version()]);

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
}

#[test]
fn a_field_no_active_version_declares_on_a_known_type_is_an_unknown_operation() {
    let verdict = document_refusal("{ order { missing } }", None, vec![first_version()]);

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
    assert_eq!(verdict.denied().len(), 0);
}

#[test]
fn a_service_without_a_graphql_version_has_no_document_to_read() {
    let verdict = document_refusal("{ order { id } }", None, Vec::new());

    assert_eq!(verdict.reason(), DecisionReason::UnknownOperation);
}

#[rstest]
#[case::does_not_parse("{ order { id ")]
#[case::two_operations_without_a_name("query A { order { id } } query B { order { id } }")]
#[case::a_leaf_with_a_selection("{ order { id { x } } }")]
fn a_document_that_cannot_be_read_is_malformed(#[case] document: &str) {
    let verdict = document_refusal(document, None, vec![first_version()]);

    assert_eq!(verdict.reason(), DecisionReason::MalformedOperation);
}

#[test]
fn a_document_over_a_limit_is_refused_before_any_field_is_resolved() {
    let aliases = (0..51)
        .map(|number| format!("a{number}: order {{ id }} "))
        .collect::<Vec<_>>()
        .concat();
    let document = format!("{{ {aliases} }}");

    let verdict = document_refusal(&document, None, vec![first_version()]);

    assert_eq!(verdict.reason(), DecisionReason::LimitsExceeded);
    assert_eq!(verdict.denied().len(), 0);
}

#[test]
fn a_document_over_the_byte_limit_is_refused_as_limits_exceeded() {
    let document = format!("{{ order {{ id }} }} # {}", "x".repeat(70 * 1024));

    let verdict = document_refusal(&document, None, vec![first_version()]);

    assert_eq!(verdict.reason(), DecisionReason::LimitsExceeded);
}
