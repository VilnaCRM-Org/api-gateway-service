use rstest::rstest;

use super::GraphQlCoordinate;
use crate::value_object::gql_name::GqlName;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

fn service(value: &str) -> ServiceName {
    ServiceName::new(value).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

#[rstest]
#[case("Query.invoices", "Query", "invoices")]
#[case("Mutation.createInvoice", "Mutation", "createInvoice")]
#[case("Subscription.invoiceUpdated", "Subscription", "invoiceUpdated")]
#[case("_Private.field_1", "_Private", "field_1")]
fn parses_and_prints_a_coordinate(
    #[case] text: &str,
    #[case] type_name: &str,
    #[case] field: &str,
) {
    let coordinate = GraphQlCoordinate::parse(text).unwrap();

    assert_eq!(coordinate.type_name().as_str(), type_name);
    assert_eq!(coordinate.field().as_str(), field);
    assert_eq!(coordinate.to_string(), text);
    assert_eq!(
        coordinate,
        GraphQlCoordinate::new(
            GqlName::parse(type_name).unwrap(),
            GqlName::parse(field).unwrap()
        )
    );
}

#[rstest]
#[case("")]
#[case("Query")]
#[case("Query.")]
#[case(".invoices")]
#[case("__Schema.types")]
#[case("Query.__typename")]
#[case("Query.in-voices")]
#[case("Query.invoices.total")]
fn refuses_anything_else(#[case] text: &str) {
    assert_eq!(GraphQlCoordinate::parse(text), None);
}

#[test]
fn builds_the_permission_key_of_its_service() {
    let coordinate = GraphQlCoordinate::parse("Query.invoices").unwrap();

    assert_eq!(
        coordinate.permission_key(&service("billing")),
        key("gql:billing:Query.invoices")
    );
}

#[rstest]
#[case("gql:billing:Query.invoices", Some("Query.invoices"))]
#[case("gql:orders:Query.invoices", None)]
#[case("gql:billing:__introspection", None)]
#[case("rest:billing:GET /invoices", None)]
#[case("iam:grant:sensitive", None)]
fn reads_the_coordinate_of_a_key_of_its_service(
    #[case] text: &str,
    #[case] expected: Option<&str>,
) {
    assert_eq!(
        GraphQlCoordinate::from_permission_key(&key(text), &service("billing")),
        expected.map(|value| GraphQlCoordinate::parse(value).unwrap())
    );
}
