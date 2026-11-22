use proptest::collection::vec;
use proptest::prelude::*;

use super::PermissionCatalogue;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};
use crate::value_object::rest_operation_set::{RestOperation, RestOperationSet};
use crate::value_object::service_name::ServiceName;

const NONE: PermissionFlags = PermissionFlags::NONE;
const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const AUDIT: PermissionFlags = PermissionFlags::NONE.with_audit_always();

fn billing() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn coordinates(entries: &[(&str, PermissionFlags)]) -> CoordinateSet {
    entries
        .iter()
        .map(|(coordinate, flags)| (GraphQlCoordinate::parse(coordinate).unwrap(), *flags))
        .collect()
}

fn operations(entries: &[(HttpMethod, &str, PermissionFlags)]) -> RestOperationSet {
    let mut set = RestOperationSet::new();
    for (method, path, flags) in entries {
        set.insert(RestOperation {
            method: *method,
            template: PathTemplate::from_openapi_path(path).unwrap(),
            label: None,
            flags: *flags,
        })
        .unwrap();
    }
    set
}

fn graphql_keys(catalogue: &PermissionCatalogue) -> Vec<String> {
    catalogue.iter().map(|(key, _)| key.to_string()).collect()
}

#[test]
fn a_graphql_set_yields_a_key_for_every_field_root_fields_and_the_introspection() {
    let set = coordinates(&[
        ("Query.invoice", NONE),
        ("Mutation.payInvoice", SENSITIVE),
        ("Subscription.invoicePaid", NONE),
        ("Invoice.total", AUDIT),
    ]);

    let catalogue = PermissionCatalogue::for_graphql(&billing(), [&set]);

    assert_eq!(catalogue.service(), &billing());
    assert_eq!(catalogue.kind(), PermissionKeyKind::Gql);
    assert_eq!(catalogue.len(), 5);
    assert!(!catalogue.is_empty());
    let mut expected = vec![
        "gql:billing:Query.invoice",
        "gql:billing:Mutation.payInvoice",
        "gql:billing:Subscription.invoicePaid",
        "gql:billing:Invoice.total",
        "gql:billing:__introspection",
    ];
    expected.sort_by_key(|text| key(text));
    assert_eq!(graphql_keys(&catalogue), expected);
    assert_eq!(
        catalogue.flags(&key("gql:billing:Mutation.payInvoice")),
        Some(SENSITIVE)
    );
    assert_eq!(
        catalogue.flags(&key("gql:billing:Invoice.total")),
        Some(AUDIT)
    );
    assert_eq!(
        catalogue.flags(&key("gql:billing:__introspection")),
        Some(NONE)
    );
}

#[test]
fn a_service_without_an_active_version_has_an_empty_catalogue() {
    let catalogue = PermissionCatalogue::for_graphql(&billing(), []);

    assert!(catalogue.is_empty());
    assert_eq!(catalogue.len(), 0);
    assert_eq!(
        catalogue,
        PermissionCatalogue::empty(billing(), PermissionKeyKind::Gql)
    );
}

#[test]
fn a_version_without_fields_still_holds_the_introspection_key() {
    let empty = CoordinateSet::new();

    let catalogue = PermissionCatalogue::for_graphql(&billing(), [&empty]);

    assert_eq!(graphql_keys(&catalogue), ["gql:billing:__introspection"]);
}

#[test]
fn a_rest_set_yields_one_key_per_operation() {
    let set = operations(&[
        (HttpMethod::Get, "/api/invoices/{id}", NONE),
        (HttpMethod::Delete, "/api/invoices/{id}", SENSITIVE),
        (HttpMethod::Post, "/api/invoices", NONE),
    ]);

    let catalogue = PermissionCatalogue::for_rest(&billing(), [&set]);

    assert_eq!(catalogue.kind(), PermissionKeyKind::Rest);
    assert_eq!(catalogue.len(), 3);
    assert!(catalogue.contains(&key("rest:billing:GET /api/invoices/{}")));
    assert!(catalogue.contains(&key("rest:billing:POST /api/invoices")));
    assert_eq!(
        catalogue.flags(&key("rest:billing:DELETE /api/invoices/{}")),
        Some(SENSITIVE)
    );
    assert_eq!(
        catalogue.flags(&key("rest:billing:PUT /api/invoices")),
        None
    );
    assert!(!catalogue.contains(&key("rest:billing:PUT /api/invoices")));
}

#[test]
fn several_active_versions_make_the_union_of_their_keys() {
    let first = coordinates(&[("Query.invoice", NONE), ("Query.old", NONE)]);
    let second = coordinates(&[("Query.invoice", NONE), ("Query.fresh", NONE)]);

    let catalogue = PermissionCatalogue::for_graphql(&billing(), [&first, &second]);

    assert_eq!(catalogue.len(), 4);
    assert!(catalogue.contains(&key("gql:billing:Query.old")));
    assert!(catalogue.contains(&key("gql:billing:Query.fresh")));
}

#[test]
fn a_key_leaves_the_catalogue_when_it_leaves_every_active_version() {
    let first = coordinates(&[("Query.invoice", NONE), ("Query.old", NONE)]);
    let second = coordinates(&[("Query.invoice", NONE)]);

    let both = PermissionCatalogue::for_graphql(&billing(), [&first, &second]);
    let second_only = PermissionCatalogue::for_graphql(&billing(), [&second]);

    assert!(both.contains(&key("gql:billing:Query.old")));
    assert!(!second_only.contains(&key("gql:billing:Query.old")));
}

#[test]
fn a_key_carries_the_most_restrictive_flags_of_the_active_versions() {
    let sensitive = coordinates(&[("Mutation.pay", SENSITIVE)]);
    let audited = coordinates(&[("Mutation.pay", AUDIT)]);
    let plain = coordinates(&[("Mutation.pay", NONE)]);

    let catalogue = PermissionCatalogue::for_graphql(&billing(), [&plain, &sensitive, &audited]);

    assert_eq!(
        catalogue.flags(&key("gql:billing:Mutation.pay")),
        Some(SENSITIVE.with_audit_always())
    );
}

#[test]
fn rest_versions_combine_flags_the_same_way() {
    let sensitive = operations(&[(HttpMethod::Post, "/pay", SENSITIVE)]);
    let plain = operations(&[(HttpMethod::Post, "/pay", NONE)]);

    let catalogue = PermissionCatalogue::for_rest(&billing(), [&plain, &sensitive]);

    assert_eq!(
        catalogue.flags(&key("rest:billing:POST /pay")),
        Some(SENSITIVE)
    );
}

#[test]
fn scope_is_the_service_and_the_form_of_the_catalogue() {
    let catalogue = PermissionCatalogue::for_graphql(&billing(), []);

    assert!(catalogue.is_in_scope(&key("gql:billing:Query.invoice")));
    assert!(catalogue.is_in_scope(&key("gql:billing:__introspection")));
    assert!(!catalogue.is_in_scope(&key("gql:orders:Query.invoice")));
    assert!(!catalogue.is_in_scope(&key("rest:billing:GET /invoices")));
    assert!(!catalogue.is_in_scope(&key("iam:audit:read")));
}

fn version() -> impl Strategy<Value = CoordinateSet> {
    vec((0_usize..6, 0_u8..4), 0..6).prop_map(|entries| {
        entries
            .into_iter()
            .map(|(index, flags)| {
                let coordinate = GraphQlCoordinate::parse(&format!("Query.f{index}")).unwrap();
                let mut value = NONE;
                if flags & 1 == 1 {
                    value = value.with_sensitive();
                }
                if flags & 2 == 2 {
                    value = value.with_audit_always();
                }
                (coordinate, value)
            })
            .collect()
    })
}

proptest! {
    #[test]
    fn the_catalogue_is_the_union_of_its_versions_in_any_order(
        versions in vec(version(), 0..4),
    ) {
        let forward = PermissionCatalogue::for_graphql(&billing(), &versions);
        let backward = PermissionCatalogue::for_graphql(&billing(), versions.iter().rev());

        prop_assert_eq!(&forward, &backward);
        for version in &versions {
            for (coordinate, flags) in version.iter() {
                let held = forward.flags(&coordinate.permission_key(&billing())).unwrap();
                prop_assert!(!flags.is_downgraded_by(held));
            }
        }
        let union_keys: std::collections::BTreeSet<_> = versions
            .iter()
            .flat_map(|version| version.iter().map(|(coordinate, _)| coordinate.clone()))
            .collect();
        let introspection = usize::from(!versions.is_empty());
        prop_assert_eq!(forward.len(), union_keys.len().saturating_add(introspection));
    }
}
