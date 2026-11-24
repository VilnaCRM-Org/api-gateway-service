use std::collections::BTreeSet;

use iam_domain::{
    AuditAction, HttpMethod, PermissionKey, PermissionKeyKind, ReservedPermission, ServiceScope,
};

use super::{OperationRules, Requirement, VALIDATE_ALL};
use crate::http::{IamState, router, specification_router};

fn rows_of(requirement: fn(Requirement) -> bool) -> Vec<(&'static str, &'static str)> {
    OperationRules::all()
        .iter()
        .filter(|rule| requirement(rule.requirement))
        .map(|rule| (rule.method.as_str(), rule.template))
        .collect()
}

fn registered() -> BTreeSet<(String, String)> {
    let mut operations = BTreeSet::new();
    for router in [router::<IamState>(), specification_router::<IamState>()] {
        for (path, item) in &router.get_openapi().paths.paths {
            let methods = [
                ("GET", &item.get),
                ("PUT", &item.put),
                ("POST", &item.post),
                ("DELETE", &item.delete),
                ("OPTIONS", &item.options),
                ("HEAD", &item.head),
                ("PATCH", &item.patch),
                ("TRACE", &item.trace),
                ("QUERY", &item.query),
            ];
            for (name, operation) in methods {
                if operation.is_some() {
                    operations.insert((name.to_owned(), format!("/api{path}")));
                }
            }
            for name in item.additional_operations.keys() {
                operations.insert((name.to_uppercase(), format!("/api{path}")));
            }
        }
    }
    operations
}

#[test]
fn every_operation_of_the_router_has_a_row_and_every_row_an_operation() {
    let rows: BTreeSet<(String, String)> = OperationRules::all()
        .iter()
        .map(|rule| (rule.method.as_str().to_owned(), rule.template.to_owned()))
        .collect();

    assert_eq!(rows, registered());
}

#[test]
fn rows_and_actions_are_unique_and_actions_are_valid_audit_actions() {
    let rules = OperationRules::all();
    let keys: BTreeSet<_> = rules
        .iter()
        .map(|rule| (rule.method, rule.template))
        .collect();
    let actions: BTreeSet<_> = rules.iter().map(|rule| rule.action).collect();

    assert_eq!(keys.len(), rules.len());
    assert_eq!(actions.len(), rules.len());
    for rule in rules {
        assert!(AuditAction::new(rule.action).is_ok(), "{}", rule.action);
        assert!(rule.template.starts_with("/api/"), "{}", rule.template);
    }
}

#[test]
fn each_reserved_key_operation_names_exactly_its_reserved_key() {
    let reserved = rows_of(|requirement| matches!(requirement, Requirement::Reserved(_)));

    assert_eq!(
        reserved,
        vec![
            ("POST", "/api/token-resolutions"),
            ("POST", "/api/access-validations"),
            ("POST", "/api/access-validations/batch"),
        ]
    );
    for rule in OperationRules::all() {
        if let Requirement::Reserved(keys) = rule.requirement {
            assert_eq!(keys, [VALIDATE_ALL], "{}", rule.template);
            assert!(!rule.requirement.needs_catalogue(), "{}", rule.template);
        }
    }
}

#[test]
fn every_other_operation_requires_its_catalogue_key() {
    let catalogue = rows_of(|requirement| requirement == Requirement::Catalogue);

    assert_eq!(catalogue.len(), OperationRules::all().len() - 3);
    for rule in OperationRules::all() {
        if rule.requirement == Requirement::Catalogue {
            assert!(rule.requirement.needs_catalogue());
            assert_eq!(rule.requirement.reserved().len(), 0);
        }
    }
}

#[test]
fn a_catalogue_and_reserved_row_needs_both() {
    let requirement = Requirement::CatalogueAndReserved(&["iam:audit:read"]);

    assert!(requirement.needs_catalogue());
    assert_eq!(requirement.reserved(), ["iam:audit:read"]);
}

#[test]
fn every_named_reserved_key_is_a_reserved_key_and_none_is_a_cache_flush() {
    for rule in OperationRules::all() {
        for raw in rule.requirement.reserved() {
            let key = PermissionKey::parse(raw).unwrap();
            assert_eq!(key.kind(), PermissionKeyKind::Reserved, "{raw}");
            assert_ne!(*raw, "iam:cache:flush");
        }
    }
    assert!(ReservedPermission::parse("iam:cache:flush").is_err());
    assert_eq!(
        ReservedPermission::parse(VALIDATE_ALL),
        Ok(ReservedPermission::Validate(ServiceScope::All))
    );
}

#[test]
fn an_operation_missing_from_the_table_has_no_row() {
    assert!(OperationRules::find("POST", "/api/roles").is_some());
    assert!(OperationRules::find("GET", "/api/roles/{id}/permissions").is_some());
    assert!(OperationRules::find("POST", "/api/cache-flushes").is_none());
    assert!(OperationRules::find("DELETE", "/api/roles").is_none());
    assert!(OperationRules::find("TRACE", "/api/roles").is_none());
    assert_eq!(
        OperationRules::find("PATCH", "/api/roles/{id}").map(|rule| rule.method),
        Some(HttpMethod::Patch)
    );
}

#[test]
fn a_row_built_at_run_time_holds_its_parts() {
    let rule = super::row(
        HttpMethod::Get,
        "/api/roles",
        "role.list",
        Requirement::Catalogue,
    );

    assert_eq!(
        rule,
        super::OperationRule {
            method: HttpMethod::Get,
            template: "/api/roles",
            action: "role.list",
            requirement: Requirement::Catalogue,
        }
    );
}

#[test]
fn every_graphql_row_has_the_requirement_of_the_rest_operation_of_its_action() {
    for rule in OperationRules::graphql() {
        let rest = OperationRules::all()
            .iter()
            .find(|row| row.action == rule.action)
            .unwrap_or_else(|| panic!("no REST operation for {}", rule.action));

        assert_eq!(rule.requirement, rest.requirement, "{}", rule.coordinate);
    }
}

#[test]
fn graphql_rows_are_unique_valid_root_coordinates_with_valid_actions() {
    let rules = OperationRules::graphql();
    let coordinates: BTreeSet<_> = rules.iter().map(|rule| rule.coordinate).collect();
    let actions: BTreeSet<_> = rules.iter().map(|rule| rule.action).collect();

    assert_eq!(coordinates.len(), rules.len());
    assert_eq!(actions.len(), rules.len());
    for rule in rules {
        assert!(AuditAction::new(rule.action).is_ok(), "{}", rule.action);
        assert!(
            rule.coordinate.starts_with("Query.") || rule.coordinate.starts_with("Mutation."),
            "{}",
            rule.coordinate
        );
        assert!(
            PermissionKey::parse(&format!("gql:iam:{}", rule.coordinate)).is_ok(),
            "{}",
            rule.coordinate
        );
    }
}

#[test]
fn a_graphql_field_that_iam_does_not_own_has_no_row() {
    assert!(OperationRules::find_graphql("Query.roles").is_some());
    assert!(OperationRules::find_graphql("Mutation.createRole").is_some());
    assert!(OperationRules::find_graphql("Query.exampleApiResource").is_none());
    assert!(OperationRules::find_graphql("Mutation.roles").is_none());
}

#[test]
fn a_graphql_row_built_at_run_time_holds_its_parts() {
    let rule = super::field("Query.roles", "role.list", Requirement::Catalogue);

    assert_eq!(
        rule,
        super::GraphQlRule {
            coordinate: "Query.roles",
            action: "role.list",
            requirement: Requirement::Catalogue,
        }
    );
}
