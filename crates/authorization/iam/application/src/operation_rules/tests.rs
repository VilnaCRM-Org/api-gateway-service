use std::collections::BTreeSet;

use iam_domain::{
    AuditAction, HttpMethod, PermissionKey, PermissionKeyKind, ReservedPermission, ServiceScope,
};

use super::{
    AUDIT_READ, CallerRule, OperationRules, POLICY_RESYNC, REVOKE_GLOBAL, REVOKE_SESSIONS,
    Requirement, VALIDATE_ALL,
};
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
fn the_decision_api_and_token_resolution_follow_the_caller_rule_and_need_no_catalogue_key() {
    let caller = rows_of(|requirement| matches!(requirement, Requirement::Caller(_)));

    assert_eq!(
        caller,
        vec![
            ("POST", "/api/token-resolutions"),
            ("POST", "/api/access-validations"),
            ("POST", "/api/access-validations/batch"),
        ]
    );
    for rule in OperationRules::all() {
        if let Requirement::Caller(caller_rule) = rule.requirement {
            assert!(!rule.requirement.needs_catalogue(), "{}", rule.template);
            assert!(rule.requirement.reserved().is_empty(), "{}", rule.template);
            assert_eq!(rule.requirement.caller_rule(), Some(caller_rule));
            assert_eq!(
                caller_rule.names_services(),
                rule.template.contains("access-validations"),
                "{}",
                rule.template
            );
        }
    }
}

#[test]
fn the_graphql_decision_fields_follow_the_same_caller_rules_as_their_rest_operations() {
    let rule = |coordinate: &str| {
        OperationRules::find_graphql(coordinate)
            .unwrap()
            .requirement
    };

    assert_eq!(
        rule("Query.validateAccess"),
        Requirement::Caller(CallerRule::Validate)
    );
    assert_eq!(
        rule("Query.validateAccessBatch"),
        Requirement::Caller(CallerRule::Validate)
    );
    assert_eq!(
        rule("Query.resolveToken"),
        Requirement::Caller(CallerRule::ResolveToken)
    );
}

#[test]
fn a_row_with_fixed_keys_has_no_caller_rule() {
    assert_eq!(Requirement::Catalogue.caller_rule(), None);
    assert_eq!(
        Requirement::Reserved(&["iam:audit:read"]).caller_rule(),
        None
    );
    assert_eq!(
        Requirement::CatalogueAndReserved(&["iam:audit:read"]).caller_rule(),
        None
    );
}

#[test]
fn every_other_operation_requires_its_catalogue_key() {
    let catalogue = rows_of(|requirement| requirement == Requirement::Catalogue);

    assert_eq!(catalogue.len(), OperationRules::all().len() - 12);
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

#[test]
fn the_upstream_operations_need_their_catalogue_keys_on_both_interfaces() {
    let rest = [
        ("POST", "/api/upstreams", "upstream.create"),
        ("GET", "/api/upstreams", "upstream.list"),
        ("GET", "/api/upstreams/{id}", "upstream.read"),
        ("PATCH", "/api/upstreams/{id}", "upstream.update"),
        ("DELETE", "/api/upstreams/{id}", "upstream.delete"),
    ];
    let graphql = [
        ("Query.upstream", "upstream.read"),
        ("Query.upstreams", "upstream.list"),
        ("Mutation.createUpstream", "upstream.create"),
        ("Mutation.updateUpstream", "upstream.update"),
        ("Mutation.deleteUpstream", "upstream.delete"),
    ];

    for (method, template, action) in rest {
        let rule = OperationRules::find(method, template).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
    for (coordinate, action) in graphql {
        let rule = OperationRules::find_graphql(coordinate).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
}

#[test]
fn the_route_operations_need_their_catalogue_keys_on_both_interfaces() {
    let rest = [
        ("POST", "/api/routes", "route.create"),
        ("GET", "/api/routes", "route.list"),
        ("GET", "/api/routes/{id}", "route.read"),
        ("PATCH", "/api/routes/{id}", "route.update"),
        ("DELETE", "/api/routes/{id}", "route.delete"),
    ];
    let graphql = [
        ("Query.route", "route.read"),
        ("Query.routes", "route.list"),
        ("Mutation.createRoute", "route.create"),
        ("Mutation.updateRoute", "route.update"),
        ("Mutation.deleteRoute", "route.delete"),
    ];

    for (method, template, action) in rest {
        let rule = OperationRules::find(method, template).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
    for (coordinate, action) in graphql {
        let rule = OperationRules::find_graphql(coordinate).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
}

#[test]
fn the_route_configuration_operations_need_their_catalogue_keys_on_both_interfaces() {
    let rest = [
        (
            "GET",
            "/api/route-configurations/{host}",
            "route_configuration.read",
        ),
        (
            "PUT",
            "/api/route-configurations/{host}",
            "route_configuration.apply",
        ),
    ];
    let graphql = [
        ("Query.routeConfiguration", "route_configuration.read"),
        (
            "Mutation.applyRouteConfiguration",
            "route_configuration.apply",
        ),
    ];

    for (method, template, action) in rest {
        let rule = OperationRules::find(method, template).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
    for (coordinate, action) in graphql {
        let rule = OperationRules::find_graphql(coordinate).unwrap();
        assert_eq!(rule.action, action);
        assert_eq!(rule.requirement, Requirement::Catalogue);
    }
}

#[test]
fn the_policy_resync_needs_the_reserved_key_and_no_catalogue_key_on_both_interfaces() {
    let rest = OperationRules::find("POST", "/api/policy-resyncs").unwrap();
    let graphql = OperationRules::find_graphql("Mutation.resyncPolicy").unwrap();

    assert_eq!(rest.action, "policy.resync");
    assert_eq!(graphql.action, "policy.resync");
    for requirement in [rest.requirement, graphql.requirement] {
        assert_eq!(requirement, Requirement::Reserved(&[POLICY_RESYNC]));
        assert!(!requirement.needs_catalogue());
        assert_eq!(requirement.reserved(), ["iam:policy:resync"]);
    }
}

#[test]
fn the_revocation_writes_need_their_reserved_key_and_no_catalogue_key_on_both_interfaces() {
    const SESSIONS: &[&str] = &[REVOKE_SESSIONS];
    const GLOBAL: &[&str] = &[REVOKE_GLOBAL];
    let cases = [
        (
            "/api/session-revocations",
            "Mutation.revokeSessions",
            "session.revoke",
            SESSIONS,
            "iam:revoke:sessions",
        ),
        (
            "/api/global-token-cutoffs",
            "Mutation.setGlobalTokenCutoff",
            "global_token.cut_off",
            GLOBAL,
            "iam:revoke:global",
        ),
    ];

    for (template, coordinate, action, keys, text) in cases {
        let rest = OperationRules::find("POST", template).unwrap();
        let graphql = OperationRules::find_graphql(coordinate).unwrap();

        assert_eq!(rest.action, action);
        assert_eq!(graphql.action, action);
        for requirement in [rest.requirement, graphql.requirement] {
            assert_eq!(requirement, Requirement::Reserved(keys));
            assert!(!requirement.needs_catalogue());
            assert_eq!(requirement.reserved(), [text]);
        }
    }
}

#[test]
fn the_audit_and_revocation_reads_need_the_audit_key_and_no_catalogue_key_on_both_interfaces() {
    let rest = [
        ("/api/security-audit-events", "security_audit.list"),
        ("/api/security-audit-events/{id}", "security_audit.read"),
        ("/api/session-revocations", "session_revocation.list"),
        ("/api/session-revocations/{id}", "session_revocation.read"),
        ("/api/users/{userId}/token-cutoff", "user_token_cutoff.read"),
        (
            "/api/global-token-cutoffs/current",
            "global_token_cutoff.read",
        ),
    ];
    let graphql = [
        ("Query.securityAuditEvents", "security_audit.list"),
        ("Query.securityAuditEvent", "security_audit.read"),
        ("Query.sessionRevocations", "session_revocation.list"),
        ("Query.sessionRevocation", "session_revocation.read"),
        ("Query.userTokenCutoff", "user_token_cutoff.read"),
        ("Query.globalTokenCutoff", "global_token_cutoff.read"),
    ];

    let rules = rest
        .iter()
        .map(|(template, action)| {
            let rule = OperationRules::find("GET", template).unwrap();
            (rule.action, rule.requirement, *action)
        })
        .chain(graphql.iter().map(|(coordinate, action)| {
            let rule = OperationRules::find_graphql(coordinate).unwrap();
            (rule.action, rule.requirement, *action)
        }));
    for (found, requirement, expected) in rules {
        assert_eq!(found, expected);
        assert_eq!(requirement, Requirement::Reserved(&[AUDIT_READ]));
        assert!(!requirement.needs_catalogue());
        assert_eq!(requirement.reserved(), ["iam:audit:read"]);
    }
}

#[test]
fn there_is_no_cache_flush_operation_on_either_interface() {
    assert!(OperationRules::find("POST", "/api/authorization-cache/flushes").is_none());
    assert!(OperationRules::find_graphql("Mutation.flushAuthorizationCache").is_none());
    for rule in OperationRules::all() {
        assert!(!rule.template.contains("flush"));
    }
    for rule in OperationRules::graphql() {
        assert!(!rule.coordinate.to_lowercase().contains("flush"));
    }
}
