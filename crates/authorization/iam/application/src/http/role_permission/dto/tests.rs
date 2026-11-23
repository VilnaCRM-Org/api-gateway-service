use iam_domain::{EntityVersion, PermissionGrant, RoleGrant, RoleId};
use serde_json::json;
use validator::Validate as _;

use super::{RolePermissionResponse, RolePermissionsResponse, SetRolePermissionsRequest};
use crate::query::get_role_permissions::RolePermissions;

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";
const MAX_KEYS: usize = 5_000;

fn stored(text: &str, active: bool) -> RoleGrant {
    RoleGrant {
        grant: PermissionGrant::parse(text).unwrap(),
        active,
    }
}

#[test]
fn the_body_holds_the_keys_and_nothing_else() {
    let request: SetRolePermissionsRequest =
        serde_json::from_value(json!({ "keys": ["gql:billing:*"] })).unwrap();

    assert_eq!(request.keys, ["gql:billing:*"]);
    assert!(
        serde_json::from_value::<SetRolePermissionsRequest>(json!({ "keys": [], "other": 1 }))
            .is_err()
    );
    assert!(serde_json::from_value::<SetRolePermissionsRequest>(json!({})).is_err());
}

#[test]
fn five_thousand_keys_are_valid_and_one_more_is_not() {
    let at_the_limit = SetRolePermissionsRequest {
        keys: vec!["rest:billing:GET /a".to_owned(); MAX_KEYS],
    };
    let beyond = SetRolePermissionsRequest {
        keys: vec!["rest:billing:GET /a".to_owned(); MAX_KEYS + 1],
    };

    assert!(at_the_limit.validate().is_ok());
    let errors = beyond.validate().unwrap_err();
    assert!(errors.field_errors().contains_key("keys"));
}

#[test]
fn the_canonical_form_covers_the_role_the_version_and_the_keys() {
    let id = RoleId::parse(ROLE).unwrap();
    let request = SetRolePermissionsRequest {
        keys: vec!["gql:billing:*".to_owned()],
    };
    let other = SetRolePermissionsRequest { keys: Vec::new() };
    let version = EntityVersion::new(2).unwrap();

    let form = request.canonical_form(id, version);

    assert!(form.starts_with("role.permissions.set:"));
    assert!(form.contains(ROLE));
    assert!(form.contains("gql:billing:*"));
    assert_ne!(form, other.canonical_form(id, version));
    assert_ne!(
        form,
        request.canonical_form(id, EntityVersion::new(3).unwrap())
    );
}

#[test]
fn a_grant_is_described_by_key_kind_service_active_and_wildcard_flags() {
    let exact = RolePermissionResponse::from(&stored("rest:billing:GET /invoices", true));
    let wildcard = RolePermissionResponse::from(&stored("gql:billing:Query.*", false));

    assert_eq!(
        serde_json::to_value(&exact).unwrap(),
        json!({
            "key": "rest:billing:GET /invoices",
            "kind": "rest",
            "service": "billing",
            "active": true,
            "wildcard": false
        })
    );
    assert_eq!(
        serde_json::to_value(&wildcard).unwrap(),
        json!({
            "key": "gql:billing:Query.*",
            "kind": "gql",
            "service": "billing",
            "active": false,
            "wildcard": true
        })
    );
}

#[test]
fn the_grants_of_a_role_come_with_its_identifier_and_version() {
    let response = RolePermissionsResponse::from(&RolePermissions {
        id: RoleId::parse(ROLE).unwrap(),
        version: EntityVersion::new(5).unwrap(),
        grants: vec![stored("gql:billing:*", true)],
    });

    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({
            "roleId": ROLE,
            "version": 5,
            "permissions": [{
                "key": "gql:billing:*",
                "kind": "gql",
                "service": "billing",
                "active": true,
                "wildcard": true
            }]
        })
    );
}
