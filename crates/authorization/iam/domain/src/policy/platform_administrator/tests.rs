use std::collections::BTreeSet;
use std::time::SystemTime;

use super::PlatformAdministrator;
use crate::role::RoleParts;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::role_kind::RoleKind;
use crate::value_object::role_name::RoleName;

fn role(name: &str, kind: RoleKind) -> RoleParts {
    RoleParts {
        id: RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
        name: RoleName::new(name.to_owned()).unwrap(),
        description: None,
        kind,
        grants: PermissionGrantSet::default(),
        version: EntityVersion::INITIAL,
        created_at: SystemTime::UNIX_EPOCH,
        updated_at: SystemTime::UNIX_EPOCH,
        deleted_at: None,
    }
}

#[test]
fn every_grant_parses_and_is_privileged_and_none_repeats() {
    let parsed: Vec<PermissionGrant> = PlatformAdministrator::GRANTS
        .iter()
        .map(|text| PermissionGrant::parse(text).unwrap())
        .collect();

    assert!(parsed.iter().all(PermissionGrant::is_privileged));
    let distinct: BTreeSet<String> = parsed.iter().map(ToString::to_string).collect();
    assert_eq!(distinct.len(), PlatformAdministrator::GRANTS.len());
    for (text, grant) in PlatformAdministrator::GRANTS.iter().zip(&parsed) {
        assert_eq!(&grant.to_string(), text);
    }
    assert!(PermissionGrantSet::new(parsed).is_ok());
}

#[test]
fn the_grants_hold_the_two_wildcards_and_every_reserved_key_but_the_cache_flush() {
    let grants = PlatformAdministrator::GRANTS;

    assert!(grants.contains(&"rest:iam:*"));
    assert!(grants.contains(&"gql:iam:*"));
    assert_eq!(
        grants
            .iter()
            .filter(|grant| grant.starts_with("iam:"))
            .count(),
        11
    );
    assert!(!grants.iter().any(|grant| grant.contains("cache")));
}

#[test]
fn only_a_system_role_of_that_name_is_the_administrator_role() {
    assert!(PlatformAdministrator::is_role(&role(
        "iam-platform-admin",
        RoleKind::System
    )));
    assert!(!PlatformAdministrator::is_role(&role(
        "iam-platform-admin",
        RoleKind::Custom
    )));
    assert!(!PlatformAdministrator::is_role(&role(
        "other",
        RoleKind::System
    )));
}
