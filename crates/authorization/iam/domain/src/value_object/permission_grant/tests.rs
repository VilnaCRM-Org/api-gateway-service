use rstest::rstest;

use super::PermissionGrant;
use crate::error::InvalidPermissionKey;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

#[rstest]
#[case("rest:core:GET /api/items")]
#[case("gql:core:Query.items")]
#[case("iam:grant:*")]
#[case("iam:route:*")]
#[case("iam:audit:read")]
fn a_key_is_granted_as_a_key(#[case] text: &str) {
    let grant = PermissionGrant::parse(text).unwrap();

    assert_eq!(
        grant,
        PermissionGrant::Key(PermissionKey::parse(text).unwrap())
    );
    assert!(!grant.is_wildcard());
    assert_eq!(grant.to_string(), text);
}

#[rstest]
#[case("rest:core:*")]
#[case("rest:core:GET *")]
#[case("gql:core:*")]
#[case("gql:core:Query.*")]
fn a_wildcard_is_granted_as_a_wildcard(#[case] text: &str) {
    let grant = PermissionGrant::parse(text).unwrap();

    assert_eq!(
        grant,
        PermissionGrant::Wildcard(WildcardPattern::parse(text).unwrap())
    );
    assert!(grant.is_wildcard());
    assert_eq!(grant.to_string(), text);
}

#[rstest]
#[case("rest:core:GET /api/items", "core")]
#[case("gql:core:*", "core")]
#[case("iam:grant:core", "iam")]
fn a_grant_names_the_service_of_its_key_or_pattern(#[case] text: &str, #[case] name: &str) {
    assert_eq!(
        PermissionGrant::parse(text).unwrap().service(),
        &ServiceName::new(name).unwrap()
    );
}

#[rstest]
#[case("gql:core:*.field", InvalidPermissionKey::Wildcard)]
#[case("rest:core:GET /api/*", InvalidPermissionKey::Wildcard)]
#[case("rest:core:* /api", InvalidPermissionKey::Wildcard)]
#[case("iam:cache:flush", InvalidPermissionKey::Reserved)]
#[case("rest:core:GET api", InvalidPermissionKey::Template)]
#[case("other", InvalidPermissionKey::Kind)]
fn a_malformed_grant_is_rejected(#[case] text: &str, #[case] error: InvalidPermissionKey) {
    assert_eq!(PermissionGrant::parse(text), Err(error));
}
