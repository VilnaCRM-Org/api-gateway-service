use rstest::rstest;

use super::{
    ConfigChangeRefused, InvalidRatePolicy, InvalidRoute, InvalidUpstream, ReferencedByRoute,
    RouteConflict, UpstreamChangeRefused,
};
use crate::error::{InvalidIamValue, VersionConflict};
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RouteId;

#[rstest]
#[case(InvalidUpstream::NameLength, "name", "length")]
#[case(InvalidUpstream::NamePattern, "name", "pattern")]
#[case(InvalidUpstream::NamespaceFormat, "namespace", "format")]
#[case(InvalidUpstream::ServiceFormat, "serviceName", "format")]
#[case(InvalidUpstream::CatalogServiceLength, "catalogService", "length")]
#[case(InvalidUpstream::CatalogServicePattern, "catalogService", "pattern")]
#[case(InvalidUpstream::PortRange, "port", "range")]
#[case(InvalidUpstream::ConnectTimeoutRange, "connectTimeoutMs", "range")]
#[case(InvalidUpstream::ResponseTimeoutRange, "responseTimeoutMs", "range")]
#[case(InvalidUpstream::ConcurrencyLimitRange, "concurrencyLimit", "range")]
#[case(InvalidUpstream::RetryBudgetRange, "retryBudgetPercent", "range")]
#[case(InvalidUpstream::OutlierThresholdRange, "outlierThreshold", "range")]
fn an_invalid_upstream_names_its_property_and_code(
    #[case] violation: InvalidUpstream,
    #[case] path: &str,
    #[case] code: &str,
) {
    assert_eq!(violation.property_path(), path);
    assert_eq!(violation.code(), code);
    assert_ne!(violation.to_string(), "");
}

#[rstest]
#[case(InvalidRoute::HostLength, "host", "length")]
#[case(InvalidRoute::HostFormat, "host", "format")]
#[case(InvalidRoute::MethodsRequired, "methods", "required")]
#[case(InvalidRoute::PathPrefix, "pathPattern", "prefix")]
#[case(InvalidRoute::PathFormat, "pathPattern", "format")]
#[case(InvalidRoute::ServiceLength, "service", "length")]
#[case(InvalidRoute::ServicePattern, "service", "pattern")]
#[case(InvalidRoute::BodyLimitRange, "bodyLimit", "range")]
#[case(InvalidRoute::RequestTimeoutRange, "timeouts.requestMs", "range")]
#[case(InvalidRoute::IdleTimeoutRange, "timeouts.idleMs", "range")]
#[case(InvalidRoute::RatePolicyCount, "ratePolicies", "count")]
#[case(InvalidRoute::RatePolicyDuplicate, "ratePolicies", "duplicate")]
#[case(InvalidRoute::CorsOriginRequired, "cors.origins", "required")]
#[case(InvalidRoute::CorsOriginFormat, "cors.origins", "format")]
#[case(InvalidRoute::CorsHeaderFormat, "cors.headers", "format")]
#[case(InvalidRoute::CorsMaxAgeRange, "cors.maxAgeSeconds", "range")]
fn an_invalid_route_names_its_property_and_code(
    #[case] violation: InvalidRoute,
    #[case] path: &str,
    #[case] code: &str,
) {
    assert_eq!(violation.property_path(), path);
    assert_eq!(violation.code(), code);
    assert_ne!(violation.to_string(), "");
}

#[test]
fn the_path_message_shows_the_segment_forms() {
    assert!(InvalidRoute::PathFormat.to_string().contains("{name:*}"));
}

#[rstest]
#[case(InvalidRatePolicy::NameLength, "name", "length")]
#[case(InvalidRatePolicy::NameControlCharacter, "name", "control_character")]
#[case(InvalidRatePolicy::LimitRange, "limit", "range")]
#[case(InvalidRatePolicy::PeriodRange, "periodSeconds", "range")]
#[case(InvalidRatePolicy::BurstRange, "burst", "range")]
fn an_invalid_rate_policy_names_its_property_and_code(
    #[case] violation: InvalidRatePolicy,
    #[case] path: &str,
    #[case] code: &str,
) {
    assert_eq!(violation.property_path(), path);
    assert_eq!(violation.code(), code);
    assert_ne!(violation.to_string(), "");
}

#[test]
fn a_change_refusal_has_the_code_of_its_cause() {
    let stale = VersionConflict::Stale {
        expected: EntityVersion::INITIAL,
        current: EntityVersion::new(2).unwrap(),
    };

    assert_eq!(ConfigChangeRefused::Deleted.code(), "deleted");
    assert_eq!(
        ConfigChangeRefused::from(VersionConflict::Missing).code(),
        "missing"
    );
    assert_eq!(ConfigChangeRefused::from(stale).code(), "stale");
    assert_eq!(
        ConfigChangeRefused::from(InvalidIamValue::EntityVersionRange).code(),
        "range"
    );
    assert_eq!(UpstreamChangeRefused::Renamed.code(), "renamed");
    assert_eq!(
        UpstreamChangeRefused::from(ConfigChangeRefused::Deleted).code(),
        "deleted"
    );
    assert_ne!(UpstreamChangeRefused::Renamed.to_string(), "");
}

#[test]
fn a_conflict_names_both_routes() {
    let first = RouteId::parse("00000000-0000-7000-8000-000000000001").unwrap();
    let second = RouteId::parse("00000000-0000-7000-8000-000000000002").unwrap();

    let same = RouteConflict::SamePattern { first, second };
    let shadow = RouteConflict::AnonymousShadow {
        anonymous: first,
        protected: second,
    };

    assert!(same.to_string().contains(&first.to_string()));
    assert!(same.to_string().contains(&second.to_string()));
    assert!(shadow.to_string().contains(&first.to_string()));
    assert!(shadow.to_string().contains(&second.to_string()));
}

#[test]
fn an_entry_that_a_route_references_cannot_be_deleted() {
    assert_eq!(ReferencedByRoute::check(0), Ok(()));
    assert_eq!(
        ReferencedByRoute::check(2),
        Err(ReferencedByRoute { count: 2 })
    );
    assert_eq!(ReferencedByRoute::CODE, "referenced_by_route");
    assert!(ReferencedByRoute { count: 2 }.to_string().contains('2'));
}
