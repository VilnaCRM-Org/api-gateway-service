//! The endpoint discovery variables of the gateway: `UPSTREAM_DISCOVERY`,
//! `UPSTREAM_STATIC_ENDPOINTS_FILE`, `UPSTREAM_ZONE_AWARE` and `GATEWAY_ZONE`.

use std::path::PathBuf;

use iam_domain::Zone;
use rstest::rstest;

use super::{gateway_problems, some, valid_gateway};
use crate::config::{GatewayConfig, UpstreamDiscovery};

/// A file of its own in the temporary directory, removed when the test ends.
struct TempFile(PathBuf);

impl TempFile {
    fn with(name: &str, content: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "config-endpoints-{}-{name}.json",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        Self(path)
    }

    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap_or_default();
    }
}

const ENDPOINTS: &str =
    r#"{"user-service": [{"address": "user-service", "port": 8081, "zone": "zone-a"}]}"#;

#[test]
fn the_defaults_discover_through_kubernetes_and_prefer_the_own_zone() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert_eq!(config.endpoints.discovery, UpstreamDiscovery::Kubernetes);
    assert!(config.endpoints.zone_aware);
    assert_eq!(config.endpoints.zone, None);
}

#[test]
fn the_static_discovery_takes_its_file_and_an_explicit_zone() {
    let file = TempFile::with("valid", ENDPOINTS);
    let mut args = valid_gateway();
    args.upstream_discovery = some("static");
    args.upstream_static_endpoints_file = some(file.path());
    args.upstream_zone_aware = some("false");
    args.gateway_zone = some("zone-b");

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(
        config.endpoints.discovery,
        UpstreamDiscovery::Static(PathBuf::from(file.path()))
    );
    assert!(!config.endpoints.zone_aware);
    assert_eq!(config.endpoints.zone, Some(Zone::new("zone-b").unwrap()));
}

#[test]
fn the_file_is_ignored_when_kubernetes_discovery_is_chosen() {
    let mut args = valid_gateway();
    args.upstream_discovery = some("kubernetes");
    args.upstream_static_endpoints_file = some("/nonexistent/endpoints.json");

    let config = GatewayConfig::from_args(&args).unwrap();

    assert_eq!(config.endpoints.discovery, UpstreamDiscovery::Kubernetes);
}

#[test]
fn the_static_discovery_without_a_file_names_the_variable() {
    let mut args = valid_gateway();
    args.upstream_discovery = some("static");

    assert_eq!(
        gateway_problems(&args),
        [(
            "UPSTREAM_STATIC_ENDPOINTS_FILE",
            "is required when UPSTREAM_DISCOVERY is static".to_owned()
        )]
    );
}

#[rstest]
#[case::missing("/nonexistent/endpoints.json")]
#[case::unparsable("[1, 2")]
#[case::invalid_entry(r#"{"s": [{"address": "", "port": 80}]}"#)]
fn the_static_discovery_with_an_unusable_file_names_the_variable(#[case] source: &str) {
    let file = TempFile::with("unusable", source);
    let path = if source.starts_with('/') {
        source
    } else {
        file.path()
    };
    let mut args = valid_gateway();
    args.upstream_discovery = some("static");
    args.upstream_static_endpoints_file = some(path);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    let (variable, reason) = problems.first().unwrap();
    assert_eq!(*variable, "UPSTREAM_STATIC_ENDPOINTS_FILE");
    assert!(reason.starts_with("must name a readable JSON file of upstream endpoints"));
}

#[test]
fn an_unknown_discovery_names_the_variable() {
    let mut args = valid_gateway();
    args.upstream_discovery = some("dns");

    assert_eq!(
        gateway_problems(&args),
        [(
            "UPSTREAM_DISCOVERY",
            "must be one of kubernetes, static".to_owned()
        )]
    );
}

#[test]
fn a_zone_awareness_that_is_no_boolean_names_the_variable() {
    let mut args = valid_gateway();
    args.upstream_zone_aware = some("yes");

    assert_eq!(
        gateway_problems(&args),
        [("UPSTREAM_ZONE_AWARE", "must be true or false".to_owned())]
    );
}

#[rstest]
#[case("zone a")]
#[case("zone/a")]
#[case(&"z".repeat(64))]
fn an_invalid_gateway_zone_names_the_variable(#[case] zone: &str) {
    let mut args = valid_gateway();
    args.gateway_zone = some(zone);

    let problems = gateway_problems(&args);

    assert_eq!(problems.len(), 1);
    assert_eq!(problems.first().unwrap().0, "GATEWAY_ZONE");
    assert!(!problems.first().unwrap().1.contains(zone));
}

#[test]
fn every_problem_of_the_discovery_variables_is_reported_together() {
    let mut args = valid_gateway();
    args.upstream_discovery = some("static");
    args.upstream_zone_aware = some("maybe");
    args.gateway_zone = some("a b");

    let variables: Vec<_> = gateway_problems(&args)
        .into_iter()
        .map(|(variable, _reason)| variable)
        .collect();

    assert_eq!(
        variables,
        [
            "UPSTREAM_ZONE_AWARE",
            "GATEWAY_ZONE",
            "UPSTREAM_STATIC_ENDPOINTS_FILE"
        ]
    );
}
