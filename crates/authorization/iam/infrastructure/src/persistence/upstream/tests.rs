use std::time::{Duration, SystemTime};

use iam_domain::{EntityVersion, RepositoryError, UpstreamProtocol};
use rstest::rstest;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{UpstreamRow, restore};

const UPSTREAM: &str = "5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn row() -> UpstreamRow {
    UpstreamRow {
        id: SqlUuid::parse_str(UPSTREAM).unwrap(),
        name: "core".to_owned(),
        namespace: "platform".to_owned(),
        service_name: "core-service".to_owned(),
        catalog_service: "core".to_owned(),
        port: 8080,
        protocol: "h2c".to_owned(),
        forward_credentials: true,
        system: true,
        connect_timeout_ms: 1_000,
        response_timeout_ms: 30_000,
        concurrency_limit: 256,
        retry_budget_percent: 20,
        outlier_threshold: 5,
        version: 4,
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let parts = restore(row()).unwrap();

    assert_eq!(parts.id.to_string(), UPSTREAM);
    assert_eq!(parts.name.as_str(), "core");
    assert_eq!(parts.settings.namespace(), "platform");
    assert_eq!(parts.settings.service_name(), "core-service");
    assert_eq!(parts.settings.catalog_service().as_str(), "core");
    assert_eq!(parts.settings.port(), 8080);
    assert_eq!(parts.settings.protocol(), UpstreamProtocol::H2c);
    assert!(parts.settings.forward_credentials());
    assert!(parts.system);
    assert_eq!(parts.settings.connect_timeout_ms(), 1_000);
    assert_eq!(parts.settings.response_timeout_ms(), 30_000);
    assert_eq!(parts.settings.concurrency_limit(), 256);
    assert_eq!(parts.settings.retry_budget_percent(), 20);
    assert_eq!(parts.settings.outlier_threshold(), 5);
    assert_eq!(parts.version, EntityVersion::new(4).unwrap());
    assert_eq!(parts.created_at, at(1_700_000_000));
    assert_eq!(parts.updated_at, at(1_700_000_100));
    assert_eq!(parts.deleted_at, None);
}

#[rstest]
#[case::unknown_protocol(UpstreamRow { protocol: "h3".to_owned(), ..row() })]
#[case::invalid_name(UpstreamRow { name: "Core Service".to_owned(), ..row() })]
#[case::port_out_of_range(UpstreamRow { port: 0, ..row() })]
#[case::zero_timeout(UpstreamRow { connect_timeout_ms: 0, ..row() })]
#[case::version_below_one(UpstreamRow { version: 0, ..row() })]
fn a_row_that_breaks_an_invariant_is_unavailable(#[case] row: UpstreamRow) {
    assert!(matches!(restore(row), Err(RepositoryError::Unavailable(_))));
}
