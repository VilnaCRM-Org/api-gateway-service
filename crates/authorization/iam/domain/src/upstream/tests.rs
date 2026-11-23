use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{UpstreamCreated, UpstreamDeleted, UpstreamUpdated};
use super::settings::{UpstreamFields, UpstreamProtocol, UpstreamSettingsDraft};
use super::{Upstream, UpstreamParts, UpstreamStamp};
use crate::error::VersionConflict;
use crate::error::{ConfigChangeRefused, InvalidIamValue, InvalidUpstream, UpstreamChangeRefused};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::EventValue;
use crate::value_object::identifier::UpstreamId;

const UPSTREAM: &str = "5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn stamp(seconds: u64) -> UpstreamStamp {
    UpstreamStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        occurred_at: at(seconds),
    }
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn id() -> UpstreamId {
    UpstreamId::parse(UPSTREAM).unwrap()
}

fn settings() -> UpstreamSettingsDraft {
    UpstreamSettingsDraft {
        namespace: "platform".to_owned(),
        service_name: "core-service".to_owned(),
        catalog_service: "core".to_owned(),
        port: 8080,
        protocol: UpstreamProtocol::Http1,
        forward_credentials: false,
        connect_timeout_ms: 1_000,
        response_timeout_ms: 30_000,
        concurrency_limit: 256,
        retry_budget_percent: 20,
        outlier_threshold: 5,
    }
}

fn fields(name: &str) -> UpstreamFields {
    UpstreamFields::new(name, &settings()).unwrap()
}

fn stored(current: i64) -> Upstream {
    let (name, settings) = fields("core").into_parts();
    Upstream::restore(UpstreamParts {
        id: id(),
        name,
        settings,
        system: false,
        version: version(current),
        created_at: at(10),
        updated_at: at(20),
        deleted_at: None,
    })
}

fn single_event<E: DomainEvent + Clone>(upstream: &mut Upstream) -> E {
    let events = upstream.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[test]
fn valid_fields_are_kept() {
    let fields = fields("core");
    let settings = fields.settings();

    assert_eq!(fields.name().as_str(), "core");
    assert_eq!(settings.namespace(), "platform");
    assert_eq!(settings.service_name(), "core-service");
    assert_eq!(settings.catalog_service().as_str(), "core");
    assert_eq!(settings.port(), 8080);
    assert_eq!(settings.protocol(), UpstreamProtocol::Http1);
    assert!(!settings.forward_credentials());
    assert_eq!(settings.connect_timeout_ms(), 1_000);
    assert_eq!(settings.response_timeout_ms(), 30_000);
    assert_eq!(settings.concurrency_limit(), 256);
    assert_eq!(settings.retry_budget_percent(), 20);
    assert_eq!(settings.outlier_threshold(), 5);
}

#[rstest]
#[case::bounds(UpstreamSettingsDraft { port: 65_535, retry_budget_percent: 100, ..settings() })]
#[case::zero_budget(UpstreamSettingsDraft { retry_budget_percent: 0, protocol: UpstreamProtocol::H2c, ..settings() })]
fn boundary_settings_are_accepted(#[case] draft: UpstreamSettingsDraft) {
    assert!(UpstreamFields::new("core", &draft).is_ok());
}

#[rstest]
#[case::empty_name("", settings(), vec![InvalidUpstream::NameLength])]
#[case::upper_case_name("Core", settings(), vec![InvalidUpstream::NamePattern])]
#[case::port_zero("core", UpstreamSettingsDraft { port: 0, ..settings() }, vec![InvalidUpstream::PortRange])]
#[case::port_high("core", UpstreamSettingsDraft { port: 65_536, ..settings() }, vec![InvalidUpstream::PortRange])]
#[case::zero_timeouts("core", UpstreamSettingsDraft { connect_timeout_ms: 0, response_timeout_ms: 0, ..settings() }, vec![InvalidUpstream::ConnectTimeoutRange, InvalidUpstream::ResponseTimeoutRange])]
#[case::zero_concurrency("core", UpstreamSettingsDraft { concurrency_limit: 0, ..settings() }, vec![InvalidUpstream::ConcurrencyLimitRange])]
#[case::budget_above_100("core", UpstreamSettingsDraft { retry_budget_percent: 101, ..settings() }, vec![InvalidUpstream::RetryBudgetRange])]
#[case::negative_budget("core", UpstreamSettingsDraft { retry_budget_percent: -1, ..settings() }, vec![InvalidUpstream::RetryBudgetRange])]
#[case::zero_outlier("core", UpstreamSettingsDraft { outlier_threshold: 0, ..settings() }, vec![InvalidUpstream::OutlierThresholdRange])]
#[case::bad_kubernetes_names(
    "core",
    UpstreamSettingsDraft { namespace: "Plat_form".to_owned(), service_name: String::new(), ..settings() },
    vec![InvalidUpstream::NamespaceFormat, InvalidUpstream::ServiceFormat]
)]
#[case::bad_catalogue_service("core", UpstreamSettingsDraft { catalog_service: "Core".to_owned(), ..settings() }, vec![InvalidUpstream::CatalogServicePattern])]
#[case::empty_catalogue_service("core", UpstreamSettingsDraft { catalog_service: String::new(), ..settings() }, vec![InvalidUpstream::CatalogServiceLength])]
#[case::every_violation(
    "-",
    UpstreamSettingsDraft {
        namespace: "-".to_owned(),
        service_name: "-".to_owned(),
        catalog_service: "-".to_owned(),
        port: 0,
        connect_timeout_ms: 0,
        response_timeout_ms: 0,
        concurrency_limit: 0,
        retry_budget_percent: 101,
        outlier_threshold: 0,
        ..settings()
    },
    vec![
        InvalidUpstream::NamePattern,
        InvalidUpstream::NamespaceFormat,
        InvalidUpstream::ServiceFormat,
        InvalidUpstream::CatalogServicePattern,
        InvalidUpstream::PortRange,
        InvalidUpstream::ConnectTimeoutRange,
        InvalidUpstream::ResponseTimeoutRange,
        InvalidUpstream::ConcurrencyLimitRange,
        InvalidUpstream::RetryBudgetRange,
        InvalidUpstream::OutlierThresholdRange,
    ]
)]
fn invalid_fields_report_each_violation(
    #[case] name: &str,
    #[case] draft: UpstreamSettingsDraft,
    #[case] expected: Vec<InvalidUpstream>,
) {
    assert_eq!(UpstreamFields::new(name, &draft).unwrap_err(), expected);
}

#[test]
fn protocols_have_names() {
    assert_eq!(UpstreamProtocol::Http1.as_str(), "http1");
    assert_eq!(UpstreamProtocol::H2c.as_str(), "h2c");
}

#[test]
fn creation_records_the_created_event_at_version_one() {
    let mut upstream = Upstream::create(id(), fields("core"), false, stamp(100));

    assert_eq!(upstream.parts().version, EntityVersion::INITIAL);
    assert_eq!(upstream.parts().created_at, at(100));
    assert!(!upstream.parts().system);
    let created: UpstreamCreated = single_event(&mut upstream);
    assert_eq!(created.upstream_id, id());
    assert_eq!(created.name.as_str(), "core");
    assert_eq!(created.catalog_service.as_str(), "core");
}

#[test]
fn an_update_replaces_the_settings_and_names_what_changed() {
    let mut upstream = stored(3);
    let change = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
            port: 9090,
            forward_credentials: true,
            ..settings()
        },
    )
    .unwrap();

    upstream
        .update(Some(version(3)), change, stamp(200))
        .unwrap();

    assert_eq!(upstream.parts().version, version(4));
    assert_eq!(upstream.parts().settings.port(), 9090);
    let updated: UpstreamUpdated = single_event(&mut upstream);
    assert_eq!(updated.changed_fields, vec!["port", "forwardCredentials"]);
}

#[test]
fn every_setting_is_reported_when_it_changes() {
    let before = fields("core");
    let after = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
            namespace: "other".to_owned(),
            service_name: "other".to_owned(),
            catalog_service: "billing".to_owned(),
            port: 1,
            protocol: UpstreamProtocol::H2c,
            forward_credentials: true,
            connect_timeout_ms: 1,
            response_timeout_ms: 1,
            concurrency_limit: 1,
            retry_budget_percent: 1,
            outlier_threshold: 1,
        },
    )
    .unwrap();

    assert_eq!(
        before.settings().changed_fields(after.settings()),
        vec![
            "namespace",
            "serviceName",
            "catalogService",
            "port",
            "protocol",
            "forwardCredentials",
            "connectTimeoutMs",
            "responseTimeoutMs",
            "concurrencyLimit",
            "retryBudgetPercent",
            "outlierThreshold",
        ]
    );
}

#[test]
fn a_rename_is_refused_and_changes_nothing() {
    let mut upstream = stored(3);

    let result = upstream.update(Some(version(3)), fields("billing"), stamp(200));

    assert_eq!(result, Err(UpstreamChangeRefused::Renamed));
    assert_eq!(UpstreamChangeRefused::Renamed.code(), "renamed");
    assert_eq!(upstream.parts().version, version(3));
    assert_eq!(upstream.parts().name.as_str(), "core");
    assert!(upstream.pull_domain_events().is_empty());
}

#[rstest]
#[case(None, VersionConflict::Missing)]
#[case(Some(version(2)), VersionConflict::Stale { expected: version(2), current: version(3) })]
fn an_update_needs_the_current_version(
    #[case] expected: Option<EntityVersion>,
    #[case] conflict: VersionConflict,
) {
    let mut upstream = stored(3);

    let result = upstream.update(expected, fields("core"), stamp(200));

    assert_eq!(
        result,
        Err(UpstreamChangeRefused::Refused(
            ConfigChangeRefused::Version(conflict)
        ))
    );
}

#[test]
fn deletion_marks_the_upstream_deleted_and_refuses_every_later_change() {
    let mut upstream = stored(3);

    upstream.delete(Some(version(3)), stamp(300)).unwrap();

    assert_eq!(upstream.parts().deleted_at, Some(at(300)));
    let deleted: UpstreamDeleted = single_event(&mut upstream);
    assert_eq!(deleted.version, version(4));
    assert_eq!(
        upstream.delete(Some(version(4)), stamp(400)),
        Err(ConfigChangeRefused::Deleted)
    );
    assert_eq!(
        upstream.update(Some(version(4)), fields("core"), stamp(400)),
        Err(UpstreamChangeRefused::Refused(ConfigChangeRefused::Deleted))
    );
    assert_eq!(ConfigChangeRefused::Deleted.code(), "deleted");
}

#[test]
fn the_version_cannot_pass_its_largest_value() {
    let mut upstream = stored(i64::MAX);

    let refused = upstream
        .delete(Some(version(i64::MAX)), stamp(300))
        .unwrap_err();

    assert_eq!(
        refused,
        ConfigChangeRefused::Range(InvalidIamValue::EntityVersionRange)
    );
    assert_eq!(refused.code(), "range");
}

#[test]
fn recorded_events_become_envelopes_with_their_data() {
    let mut upstream = Upstream::create(id(), fields("core"), false, stamp(100));
    upstream
        .update(
            Some(EntityVersion::INITIAL),
            UpstreamFields::new(
                "core",
                &UpstreamSettingsDraft {
                    port: 9090,
                    ..settings()
                },
            )
            .unwrap(),
            stamp(200),
        )
        .unwrap();
    upstream.delete(Some(version(2)), stamp(300)).unwrap();

    let envelopes = upstream.pull_envelopes().unwrap();

    let types: Vec<String> = envelopes
        .iter()
        .map(|envelope| envelope.parts().event_type.to_string())
        .collect();
    assert_eq!(
        types,
        [
            "iam.upstream.created",
            "iam.upstream.updated",
            "iam.upstream.deleted"
        ]
    );
    let created = envelopes.first().unwrap().parts().data.fields();
    assert!(created.contains(&(
        "catalogService".to_owned(),
        EventValue::Text("core".to_owned())
    )));
    let updated = envelopes[1].parts().data.fields();
    assert!(updated.contains(&(
        "changedFields".to_owned(),
        EventValue::List(vec![EventValue::Text("port".to_owned())])
    )));
}
