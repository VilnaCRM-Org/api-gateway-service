use std::any::Any;

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent};

use super::event::{RouteCreated, RouteDeleted, RouteUpdated};
use super::fields::{RouteDraft, RouteFields};
use super::fixtures::{at, draft, fields, parts, route_id, stamp};
use super::settings::{EnforcementMode, RouteFlag, RouteFlags};
use super::{Route, RouteParts};
use crate::error::{ConfigChangeRefused, InvalidIamValue, InvalidRoute, VersionConflict};
use crate::policy::route_revocation_rule::RouteChangeClass;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RatePolicyId, RoleId};

const HOST: &str = "api.example.com";
const PATH: &str = "/api/orders/{id}";

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn stored(current: i64) -> Route {
    Route::restore(RouteParts {
        version: version(current),
        ..parts(1, fields(HOST, PATH, &[HttpMethod::Get]))
    })
}

fn single_event<E: DomainEvent + Clone>(route: &mut Route) -> E {
    let events = route.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

fn rate_policy(number: u32) -> RatePolicyId {
    RatePolicyId::parse(&format!("00000000-0000-7000-8000-{number:012x}")).unwrap()
}

#[test]
fn a_valid_draft_is_kept_with_sorted_methods_without_duplicates() {
    let fields = RouteFields::new(&draft(
        HOST,
        PATH,
        &[HttpMethod::Post, HttpMethod::Get, HttpMethod::Post],
    ))
    .unwrap();

    assert_eq!(fields.host().as_str(), HOST);
    assert_eq!(fields.methods(), [HttpMethod::Get, HttpMethod::Post]);
    assert_eq!(fields.path_pattern().as_str(), PATH);
    assert_eq!(fields.service().as_str(), "core");
    assert_eq!(fields.upstream_id(), super::fixtures::upstream_id());
    assert!(!fields.flags().anonymous());
    assert_eq!(fields.enforcement(), EnforcementMode::Enforce);
    assert_eq!(fields.body_limit().bytes(), 1_048_576);
    assert_eq!(fields.timeouts().request_ms(), 30_000);
    assert_eq!(fields.retry(), super::settings::RetryPolicy::None);
    assert_eq!(fields.rate_policies().len(), 0);
    assert!(fields.cors().is_none());
}

#[rstest]
#[case::upper_case_host(RouteDraft { host: "API.example.com".to_owned(), ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::HostFormat])]
#[case::empty_host(RouteDraft { host: String::new(), ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::HostLength])]
#[case::no_method(draft(HOST, PATH, &[]), vec![InvalidRoute::MethodsRequired])]
#[case::path_without_slash(draft(HOST, "api/orders", &[HttpMethod::Get]), vec![InvalidRoute::PathPrefix])]
#[case::invalid_service(RouteDraft { service: "Core".to_owned(), ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::ServicePattern])]
#[case::long_service(RouteDraft { service: "a".repeat(64), ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::ServiceLength])]
#[case::zero_body_limit(RouteDraft { body_limit: 0, ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::BodyLimitRange])]
#[case::zero_timeouts(RouteDraft { request_timeout_ms: 0, idle_timeout_ms: 0, ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::RequestTimeoutRange, InvalidRoute::IdleTimeoutRange])]
#[case::duplicate_rate_policy(RouteDraft { rate_policies: vec![rate_policy(1), rate_policy(1)], ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::RatePolicyDuplicate])]
#[case::too_many_rate_policies(RouteDraft { rate_policies: (1..=11).map(rate_policy).collect(), ..draft(HOST, PATH, &[HttpMethod::Get]) }, vec![InvalidRoute::RatePolicyCount])]
#[case::every_property(
    RouteDraft {
        host: "BAD".to_owned(),
        service: String::new(),
        body_limit: -1,
        ..draft(HOST, "x", &[])
    },
    vec![
        InvalidRoute::HostFormat,
        InvalidRoute::MethodsRequired,
        InvalidRoute::PathPrefix,
        InvalidRoute::ServiceLength,
        InvalidRoute::BodyLimitRange,
    ]
)]
fn invalid_drafts_report_each_violation(
    #[case] draft: RouteDraft,
    #[case] expected: Vec<InvalidRoute>,
) {
    assert_eq!(RouteFields::new(&draft).unwrap_err(), expected);
}

#[test]
fn an_invalid_cors_policy_is_reported_with_its_violations() {
    let mut invalid = draft(HOST, PATH, &[HttpMethod::Get]);
    invalid.cors = Some(super::cors::CorsDraft {
        origins: vec!["*".to_owned()],
        methods: Vec::new(),
        headers: Vec::new(),
        allow_credentials: false,
        max_age_seconds: 86_401,
    });

    assert_eq!(
        RouteFields::new(&invalid).unwrap_err(),
        vec![
            InvalidRoute::CorsOriginFormat,
            InvalidRoute::CorsMaxAgeRange
        ]
    );
}

#[test]
fn routes_share_a_method_when_their_method_sets_intersect() {
    let first = fields(HOST, PATH, &[HttpMethod::Get, HttpMethod::Post]);

    assert!(first.shares_a_method_with(&fields(HOST, PATH, &[HttpMethod::Post, HttpMethod::Put])));
    assert!(!first.shares_a_method_with(&fields(HOST, PATH, &[HttpMethod::Delete])));
}

#[test]
fn creation_records_the_created_event_at_version_one() {
    let mut route = Route::create(
        route_id(1),
        fields(HOST, PATH, &[HttpMethod::Get]),
        false,
        stamp(100),
    );

    assert_eq!(route.parts().version, EntityVersion::INITIAL);
    assert_eq!(route.parts().created_at, at(100));
    assert!(!route.parts().system);
    let created: RouteCreated = single_event(&mut route);
    assert_eq!(created.route_id, route_id(1));
    assert_eq!(created.host.as_str(), HOST);
    assert_eq!(created.path_pattern.as_str(), PATH);
    assert_eq!(created.service.as_str(), "core");
}

#[test]
fn a_system_route_keeps_its_flag() {
    let route = Route::create(
        route_id(1),
        fields(HOST, PATH, &[HttpMethod::Get]),
        true,
        stamp(100),
    );

    assert!(route.parts().system);
}

#[test]
fn an_update_replaces_the_fields_and_names_what_changed() {
    let mut route = stored(3);
    let mut change = draft(HOST, "/api/orders", &[HttpMethod::Get]);
    change.request_timeout_ms = 5_000;

    let class = route
        .update(
            Some(version(3)),
            RouteFields::new(&change).unwrap(),
            stamp(200),
        )
        .unwrap();

    assert_eq!(class, RouteChangeClass::Standard);
    assert_eq!(route.parts().version, version(4));
    assert_eq!(route.parts().updated_at, at(200));
    assert_eq!(route.parts().fields.timeouts().request_ms(), 5_000);
    let updated: RouteUpdated = single_event(&mut route);
    assert_eq!(updated.version, version(4));
    assert_eq!(updated.changed_fields, vec!["pathPattern", "timeouts"]);
    assert!(!updated.revocation);
}

#[test]
fn clearing_anonymous_is_a_revocation() {
    let anonymous = RouteDraft {
        flags: RouteFlags::default().with(RouteFlag::Anonymous, true),
        ..draft(HOST, PATH, &[HttpMethod::Get])
    };
    let mut route = Route::restore(RouteParts {
        version: version(1),
        ..parts(1, RouteFields::new(&anonymous).unwrap())
    });

    let class = route
        .update(
            Some(version(1)),
            fields(HOST, PATH, &[HttpMethod::Get]),
            stamp(200),
        )
        .unwrap();

    assert_eq!(class, RouteChangeClass::Revocation);
    let updated: RouteUpdated = single_event(&mut route);
    assert!(updated.revocation);
    assert_eq!(updated.changed_fields, vec!["anonymous"]);
}

#[rstest]
#[case(None, ConfigChangeRefused::Version(VersionConflict::Missing))]
#[case(
    Some(version(2)),
    ConfigChangeRefused::Version(VersionConflict::Stale { expected: version(2), current: version(3) })
)]
fn an_update_needs_the_current_version(
    #[case] expected: Option<EntityVersion>,
    #[case] refused: ConfigChangeRefused,
) {
    let mut route = stored(3);

    let result = route.update(
        expected,
        fields(HOST, PATH, &[HttpMethod::Post]),
        stamp(200),
    );

    assert_eq!(result, Err(refused));
    assert_eq!(route.parts().version, version(3));
    assert!(route.pull_domain_events().is_empty());
}

#[test]
fn deletion_marks_the_route_deleted_and_refuses_every_later_change() {
    let mut route = stored(3);

    route.delete(Some(version(3)), stamp(300)).unwrap();

    assert_eq!(route.parts().deleted_at, Some(at(300)));
    assert_eq!(route.parts().version, version(4));
    let deleted: RouteDeleted = single_event(&mut route);
    assert_eq!(deleted.version, version(4));
    assert_eq!(
        route.delete(Some(version(4)), stamp(400)),
        Err(ConfigChangeRefused::Deleted)
    );
    assert_eq!(
        route.update(
            Some(version(4)),
            fields(HOST, PATH, &[HttpMethod::Get]),
            stamp(400)
        ),
        Err(ConfigChangeRefused::Deleted)
    );
}

#[test]
fn the_version_cannot_pass_its_largest_value() {
    let mut route = Route::restore(RouteParts {
        version: version(i64::MAX),
        ..parts(1, fields(HOST, PATH, &[HttpMethod::Get]))
    });

    assert_eq!(
        route.delete(Some(version(i64::MAX)), stamp(300)),
        Err(ConfigChangeRefused::Range(
            InvalidIamValue::EntityVersionRange
        ))
    );
}

#[test]
fn recorded_events_become_envelopes_in_order() {
    let mut route = Route::create(
        route_id(1),
        fields(HOST, PATH, &[HttpMethod::Get]),
        false,
        stamp(100),
    );
    route
        .update(
            Some(EntityVersion::INITIAL),
            fields(HOST, PATH, &[HttpMethod::Post]),
            stamp(200),
        )
        .unwrap();
    route.delete(Some(version(2)), stamp(300)).unwrap();

    let envelopes = route.pull_envelopes().unwrap();

    let types: Vec<String> = envelopes
        .iter()
        .map(|envelope| envelope.parts().event_type.to_string())
        .collect();
    assert_eq!(
        types,
        [
            "iam.route.created",
            "iam.route.updated",
            "iam.route.deleted"
        ]
    );
    assert_eq!(route.pull_envelopes().unwrap().len(), 0);
}

#[test]
fn an_event_of_another_aggregate_cannot_be_enveloped() {
    use crate::entity::aggregate_event::envelopes_of;
    use crate::error::InvalidEventEnvelope;

    let mut other = crate::role::Role::create(
        RoleId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
        crate::role::RoleFields::new("Billing".to_owned(), None).unwrap(),
        crate::role::RoleStamp {
            event_id: shared_domain::Uuid::parse(super::fixtures::EVENT).unwrap(),
            actor: ActorRef::User(shared_domain::Uuid::parse(super::fixtures::USER).unwrap()),
            occurred_at: at(1),
        },
    );
    let events = other.pull_domain_events();

    assert_eq!(
        envelopes_of(&events, &[]).unwrap_err(),
        InvalidEventEnvelope::EventType
    );
}
