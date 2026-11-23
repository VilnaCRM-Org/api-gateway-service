use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::GatewayStatement;
use crate::rate_policy::fields::{RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields};
use crate::rate_policy::statement::RatePolicyStatement;
use crate::rate_policy::{RatePolicy, RatePolicyStamp};
use crate::route::Route;
use crate::route::fixtures::{fields, stamp};
use crate::route::statement::RouteStatement;
use crate::state::key::StateKey;
use crate::upstream::settings::{UpstreamFields, UpstreamProtocol, UpstreamSettingsDraft};
use crate::upstream::statement::UpstreamStatement;
use crate::upstream::{Upstream, UpstreamStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::change_statement::ChangeStatement;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RatePolicyId, RouteId, UpstreamId};
use crate::value_object::upstream_name::UpstreamName;

const ROUTE: &str = "00000000-0000-7000-8000-000000000001";
const POLICY: &str = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap())
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn upstream() -> UpstreamStatement {
    let fields = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
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
        },
    )
    .unwrap();
    UpstreamStatement::insert(&Upstream::create(
        UpstreamId::parse("5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d").unwrap(),
        fields,
        false,
        UpstreamStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: at(),
        },
    ))
}

fn route() -> RouteStatement {
    RouteStatement::insert(&Route::create(
        RouteId::parse(ROUTE).unwrap(),
        fields("api.example.com", "/users", &[HttpMethod::Get]),
        false,
        stamp(10),
    ))
}

fn rate_policy() -> RatePolicyStatement {
    let fields = RatePolicyFields::new(RatePolicyDraft {
        name: "per-ip".to_owned(),
        key_kind: RateKeyKind::Ip,
        limit: 100,
        period_seconds: 60,
        burst: 10,
        fallback: RateFallback::Divided,
    })
    .unwrap();
    RatePolicyStatement::insert(&RatePolicy::create(
        RatePolicyId::parse(POLICY).unwrap(),
        fields,
        RatePolicyStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: actor(),
            occurred_at: at(),
        },
    ))
}

#[test]
fn each_write_changes_the_state_record_of_its_own_entity() {
    assert_eq!(
        GatewayStatement::Upstream(upstream()).state_key(),
        StateKey::Upstream(UpstreamName::new("core").unwrap())
    );
    assert_eq!(
        GatewayStatement::Route(route()).state_key(),
        StateKey::Route(RouteId::parse(ROUTE).unwrap())
    );
    assert_eq!(
        GatewayStatement::RatePolicy(rate_policy()).state_key(),
        StateKey::RatePolicy(RatePolicyId::parse(POLICY).unwrap())
    );
}

#[test]
fn a_statement_becomes_the_change_statement_of_its_entity() {
    assert_eq!(
        ChangeStatement::from(upstream()),
        ChangeStatement::SaveGateway(Box::new(GatewayStatement::Upstream(upstream())))
    );
    assert_eq!(
        ChangeStatement::from(route()),
        ChangeStatement::SaveGateway(Box::new(GatewayStatement::Route(route())))
    );
    assert_eq!(
        ChangeStatement::from(rate_policy()),
        ChangeStatement::SaveGateway(Box::new(GatewayStatement::RatePolicy(rate_policy())))
    );
}
