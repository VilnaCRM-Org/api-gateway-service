use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::UpstreamStatement;
use crate::upstream::settings::{UpstreamFields, UpstreamProtocol, UpstreamSettingsDraft};
use crate::upstream::{Upstream, UpstreamStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::UpstreamId;

const UPSTREAM: &str = "5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn upstream() -> Upstream {
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
    Upstream::create(
        UpstreamId::parse(UPSTREAM).unwrap(),
        fields,
        false,
        UpstreamStamp {
            event_id: Uuid::parse(EVENT).unwrap(),
            actor: ActorRef::User(Uuid::parse(USER).unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1_700_000_000))
                .unwrap(),
        },
    )
}

#[test]
fn an_insert_carries_the_state_of_the_upstream_and_expects_no_version() {
    let upstream = upstream();

    let statement = UpstreamStatement::insert(&upstream);

    assert_eq!(statement.upstream(), upstream.parts());
    assert_eq!(statement.expected(), None);
}

#[test]
fn an_update_carries_the_state_of_the_upstream_and_the_expected_version() {
    let upstream = upstream();
    let expected = EntityVersion::new(3).unwrap();

    let statement = UpstreamStatement::update(&upstream, expected);

    assert_eq!(statement.upstream(), upstream.parts());
    assert_eq!(statement.expected(), Some(expected));
}
