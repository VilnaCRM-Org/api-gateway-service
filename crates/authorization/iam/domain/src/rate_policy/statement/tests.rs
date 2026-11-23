use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::RatePolicyStatement;
use crate::rate_policy::fields::{RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields};
use crate::rate_policy::{RatePolicy, RatePolicyStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::identifier::RatePolicyId;

fn rate_policy() -> RatePolicy {
    let fields = RatePolicyFields::new(RatePolicyDraft {
        name: "per-ip".to_owned(),
        key_kind: RateKeyKind::Ip,
        limit: 100,
        period_seconds: 60,
        burst: 10,
        fallback: RateFallback::Divided,
    })
    .unwrap();
    RatePolicy::create(
        RatePolicyId::parse("6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e").unwrap(),
        fields,
        RatePolicyStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1_700_000_000))
                .unwrap(),
        },
    )
}

#[test]
fn an_insert_carries_the_state_of_the_rate_policy_and_expects_no_version() {
    let policy = rate_policy();

    let statement = RatePolicyStatement::insert(&policy);

    assert_eq!(statement.rate_policy(), policy.parts());
    assert_eq!(statement.expected(), None);
}

#[test]
fn an_update_carries_the_state_of_the_rate_policy_and_the_expected_version() {
    let policy = rate_policy();
    let expected = EntityVersion::new(3).unwrap();

    let statement = RatePolicyStatement::update(&policy, expected);

    assert_eq!(statement.rate_policy(), policy.parts());
    assert_eq!(statement.expected(), Some(expected));
}
