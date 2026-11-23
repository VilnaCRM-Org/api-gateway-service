use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{RatePolicyCreated, RatePolicyDeleted, RatePolicyUpdated};
use super::fields::{RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields};
use super::{RatePolicy, RatePolicyParts, RatePolicyStamp};
use crate::error::{ConfigChangeRefused, InvalidRatePolicy, VersionConflict};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::event_data::EventValue;
use crate::value_object::identifier::RatePolicyId;

const POLICY: &str = "6c3f0d2b-8e4a-4b7c-9d1e-2f3a4b5c6d7e";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn stamp(seconds: u64) -> RatePolicyStamp {
    RatePolicyStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        occurred_at: at(seconds),
    }
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn id() -> RatePolicyId {
    RatePolicyId::parse(POLICY).unwrap()
}

fn draft(key_kind: RateKeyKind) -> RatePolicyDraft {
    RatePolicyDraft {
        name: "per-subject".to_owned(),
        key_kind,
        limit: 100,
        period_seconds: 60,
        burst: 20,
        fallback: RateFallback::Divided,
    }
}

fn fields() -> RatePolicyFields {
    RatePolicyFields::new(draft(RateKeyKind::Subject)).unwrap()
}

fn stored(current: i64) -> RatePolicy {
    RatePolicy::restore(RatePolicyParts {
        id: id(),
        fields: fields(),
        version: version(current),
        created_at: at(10),
        updated_at: at(20),
        deleted_at: None,
    })
}

fn single_event<E: DomainEvent + Clone>(policy: &mut RatePolicy) -> E {
    let events = policy.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[rstest]
#[case(RateKeyKind::Ip, "ip")]
#[case(RateKeyKind::Subject, "subject")]
#[case(RateKeyKind::SubjectRoute, "subject_route")]
#[case(RateKeyKind::Route, "route")]
fn every_key_kind_is_accepted(#[case] kind: RateKeyKind, #[case] name: &str) {
    let fields = RatePolicyFields::new(draft(kind)).unwrap();

    assert_eq!(fields.key_kind(), kind);
    assert_eq!(kind.as_str(), name);
}

#[test]
fn valid_fields_are_kept() {
    let fields = fields();

    assert_eq!(fields.name(), "per-subject");
    assert_eq!(fields.limit(), 100);
    assert_eq!(fields.period_seconds(), 60);
    assert_eq!(fields.burst(), 20);
    assert_eq!(fields.fallback(), RateFallback::Divided);
    assert_eq!(RateFallback::Divided.as_str(), "divided");
    assert_eq!(RateFallback::Full.as_str(), "full");
}

#[test]
fn a_zero_burst_is_accepted() {
    let draft = RatePolicyDraft {
        burst: 0,
        ..draft(RateKeyKind::Ip)
    };

    assert_eq!(RatePolicyFields::new(draft).unwrap().burst(), 0);
}

#[rstest]
#[case::empty_name(RatePolicyDraft { name: String::new(), ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::NameLength])]
#[case::long_name(RatePolicyDraft { name: "n".repeat(101), ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::NameLength])]
#[case::control_character(RatePolicyDraft { name: "a\u{7}b".to_owned(), ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::NameControlCharacter])]
#[case::zero_limit(RatePolicyDraft { limit: 0, ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::LimitRange])]
#[case::zero_period(RatePolicyDraft { period_seconds: 0, ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::PeriodRange])]
#[case::negative_burst(RatePolicyDraft { burst: -1, ..draft(RateKeyKind::Ip) }, vec![InvalidRatePolicy::BurstRange])]
#[case::every_violation(
    RatePolicyDraft { name: String::new(), limit: 0, period_seconds: 0, burst: -1, ..draft(RateKeyKind::Ip) },
    vec![
        InvalidRatePolicy::NameLength,
        InvalidRatePolicy::LimitRange,
        InvalidRatePolicy::PeriodRange,
        InvalidRatePolicy::BurstRange,
    ]
)]
fn invalid_drafts_report_each_violation(
    #[case] draft: RatePolicyDraft,
    #[case] expected: Vec<InvalidRatePolicy>,
) {
    assert_eq!(RatePolicyFields::new(draft).unwrap_err(), expected);
}

#[test]
fn creation_records_the_created_event_at_version_one() {
    let mut policy = RatePolicy::create(id(), fields(), stamp(100));

    assert_eq!(policy.parts().version, EntityVersion::INITIAL);
    let created: RatePolicyCreated = single_event(&mut policy);
    assert_eq!(created.rate_policy_id, id());
    assert_eq!(created.name, "per-subject");
}

#[test]
fn an_update_replaces_the_fields_and_names_what_changed() {
    let mut policy = stored(3);
    let change = RatePolicyFields::new(RatePolicyDraft {
        name: "renamed".to_owned(),
        key_kind: RateKeyKind::Route,
        limit: 1,
        period_seconds: 1,
        burst: 1,
        fallback: RateFallback::Full,
    })
    .unwrap();

    policy.update(Some(version(3)), change, stamp(200)).unwrap();

    assert_eq!(policy.parts().version, version(4));
    assert_eq!(policy.parts().fields.name(), "renamed");
    let updated: RatePolicyUpdated = single_event(&mut policy);
    assert_eq!(
        updated.changed_fields,
        vec![
            "name",
            "keyKind",
            "limit",
            "periodSeconds",
            "burst",
            "fallback"
        ]
    );
}

#[rstest]
#[case(None, VersionConflict::Missing)]
#[case(Some(version(2)), VersionConflict::Stale { expected: version(2), current: version(3) })]
fn an_update_needs_the_current_version(
    #[case] expected: Option<EntityVersion>,
    #[case] conflict: VersionConflict,
) {
    let mut policy = stored(3);

    assert_eq!(
        policy.update(expected, fields(), stamp(200)),
        Err(ConfigChangeRefused::Version(conflict))
    );
    assert!(policy.pull_domain_events().is_empty());
}

#[test]
fn deletion_marks_the_policy_deleted_and_refuses_every_later_change() {
    let mut policy = stored(3);

    policy.delete(Some(version(3)), stamp(300)).unwrap();

    assert_eq!(policy.parts().deleted_at, Some(at(300)));
    let deleted: RatePolicyDeleted = single_event(&mut policy);
    assert_eq!(deleted.version, version(4));
    assert_eq!(
        policy.delete(Some(version(4)), stamp(400)),
        Err(ConfigChangeRefused::Deleted)
    );
}

#[test]
fn recorded_events_become_envelopes_with_their_data() {
    let mut policy = RatePolicy::create(id(), fields(), stamp(100));
    policy
        .update(
            Some(EntityVersion::INITIAL),
            RatePolicyFields::new(RatePolicyDraft {
                limit: 5,
                ..draft(RateKeyKind::Subject)
            })
            .unwrap(),
            stamp(200),
        )
        .unwrap();
    policy.delete(Some(version(2)), stamp(300)).unwrap();

    let envelopes = policy.pull_envelopes().unwrap();

    let types: Vec<String> = envelopes
        .iter()
        .map(|envelope| envelope.parts().event_type.to_string())
        .collect();
    assert_eq!(
        types,
        [
            "iam.rate_policy.created",
            "iam.rate_policy.updated",
            "iam.rate_policy.deleted"
        ]
    );
    let updated = envelopes[1].parts().data.fields();
    assert!(updated.contains(&(
        "changedFields".to_owned(),
        EventValue::List(vec![EventValue::Text("limit".to_owned())])
    )));
}
