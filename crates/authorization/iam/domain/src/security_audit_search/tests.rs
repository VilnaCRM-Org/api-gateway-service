use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::Uuid;

use super::{SecurityAuditFilter, SecurityAuditSearch};
use crate::entity::security_audit_event::{
    SecurityAuditEvent, SecurityAuditEventParts, StoredSecurityAuditEvent,
};
use crate::error::InvalidIamValue;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::audit_action::AuditAction;
use crate::value_object::audit_hash::AuditHash;
use crate::value_object::audit_outcome::AuditOutcome;
use crate::value_object::audit_target::AuditTarget;
use crate::value_object::identifier::SecurityAuditEventId;

const ID: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const OTHER_USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abd";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn record() -> StoredSecurityAuditEvent {
    let event = SecurityAuditEvent::record(SecurityAuditEventParts {
        id: SecurityAuditEventId::parse(ID).unwrap(),
        occurred_at: at(1_000),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        caller_service: None,
        action: AuditAction::new("role.create").unwrap(),
        target: AuditTarget::new("role", "r-1").unwrap(),
        scope: None,
        before: None,
        after: None,
        idempotency_key: None,
        outcome: AuditOutcome::Committed,
        reason: None,
        policy_version: None,
        request_id: None,
    })
    .unwrap();
    StoredSecurityAuditEvent::new(1, event, AuditHash::GENESIS, AuditHash::GENESIS).unwrap()
}

#[test]
fn a_filter_without_conditions_keeps_every_record() {
    let filter = SecurityAuditFilter::new();

    assert!(filter.matches(&record()));
    assert_eq!(filter, SecurityAuditFilter::default());
    assert_eq!(filter.since_micros(), None);
    assert_eq!(filter.until_micros(), None);
    assert_eq!(filter.actor(), None);
    assert_eq!(filter.action(), None);
    assert_eq!(filter.target_type(), None);
    assert_eq!(filter.target_id(), None);
    assert_eq!(filter.outcome(), None);
}

#[rstest]
#[case::inside_the_range(Some(1_000), Some(1_001), true)]
#[case::the_lower_bound_is_kept(Some(1_000), None, true)]
#[case::the_upper_bound_is_not_kept(None, Some(1_000), false)]
#[case::before_the_range(Some(1_001), None, false)]
#[case::after_the_range(None, Some(999), false)]
fn the_time_range_keeps_records_from_its_start_up_to_its_end(
    #[case] from: Option<u64>,
    #[case] until: Option<u64>,
    #[case] kept: bool,
) {
    let filter = SecurityAuditFilter::new()
        .within(from.map(at), until.map(at))
        .unwrap();

    assert_eq!(filter.matches(&record()), kept);
}

#[test]
fn the_bounds_of_the_range_are_kept_in_microseconds() {
    let filter = SecurityAuditFilter::new()
        .within(Some(at(2)), Some(at(3)))
        .unwrap();

    assert_eq!(filter.since_micros(), Some(2_000_000));
    assert_eq!(filter.until_micros(), Some(3_000_000));
}

#[test]
fn a_bound_before_1970_is_refused() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .unwrap();

    assert_eq!(
        SecurityAuditFilter::new().within(Some(before), None),
        Err(InvalidIamValue::AuditTimestamp)
    );
    assert_eq!(
        SecurityAuditFilter::new().within(None, Some(before)),
        Err(InvalidIamValue::AuditTimestamp)
    );
}

#[rstest]
#[case(USER, true)]
#[case(OTHER_USER, false)]
fn the_actor_condition_keeps_the_records_of_that_actor(#[case] actor: &str, #[case] kept: bool) {
    let filter = SecurityAuditFilter::new().by_actor(ActorRef::User(Uuid::parse(actor).unwrap()));

    assert_eq!(filter.matches(&record()), kept);
    assert_eq!(
        filter.actor(),
        Some(&ActorRef::User(Uuid::parse(actor).unwrap()))
    );
}

#[rstest]
#[case("role.create", true)]
#[case("role.update", false)]
fn the_action_condition_keeps_the_records_of_that_action(#[case] action: &str, #[case] kept: bool) {
    let filter = SecurityAuditFilter::new().of_action(AuditAction::new(action).unwrap());

    assert_eq!(filter.matches(&record()), kept);
    assert_eq!(filter.action().map(AuditAction::as_str), Some(action));
}

#[rstest]
#[case(AuditOutcome::Committed, true)]
#[case(AuditOutcome::Rejected, false)]
fn the_outcome_condition_keeps_the_records_of_that_outcome(
    #[case] outcome: AuditOutcome,
    #[case] kept: bool,
) {
    let filter = SecurityAuditFilter::new().with_outcome(outcome);

    assert_eq!(filter.matches(&record()), kept);
    assert_eq!(filter.outcome(), Some(outcome));
}

#[rstest]
#[case("role", None, true)]
#[case("role", Some("r-1"), true)]
#[case("role", Some("r-2"), false)]
#[case("upstream", None, false)]
fn the_target_condition_keeps_a_type_or_one_target(
    #[case] target_type: &str,
    #[case] target_id: Option<&str>,
    #[case] kept: bool,
) {
    let filter = SecurityAuditFilter::new()
        .about(target_type, target_id)
        .unwrap();

    assert_eq!(filter.matches(&record()), kept);
    assert_eq!(filter.target_type(), Some(target_type));
    assert_eq!(filter.target_id(), target_id);
}

#[rstest]
#[case("Role", None, InvalidIamValue::AuditTargetType)]
#[case("", Some("r-1"), InvalidIamValue::AuditTargetType)]
#[case("role", Some(""), InvalidIamValue::AuditTargetId)]
#[case("role", Some("two words"), InvalidIamValue::AuditTargetId)]
fn a_target_that_is_not_valid_is_refused(
    #[case] target_type: &str,
    #[case] target_id: Option<&str>,
    #[case] error: InvalidIamValue,
) {
    assert_eq!(
        SecurityAuditFilter::new().about(target_type, target_id),
        Err(error)
    );
}

#[test]
fn every_condition_must_hold_at_once() {
    let filter = SecurityAuditFilter::new()
        .by_actor(ActorRef::User(Uuid::parse(USER).unwrap()))
        .of_action(AuditAction::new("role.create").unwrap())
        .with_outcome(AuditOutcome::Rejected);

    assert!(!filter.matches(&record()));
}

#[test]
fn a_search_holds_its_filter_cursor_and_limit() {
    let search = SecurityAuditSearch {
        filter: SecurityAuditFilter::new(),
        before_seq: Some(7),
        limit: 31,
    };

    assert_eq!(search.clone(), search);
    assert_eq!(search.before_seq, Some(7));
    assert_eq!(search.limit, 31);
}
