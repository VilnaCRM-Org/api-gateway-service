use std::sync::Arc;

use iam_domain::{
    AccessClass, AccessDecision, AccessLane, Decision, DecisionReason, PermissionFlags, Rng,
    SampleRate, SubjectKind,
};
use rstest::rstest;
use test_support::log::LogRecorder;

use super::{AccessItem, AccessRecordBuilder};
use crate::access_log::facts::AccessFacts;
use crate::access_log::fixtures::{allowed, decision_id, denied, unavailable};

/// A generator that always returns the same draw.
#[derive(Debug)]
struct ConstantRng(u64);

impl Rng for ConstantRng {
    fn next_u64(&self) -> u64 {
        self.0
    }
}

fn builder(rate: SampleRate, draw: u64) -> AccessRecordBuilder {
    AccessRecordBuilder::new(Arc::new(ConstantRng(draw)), rate)
}

fn built(facts: AccessFacts) -> AccessItem {
    builder(SampleRate::ALL, 0).build(facts).unwrap()
}

fn with_flags(flags: PermissionFlags) -> AccessFacts {
    let mut facts = allowed();
    facts.verdict.trace.flags = flags;
    facts
}

#[rstest]
#[case::missing_permission(denied(DecisionReason::PermissionMissing, 403))]
#[case::invalid_token(denied(DecisionReason::TokenInvalid, 401))]
#[case::unknown_operation(denied(DecisionReason::UnknownOperation, 403))]
#[case::audit_mode_would_deny(denied(DecisionReason::AuditModeWouldDeny, 200))]
fn every_denial_goes_to_the_audit_lane(#[case] facts: AccessFacts) {
    let item = built(facts);

    assert_eq!(item.lane, AccessLane::Audit);
    assert_eq!(item.class, AccessClass::Audit);
    assert_eq!(item.record.decision, AccessDecision::Deny);
}

#[rstest]
#[case::always_audit(PermissionFlags::NONE.with_audit_always())]
#[case::sensitive(PermissionFlags::NONE.with_sensitive())]
#[case::both(PermissionFlags::NONE.with_sensitive().with_audit_always())]
fn an_allow_on_an_always_audit_or_sensitive_key_goes_to_the_audit_lane(
    #[case] flags: PermissionFlags,
) {
    let item = built(with_flags(flags));

    assert_eq!(item.lane, AccessLane::Audit);
    assert_eq!(item.record.decision, AccessDecision::Allow);
}

#[test]
fn a_wildcard_allow_goes_to_the_audit_lane() {
    let mut facts = allowed();
    facts.verdict.trace.wildcard = true;

    assert_eq!(built(facts).lane, AccessLane::Audit);
}

#[test]
fn an_ordinary_allow_goes_to_the_ordinary_lane_in_the_allow_class() {
    let item = built(allowed());

    assert_eq!(item.lane, AccessLane::Access);
    assert_eq!(item.class, AccessClass::Allow);
}

#[test]
fn an_undecidable_request_is_an_error_of_the_ordinary_lane_that_is_never_sampled() {
    let item = builder(SampleRate::NONE, 0).build(unavailable()).unwrap();

    assert_eq!(item.lane, AccessLane::Access);
    assert_eq!(item.class, AccessClass::Error);
    assert_eq!(item.record.decision, AccessDecision::Error);
}

#[test]
fn an_allow_that_the_upstream_failed_is_an_error() {
    let mut facts = allowed();
    facts.response.status = 502;

    let item = builder(SampleRate::NONE, 0).build(facts).unwrap();

    assert_eq!(item.class, AccessClass::Error);
    assert_eq!(item.record.decision, AccessDecision::Error);
}

#[test]
fn an_error_on_a_sensitive_key_is_written_to_the_audit_lane() {
    let mut facts = with_flags(PermissionFlags::NONE.with_sensitive());
    facts.response.status = 504;

    let item = built(facts);

    assert_eq!(item.lane, AccessLane::Audit);
    assert_eq!(item.class, AccessClass::Audit);
    assert_eq!(item.record.decision, AccessDecision::Error);
}

#[test]
fn a_wildcard_flag_on_a_denial_changes_nothing() {
    let mut facts = denied(DecisionReason::PermissionMissing, 403);
    facts.verdict.trace.wildcard = true;

    assert_eq!(built(facts).lane, AccessLane::Audit);
}

#[test]
fn the_audit_lane_is_never_sampled() {
    let facts = denied(DecisionReason::PermissionMissing, 403);

    assert!(builder(SampleRate::NONE, 0).build(facts).is_some());
}

#[test]
fn an_ordinary_allow_is_written_when_its_draw_falls_into_the_sample() {
    let rate = SampleRate::parse("0.01").unwrap();

    assert!(builder(rate, 9_999_999).build(allowed()).is_some());
    assert!(builder(rate, 10_000_000).build(allowed()).is_none());
    assert!(builder(SampleRate::NONE, 0).build(allowed()).is_none());
}

#[test]
fn the_sample_of_ordinary_allows_follows_the_rate() {
    let rate = SampleRate::parse("0.25").unwrap();
    let rng = test_support::rng::FakeRng::seeded(11);
    let builder = AccessRecordBuilder::new(Arc::new(rng), rate);

    let written = (0..20_000)
        .filter(|_| builder.build(allowed()).is_some())
        .count();

    assert!((4_500..=5_500).contains(&written), "{written}");
}

#[test]
fn the_record_carries_the_facts_of_the_decision() {
    let item = built(allowed());
    let record = item.record;

    assert_eq!(record.decision_id, decision_id(1));
    assert_eq!(record.method, "GET");
    assert_eq!(record.host, "api.example.test");
    assert_eq!(record.route_id, Some(decision_id(100)));
    assert_eq!(record.route_template.as_deref(), Some("/api/orders/{id}"));
    assert_eq!(record.status, 200);
    assert_eq!(record.upstream.as_deref(), Some("orders"));
    assert_eq!(record.latency_us, 900);
    assert_eq!(record.bytes_out, 512);
    assert_eq!(record.request_id.as_deref(), Some("req-1"));
    assert_eq!(record.subject_id, Some(decision_id(7).to_string()));
    assert_eq!(record.subject_kind, Some(SubjectKind::User));
    assert_eq!(record.reason, DecisionReason::Allowed);
    assert_eq!(
        record.permission_key.as_deref(),
        Some("rest:orders:GET /api/orders/{}")
    );
    assert_eq!(record.policy_version, Some(42));
    assert_eq!(record.credential_digest_prefix.as_deref(), Some("0a1b2c3d"));
}

#[test]
fn a_denial_names_the_denied_keys_and_a_request_without_route_has_no_route_fields() {
    let mut facts = denied(DecisionReason::PermissionMissing, 403);
    facts.route = None;
    facts.verdict.subject = None;

    let record = built(facts).record;

    assert_eq!(record.denied, ["rest:orders:GET /api/orders/{}"]);
    assert!(record.route_id.is_none());
    assert!(record.route_template.is_none());
    assert!(record.upstream.is_none());
    assert!(record.subject_id.is_none());
    assert!(record.subject_kind.is_none());
    assert_eq!(record.decision, AccessDecision::Deny);
}

#[test]
fn a_deny_decision_is_a_deny_whatever_the_flags() {
    let mut facts = allowed();
    facts.verdict.decision = Decision::Deny;
    facts.verdict.reason = DecisionReason::ScopeMissing;

    assert_eq!(built(facts).record.decision, AccessDecision::Deny);
}

#[test]
fn every_decision_is_counted_by_reason_even_when_the_sample_leaves_it_out() {
    let (recorder, _guard) = LogRecorder::install();
    let builder = builder(SampleRate::NONE, 0);

    assert!(builder.build(allowed()).is_none());
    assert!(
        builder
            .build(denied(DecisionReason::TokenExpired, 401))
            .is_some()
    );

    let lines: Vec<_> = recorder
        .lines()
        .into_iter()
        .filter(|line| line.target == "metrics")
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].field("metric"), Some("gateway_decisions_total"));
    assert_eq!(lines[0].field("reason"), Some("allowed"));
    assert_eq!(lines[1].field("reason"), Some("token_expired"));
}
