use std::collections::BTreeSet;

use super::{DecisionOutcome, DecisionVerdict};
use crate::value_object::decision::Decision;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::identifier::{DecisionId, ProjectId};
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::scope_set::ScopeSet;
use crate::value_object::service_name::ServiceName;
use crate::value_object::subject::SubjectRef;

fn decision_id() -> DecisionId {
    DecisionId::parse("00000000-0000-7000-8000-000000000001").unwrap()
}

fn project() -> ProjectId {
    ProjectId::parse("00000000-0000-7000-8000-0000000000aa").unwrap()
}

#[test]
fn an_allow_carries_its_scopes_and_denies_nothing() {
    let scopes = ScopeSet::Projects(BTreeSet::from([project()]));
    let verdict = DecisionVerdict::allow(scopes.clone());

    assert_eq!(verdict.decision(), Decision::Allow);
    assert_eq!(verdict.reason(), DecisionReason::Allowed);
    assert_eq!(verdict.denied(), Vec::<String>::new());
    assert_eq!(verdict.scopes(), &scopes);
}

#[test]
fn a_deny_carries_its_reason_and_denied_keys_and_no_scope() {
    let denied = vec![String::from("rest:orders:GET /api/orders")];
    let verdict = DecisionVerdict::deny(DecisionReason::ScopeMissing, denied.clone());

    assert_eq!(verdict.decision(), Decision::Deny);
    assert_eq!(verdict.reason(), DecisionReason::ScopeMissing);
    assert_eq!(verdict.denied(), denied.as_slice());
    assert!(verdict.scopes().is_empty());
}

#[test]
fn a_deny_never_reports_allowed() {
    let verdict = DecisionVerdict::deny(DecisionReason::Allowed, Vec::new());

    assert_eq!(verdict.decision(), Decision::Deny);
    assert_eq!(verdict.reason(), DecisionReason::Unavailable);
}

#[test]
fn an_outcome_joins_the_verdict_with_the_response_facts() {
    let subject = SubjectRef::service(ServiceName::new("orders").unwrap());
    let version = PolicyVersion::new(7).unwrap();
    let verdict = DecisionVerdict::allow(ScopeSet::All);
    let outcome = DecisionOutcome::new(
        verdict.clone(),
        decision_id(),
        Some(subject.clone()),
        Some(version),
    );

    assert_eq!(outcome.decision(), Decision::Allow);
    assert_eq!(outcome.reason(), DecisionReason::Allowed);
    assert_eq!(outcome.denied(), Vec::<String>::new());
    assert_eq!(outcome.scopes(), &ScopeSet::All);
    assert_eq!(outcome.verdict(), &verdict);
    assert_eq!(outcome.decision_id(), decision_id());
    assert_eq!(outcome.subject(), Some(&subject));
    assert_eq!(outcome.policy_version(), Some(version));
}

#[test]
fn an_outcome_without_a_token_has_no_subject_or_version() {
    let outcome = DecisionOutcome::new(
        DecisionVerdict::deny(DecisionReason::TokenMissing, Vec::new()),
        decision_id(),
        None,
        None,
    );

    assert_eq!(outcome.decision(), Decision::Deny);
    assert_eq!(outcome.reason(), DecisionReason::TokenMissing);
    assert_eq!(outcome.subject(), None);
    assert_eq!(outcome.policy_version(), None);
}
