//! Builds the access record of a decision and routes it to its lane (FR-50).

use std::sync::Arc;

use iam_domain::{
    AccessClass, AccessDecision, AccessLane, AccessRecord, Rng, SampleRate, SubjectId,
};

use super::facts::{AccessFacts, RouteFacts};

/// A record on its way to the writer: the lane and the class it counts against, and the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessItem {
    /// The lane the record is written to.
    pub lane: AccessLane,
    /// The class whose budget the record counts against.
    pub class: AccessClass,
    /// The record.
    pub record: AccessRecord,
}

/// Builds the access record of a decision from its outcome and route data.
///
/// The lane rule: every denial, every decision on an always-audit or sensitive key and every
/// wildcard allow goes to the audit lane; everything else goes to the ordinary lane. An allow of
/// the ordinary lane is written only when the draw of the `Rng` port falls into the sample rate;
/// errors are always built, and the writer bounds them with the budget of their class.
#[derive(Debug)]
pub struct AccessRecordBuilder {
    rng: Arc<dyn Rng>,
    sample_rate: SampleRate,
}

impl AccessRecordBuilder {
    /// A builder that samples ordinary allows at `sample_rate` with draws of `rng`.
    #[must_use]
    pub fn new(rng: Arc<dyn Rng>, sample_rate: SampleRate) -> Self {
        Self { rng, sample_rate }
    }

    /// The item to write for `facts`, or `None` for an ordinary allow that the sample leaves out.
    ///
    /// Every call counts the decision in `gateway_decisions_total`, by reason, whatever the
    /// sample decides.
    #[must_use]
    pub fn build(&self, facts: AccessFacts) -> Option<AccessItem> {
        decision_counted(facts.verdict.reason.as_str());
        let kind = AccessDecision::of(
            facts.verdict.decision,
            facts.verdict.reason,
            facts.response.status,
        );
        let lane = lane_of(&facts, kind);
        let class = class_of(lane, kind);
        if class == AccessClass::Allow && !self.sampled() {
            return None;
        }
        Some(AccessItem {
            lane,
            class,
            record: record_of(facts, kind),
        })
    }

    /// One draw of the `Rng` port against the sample rate.
    fn sampled(&self) -> bool {
        self.sample_rate.admits(self.rng.next_u64())
    }
}

/// The metric event `gateway_decisions_total`, by reason.
fn decision_counted(reason: &str) {
    tracing::info!(
        target: "metrics",
        metric = "gateway_decisions_total",
        reason,
        value = 1_u64,
    );
}

/// The lane of a decision: the audit lane for a denial, for a key that is always audited or
/// sensitive and for a wildcard allow.
fn lane_of(facts: &AccessFacts, kind: AccessDecision) -> AccessLane {
    let trace = &facts.verdict.trace;
    let wildcard_allow = trace.wildcard && facts.verdict.decision.is_allow();
    if kind == AccessDecision::Deny
        || trace.flags.is_audit_always()
        || trace.flags.is_sensitive()
        || wildcard_allow
    {
        AccessLane::Audit
    } else {
        AccessLane::Access
    }
}

/// The class a record counts against.
const fn class_of(lane: AccessLane, kind: AccessDecision) -> AccessClass {
    match (lane, kind) {
        (AccessLane::Audit, _) => AccessClass::Audit,
        (AccessLane::Access, AccessDecision::Error) => AccessClass::Error,
        (AccessLane::Access, AccessDecision::Allow | AccessDecision::Deny) => AccessClass::Allow,
    }
}

/// The record of `facts` for tests that need an item without a lane decision.
#[cfg(test)]
pub(super) fn record_for_tests(facts: AccessFacts) -> AccessRecord {
    let kind = AccessDecision::of(
        facts.verdict.decision,
        facts.verdict.reason,
        facts.response.status,
    );
    record_of(facts, kind)
}

fn record_of(facts: AccessFacts, kind: AccessDecision) -> AccessRecord {
    let AccessFacts {
        decision_id,
        occurred_at,
        request,
        route,
        verdict,
        response,
    } = facts;
    let (route_id, route_template, upstream) = route.map_or((None, None, None), split_route);
    AccessRecord {
        decision_id,
        occurred_at,
        method: request.method,
        host: request.host,
        route_id,
        route_template,
        status: response.status,
        upstream,
        latency_us: response.latency_us,
        bytes_in: request.bytes_in,
        bytes_out: response.bytes_out,
        request_id: request.request_id,
        subject_id: verdict.subject.as_ref().map(ToString::to_string),
        subject_kind: verdict.subject.as_ref().map(SubjectId::kind),
        decision: kind,
        reason: verdict.reason,
        permission_key: verdict.trace.permission_key,
        denied: verdict.denied,
        project_id: verdict.project_id,
        policy_version: verdict.policy_version,
        credential_digest_prefix: request.credential_digest_prefix,
    }
}

type RouteParts = (Option<shared_domain::Uuid>, Option<String>, Option<String>);

fn split_route(route: RouteFacts) -> RouteParts {
    (route.id, Some(route.template), route.upstream)
}

#[cfg(test)]
mod tests;
