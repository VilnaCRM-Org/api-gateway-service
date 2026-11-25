//! Facts and items for the tests of the access log.

use std::time::{Duration, SystemTime};

use iam_domain::{AccessClass, AccessLane, Decision, DecisionReason, PermissionFlags, SubjectId};
use shared_domain::Uuid;

use super::builder::AccessItem;
use super::facts::{
    AccessFacts, DecisionTrace, RequestFacts, ResponseFacts, RouteFacts, VerdictFacts,
};

/// A time a number of seconds after the epoch.
pub(crate) fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// A decision id with a counter.
pub(crate) fn decision_id(counter: u32) -> Uuid {
    Uuid::parse(&format!("00000000-0000-7000-8000-{counter:012x}")).unwrap()
}

/// The facts of an allowed `GET` that matched a route and was answered 200.
pub(crate) fn allowed() -> AccessFacts {
    AccessFacts {
        decision_id: decision_id(1),
        occurred_at: at(1_800_000_000),
        request: RequestFacts {
            method: "GET".to_owned(),
            host: "api.example.test".to_owned(),
            request_id: Some("req-1".to_owned()),
            bytes_in: 0,
            credential_digest_prefix: Some("0a1b2c3d".to_owned()),
        },
        route: Some(RouteFacts {
            id: Some(decision_id(100)),
            template: "/api/orders/{id}".to_owned(),
            upstream: Some("orders".to_owned()),
        }),
        verdict: VerdictFacts {
            decision: Decision::Allow,
            reason: DecisionReason::Allowed,
            subject: Some(SubjectId::User(decision_id(7))),
            policy_version: Some(42),
            trace: DecisionTrace {
                permission_key: Some("rest:orders:GET /api/orders/{}".to_owned()),
                flags: PermissionFlags::NONE,
                wildcard: false,
            },
            denied: Vec::new(),
            project_id: None,
        },
        response: ResponseFacts {
            status: 200,
            bytes_out: 512,
            latency_us: 900,
        },
    }
}

/// The facts of a request that was refused with `reason` and answered `status`.
pub(crate) fn denied(reason: DecisionReason, status: u16) -> AccessFacts {
    let mut facts = allowed();
    facts.verdict.decision = Decision::Deny;
    facts.verdict.reason = reason;
    facts.verdict.denied = vec!["rest:orders:GET /api/orders/{}".to_owned()];
    facts.response.status = status;
    facts
}

/// The facts of a request that could not be decided and was answered 503.
pub(crate) fn unavailable() -> AccessFacts {
    let mut facts = denied(DecisionReason::Unavailable, 503);
    facts.verdict.subject = None;
    facts.verdict.policy_version = None;
    facts
}

/// An item of the ordinary lane with a decision id and a status.
pub(crate) fn error_item(counter: u32, route: u32, status: u16) -> AccessItem {
    let mut facts = unavailable();
    facts.decision_id = decision_id(counter);
    facts.response.status = status;
    facts.route.as_mut().unwrap().id = Some(decision_id(route));
    item(AccessLane::Access, AccessClass::Error, facts)
}

/// An item of `lane` and `class` over `facts`.
pub(crate) fn item(lane: AccessLane, class: AccessClass, facts: AccessFacts) -> AccessItem {
    AccessItem {
        lane,
        class,
        record: super::builder::record_for_tests(facts),
    }
}
