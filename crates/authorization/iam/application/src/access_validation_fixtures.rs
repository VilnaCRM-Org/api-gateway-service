//! Values and doubles that the tests of the access-validation operation of the REST and GraphQL
//! adapters share.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    DecisionId, DecisionOutcome, DecisionReason, DecisionVerdict, PolicyVersion, ProjectId,
    ScopeSet, SubjectRef,
};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::http::IamState;
use crate::query::validate_access::ValidateAccessQuery;

/// The subject that every decision names.
pub(crate) const SUBJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
/// The identifier of every decision.
pub(crate) const DECISION: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
/// The project of a decision that holds in one project.
pub(crate) const PROJECT: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The decision `allow` for every project, of the subject, on policy version 7.
pub(crate) fn allowed() -> DecisionOutcome {
    outcome(DecisionVerdict::allow(ScopeSet::All))
}

/// The decision `allow` for one project.
pub(crate) fn allowed_in_project() -> DecisionOutcome {
    let project = ProjectId::parse(PROJECT).unwrap();
    outcome(DecisionVerdict::allow(ScopeSet::Projects(BTreeSet::from(
        [project],
    ))))
}

/// The decision `deny` for `reason` with the denied keys, of the subject, on policy version 7.
pub(crate) fn denied(reason: DecisionReason, keys: &[&str]) -> DecisionOutcome {
    outcome(DecisionVerdict::deny(
        reason,
        keys.iter().map(|&key| key.to_owned()).collect(),
    ))
}

fn outcome(verdict: DecisionVerdict) -> DecisionOutcome {
    DecisionOutcome::new(
        verdict,
        DecisionId::from_uuid(Uuid::parse(DECISION).unwrap()),
        Some(SubjectRef::user(Uuid::parse(SUBJECT).unwrap())),
        Some(PolicyVersion::new(7).unwrap()),
    )
}

/// The decision `deny` for a refused token: no subject and no policy version.
pub(crate) fn token_refused() -> DecisionOutcome {
    DecisionOutcome::new(
        DecisionVerdict::deny(DecisionReason::TokenExpired, Vec::new()),
        DecisionId::from_uuid(Uuid::parse(DECISION).unwrap()),
        None,
        None,
    )
}

/// The queries that the double was asked, in order.
pub(crate) type Asked = Arc<Mutex<Vec<ValidateAccessQuery>>>;

/// The queries a double recorded, in order.
pub(crate) fn recorded(log: &Asked) -> Vec<ValidateAccessQuery> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The state over a query bus that answers `answer` to every check and records what it was asked.
pub(crate) fn scenario(answer: Result<DecisionOutcome, Refusal>) -> (IamState, Asked) {
    let asked = Asked::default();
    let log = Arc::clone(&asked);
    let query_bus: Arc<dyn QueryBus> = Arc::new(FakeQueryBus::answering(
        move |query: ValidateAccessQuery| {
            log.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(query);
            answer.clone().map_err(|refusal| refusal())
        },
    ));
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, asked)
}
