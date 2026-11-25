//! The access record of the internal decision API (Story 14.1, FR-50).
//!
//! A check that a microservice makes of the decision API is a gateway decision as well, so it
//! produces one record, with the decision id that the response carries.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{AccessCheck, Credential, DecisionOutcome, RequestDigester};
use shared_domain::Clock;

use super::facts::{
    AccessFacts, DecisionTrace, RequestFacts, ResponseFacts, RouteFacts, VerdictFacts,
};
use super::recorder::AccessRecorder;

/// The host that stands for the decision listener in a record: the API has no host header of its
/// own that is worth logging.
pub const DECISION_API_HOST: &str = "decision-api";

/// The route template of a single check.
pub const VALIDATION_TEMPLATE: &str = "/api/access-validations";

/// The route template of one check of a batch.
pub const BATCH_VALIDATION_TEMPLATE: &str = "/api/access-validations/batch";

/// How many bytes of the digest make the 8 hexadecimal characters of the prefix.
const PREFIX_BYTES: usize = 4;

/// One check of the decision API, as the access log sees it.
#[derive(Debug, Clone, Copy)]
pub struct DecisionCall<'call> {
    /// The route template: [`VALIDATION_TEMPLATE`] or [`BATCH_VALIDATION_TEMPLATE`].
    pub template: &'static str,
    /// The credential that was checked.
    pub credential: &'call Credential,
    /// What the check named, for the project it concerns.
    pub check: Option<&'call AccessCheck>,
    /// The decision body.
    pub outcome: &'call DecisionOutcome,
    /// What the decision knows about the key it was made on.
    pub trace: &'call DecisionTrace,
    /// How long the decision took.
    pub latency: Duration,
}

/// Records the checks of the decision API.
#[derive(Debug)]
pub struct DecisionAccessLog {
    recorder: Arc<AccessRecorder>,
    clock: Arc<dyn Clock>,
    digester: Arc<dyn RequestDigester>,
}

impl DecisionAccessLog {
    /// A log over `recorder`; records are stamped with `clock` and the credential digest prefix is
    /// taken with `digester`.
    #[must_use]
    pub fn new(
        recorder: Arc<AccessRecorder>,
        clock: Arc<dyn Clock>,
        digester: Arc<dyn RequestDigester>,
    ) -> Self {
        Self {
            recorder,
            clock,
            digester,
        }
    }

    /// Records one check. The call never waits and never fails.
    pub fn record(&self, call: &DecisionCall<'_>) {
        let outcome = call.outcome;
        self.recorder.record(AccessFacts {
            decision_id: outcome.decision_id().as_uuid(),
            occurred_at: self.clock.now(),
            request: RequestFacts {
                method: "POST".to_owned(),
                host: DECISION_API_HOST.to_owned(),
                request_id: None,
                bytes_in: 0,
                credential_digest_prefix: self.digest_prefix(call.credential),
            },
            route: Some(RouteFacts {
                id: None,
                template: call.template.to_owned(),
                upstream: None,
            }),
            verdict: VerdictFacts {
                decision: outcome.decision(),
                reason: outcome.reason(),
                subject: outcome.subject().map(|subject| subject.id().clone()),
                policy_version: outcome
                    .policy_version()
                    .map(iam_domain::PolicyVersion::value),
                trace: call.trace.clone(),
                denied: outcome.denied().to_vec(),
                project_id: call
                    .check
                    .and_then(AccessCheck::project)
                    .map(|project| project.as_uuid()),
            },
            response: ResponseFacts {
                status: 200,
                bytes_out: 0,
                latency_us: u64::try_from(call.latency.as_micros()).unwrap_or(u64::MAX),
            },
        });
    }

    /// The first 8 hexadecimal characters of the digest of the credential; none for a blank one.
    fn digest_prefix(&self, credential: &Credential) -> Option<String> {
        if credential.is_blank() {
            return None;
        }
        let digest = self.digester.digest(credential.expose());
        Some(
            digest
                .as_bytes()
                .iter()
                .take(PREFIX_BYTES)
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests;
