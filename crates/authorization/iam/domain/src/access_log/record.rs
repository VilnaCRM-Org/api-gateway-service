//! The access record of one gateway decision (FR-50, architecture section 12.1).

use std::time::SystemTime;

use shared_domain::Uuid;

use super::kinds::AccessDecision;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::subject::SubjectKind;

/// One gateway decision as it is logged.
///
/// The record holds identifiers and low-cardinality names only: the route template and never the
/// concrete path, a digest prefix and never the credential, and no cookie, no header and no
/// GraphQL document (NFR-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRecord {
    /// The id of the decision, a UUID v7.
    pub decision_id: Uuid,
    /// When the decision was made, from the `Clock` port.
    pub occurred_at: SystemTime,
    /// The HTTP method of the request.
    pub method: String,
    /// The host of the request, in lower case and without a port.
    pub host: String,
    /// The matched route, when there is one.
    pub route_id: Option<Uuid>,
    /// The path template of the matched route.
    pub route_template: Option<String>,
    /// The status of the answer.
    pub status: u16,
    /// The registered name of the upstream, when the request had one.
    pub upstream: Option<String>,
    /// Microseconds from the receipt of the request to the end of the response.
    pub latency_us: u64,
    /// The bytes of the request body that were announced.
    pub bytes_in: u64,
    /// The bytes of the response body that were announced.
    pub bytes_out: u64,
    /// The request id of the request.
    pub request_id: Option<String>,
    /// The subject that the token proved; absent without a valid token.
    pub subject_id: Option<String>,
    /// The kind of the subject.
    pub subject_kind: Option<SubjectKind>,
    /// The kind of the decision.
    pub decision: AccessDecision,
    /// The reason code of the decision.
    pub reason: DecisionReason,
    /// The permission key the operation required, for a decision that was made on one.
    pub permission_key: Option<String>,
    /// The keys that were denied, for a denial.
    pub denied: Vec<String>,
    /// The project of the request, when it names one.
    pub project_id: Option<Uuid>,
    /// The version of the policy snapshot that decided.
    pub policy_version: Option<i64>,
    /// The first 8 hexadecimal characters of the SHA-256 digest of the credential.
    pub credential_digest_prefix: Option<String>,
}
