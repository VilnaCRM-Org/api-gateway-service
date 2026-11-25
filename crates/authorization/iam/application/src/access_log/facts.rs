//! What an access record is built from: the facts of the request, the route, the verdict and the
//! response, as the composition root collects them.

use std::time::SystemTime;

use iam_domain::{Decision, DecisionReason, PermissionFlags, RequiredKey, SubjectId};
use shared_domain::Uuid;

/// What a decision knows about the key it was made on, beyond the verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionTrace {
    /// The permission key the operation required.
    pub permission_key: Option<String>,
    /// The most restrictive catalogue flags of the required keys.
    pub flags: PermissionFlags,
    /// Whether an allow rests on a wildcard grant.
    pub wildcard: bool,
}

impl DecisionTrace {
    /// The trace of a decision that required `required`: the first key and the flags of all.
    #[must_use]
    pub fn of_required(required: &[RequiredKey]) -> Self {
        let flags = required
            .iter()
            .fold(PermissionFlags::NONE, |flags, required| {
                let held = required.flags();
                let flags = if held.is_sensitive() {
                    flags.with_sensitive()
                } else {
                    flags
                };
                if held.is_audit_always() {
                    flags.with_audit_always()
                } else {
                    flags
                }
            });
        Self {
            permission_key: required.first().map(|required| required.key().to_string()),
            flags,
            wildcard: false,
        }
    }

    /// The same trace, noting whether an allow rests on a wildcard grant.
    #[must_use]
    pub fn with_wildcard(self, wildcard: bool) -> Self {
        Self { wildcard, ..self }
    }
}

/// The request as it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFacts {
    /// The HTTP method.
    pub method: String,
    /// The host, in lower case and without a port.
    pub host: String,
    /// The request id.
    pub request_id: Option<String>,
    /// The announced bytes of the request body.
    pub bytes_in: u64,
    /// The first 8 hexadecimal characters of the SHA-256 digest of the credential.
    pub credential_digest_prefix: Option<String>,
}

/// The route the request matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteFacts {
    /// The identifier of the route; absent for a decision of the internal decision API, which has
    /// no route.
    pub id: Option<Uuid>,
    /// The path template of the route; never the concrete path.
    pub template: String,
    /// The registered name of the upstream.
    pub upstream: Option<String>,
}

/// What was decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictFacts {
    /// Allow or deny.
    pub decision: Decision,
    /// The reason code.
    pub reason: DecisionReason,
    /// The subject that the token proved.
    pub subject: Option<SubjectId>,
    /// The version of the snapshot that decided.
    pub policy_version: Option<i64>,
    /// What the decision knows about its key.
    pub trace: DecisionTrace,
    /// The denied keys.
    pub denied: Vec<String>,
    /// The project of the request.
    pub project_id: Option<Uuid>,
}

/// The answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseFacts {
    /// The status.
    pub status: u16,
    /// The announced bytes of the response body.
    pub bytes_out: u64,
    /// Microseconds from the receipt of the request to the end of the response.
    pub latency_us: u64,
}

/// Everything one access record needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessFacts {
    /// The id of the decision, from the `UuidGenerator` port.
    pub decision_id: Uuid,
    /// When the decision was made, from the `Clock` port.
    pub occurred_at: SystemTime,
    /// The request.
    pub request: RequestFacts,
    /// The matched route, when there is one.
    pub route: Option<RouteFacts>,
    /// The decision.
    pub verdict: VerdictFacts,
    /// The answer.
    pub response: ResponseFacts,
}

#[cfg(test)]
mod tests;
