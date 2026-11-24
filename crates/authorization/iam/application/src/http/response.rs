//! The response headers and statuses of the IAM writes: `ETag`, `Location`, `Iam-Policy-Version`,
//! `Iam-Policy-Offset` and `Iam-Propagation-Status` (FR-2, FR-75).

use axum::http::header::{ETAG, LOCATION};
use axum::http::{HeaderName, StatusCode};
use axum::response::AppendHeaders;
use iam_domain::{ChangeReceipt, EntityVersion, PropagationOutcome};

/// The response header that carries the policy version a change produced.
pub const IAM_POLICY_VERSION: HeaderName = HeaderName::from_static("iam-policy-version");

/// The response header that carries the offset at which Kafka stored the `__head` record of the
/// policy version; only a write whose version was acknowledged has it.
pub const IAM_POLICY_OFFSET: HeaderName = HeaderName::from_static("iam-policy-offset");

/// The response header that names the propagation status of a write that was committed and not yet
/// acknowledged by Kafka, next to the status 202.
pub const IAM_PROPAGATION_STATUS: HeaderName = HeaderName::from_static("iam-propagation-status");

/// The headers of a write response, to return with its status and body.
pub type WriteHeaders = AppendHeaders<Vec<(HeaderName, String)>>;

/// The strong `ETag` of an entity version: the number in double quotes, such as `"4"`; the
/// `If-Match` header of a later update or delete returns it.
#[must_use]
pub fn etag(version: EntityVersion) -> String {
    format!("\"{}\"", version.value())
}

/// The headers of an update or a delete.
///
/// They are the `ETag` of the version the change produced and, when the change affected
/// decisions, its `Iam-Policy-Version`. A replay with the same
/// idempotency key returns the same headers, because both come from the stored receipt.
pub fn change_headers(receipt: &ChangeReceipt) -> WriteHeaders {
    let mut headers = vec![(ETAG, etag(receipt.entity_version()))];
    if let Some(version) = receipt.policy_version() {
        headers.push((IAM_POLICY_VERSION, version.value().to_string()));
    }
    match receipt.propagation() {
        Some(PropagationOutcome::Published { offset }) => {
            headers.push((IAM_POLICY_OFFSET, offset.to_string()));
        }
        Some(pending @ PropagationOutcome::CommittedPending) => {
            headers.push((IAM_PROPAGATION_STATUS, pending.status().to_owned()));
        }
        None => {}
    }
    AppendHeaders(headers)
}

/// The status of a write response.
///
/// It is `success` when the write needs no further wait or its version reached Kafka, and
/// `202 Accepted` when the change is committed and its version was not acknowledged within
/// `PUBLISH_WAIT_TIMEOUT`.
#[must_use]
pub const fn write_status(receipt: &ChangeReceipt, success: StatusCode) -> StatusCode {
    match receipt.propagation() {
        Some(PropagationOutcome::CommittedPending) => StatusCode::ACCEPTED,
        Some(PropagationOutcome::Published { .. }) | None => success,
    }
}

/// The headers of a create.
///
/// They are [`change_headers`] and the `Location` of the created record: the target id of the
/// receipt under `collection` (such as `/api/roles`).
pub fn created_headers(receipt: &ChangeReceipt, collection: &str) -> WriteHeaders {
    let AppendHeaders(mut headers) = change_headers(receipt);
    let location = format!("{collection}/{}", receipt.target().target_id());
    headers.push((LOCATION, location));
    AppendHeaders(headers)
}

#[cfg(test)]
mod tests;
