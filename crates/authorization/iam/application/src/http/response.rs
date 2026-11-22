//! The response headers of the IAM writes: `ETag`, `Location` and `Iam-Policy-Version` (FR-2).

use axum::http::HeaderName;
use axum::http::header::{ETAG, LOCATION};
use axum::response::AppendHeaders;
use iam_domain::{ChangeReceipt, EntityVersion};

/// The response header that carries the policy version a change produced.
pub const IAM_POLICY_VERSION: HeaderName = HeaderName::from_static("iam-policy-version");

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
    AppendHeaders(headers)
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
