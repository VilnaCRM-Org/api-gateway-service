//! Authorization of the callers of IAM's own REST operations (FR-4).
//!
//! [`require_operation`] runs inside [`require_principal`](super::authentication::require_principal):
//! it takes the [`Principal`] that the authentication left in the request extensions and asks the
//! [`IamAccessGuard`] whether it may call the operation that the router matched. A refusal is the
//! 403 problem; the guard has already offered it to the audit log without waiting for the write.
//! The caller rule of the decision API (FR-12) depends on the target services that the body names,
//! so for those operations the middleware reads the body, hands the services to the guard and puts
//! the body back for the handler.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use iam_application::http::access_validation::ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES;
use iam_application::{
    CallerRule, IamAccessGuard, IamError, OperationRequest, OperationRules, Principal,
    target_services,
};
use shared_application::http::Problem;

use super::request_id::REQUEST_ID_HEADER;

/// What the guard needs to know about a request, copied out so that it holds no borrow of the
/// request while the guard decides.
struct Operation {
    method: String,
    template: String,
    path: String,
    request_id: Option<String>,
}

impl Operation {
    fn of(request: &Request) -> Self {
        Self {
            method: request.method().as_str().to_owned(),
            template: request
                .extensions()
                .get::<MatchedPath>()
                .map(|matched| matched.as_str().to_owned())
                .unwrap_or_default(),
            path: request.uri().path().to_owned(),
            request_id: request
                .headers()
                .get(&REQUEST_ID_HEADER)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        }
    }

    /// Whether the caller rule of the operation depends on the services its body names.
    fn names_services(&self) -> bool {
        OperationRules::find(&self.method, &self.template)
            .and_then(|rule| rule.requirement.caller_rule())
            .is_some_and(CallerRule::names_services)
    }

    fn request<'a>(&'a self, services: &'a [String]) -> OperationRequest<'a> {
        OperationRequest {
            method: &self.method,
            template: &self.template,
            path: &self.path,
            services,
            request_id: self.request_id.as_deref(),
        }
    }
}

/// Lets a request through only when its caller holds the keys of the operation.
///
/// A request without a [`Principal`] is refused with 401, so a route that is wired without the
/// authentication in front of it fails closed.
pub async fn require_operation(
    State(guard): State<Arc<IamAccessGuard>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(principal) = request.extensions().get::<Principal>().cloned() else {
        return Problem::from(IamError::Unauthenticated).into_response();
    };
    let operation = Operation::of(&request);
    let (request, services) = match named_services(request, &operation).await {
        Ok(read) => read,
        Err(response) => return *response,
    };
    match guard
        .authorize(&principal, &operation.request(&services))
        .await
    {
        Ok(()) => next.run(request).await,
        Err(error) => Problem::from(error).into_response(),
    }
}

/// The target services that the body of the request names, with the body put back; a request whose
/// operation does not depend on them is returned untouched. A body above the largest that the
/// decision API accepts is the 413 problem, as its handler would answer.
async fn named_services(
    request: Request,
    operation: &Operation,
) -> Result<(Request, Vec<String>), Box<Response>> {
    if !operation.names_services() {
        return Ok((request, Vec::new()));
    }
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, ACCESS_VALIDATION_BATCH_BODY_LIMIT_BYTES)
        .await
        .map_err(|_unreadable| {
            Box::new(Problem::new(StatusCode::PAYLOAD_TOO_LARGE).into_response())
        })?;
    let services = body_services(&bytes);
    Ok((Request::from_parts(parts, Body::from(bytes)), services))
}

/// The target services that the JSON body of a decision request names; a body that is not JSON
/// names none, and the handler refuses it.
fn body_services(body: &[u8]) -> Vec<String> {
    serde_json::from_slice::<async_graphql::Value>(body)
        .map(|value| target_services(&value))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
