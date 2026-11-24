//! Authorization of the callers of IAM's own REST operations (FR-4).
//!
//! [`require_operation`] runs inside [`require_principal`](super::authentication::require_principal):
//! it takes the [`Principal`] that the authentication left in the request extensions and asks the
//! [`IamAccessGuard`] whether it may call the operation that the router matched. A refusal is the
//! 403 problem; the guard has already offered it to the audit log without waiting for the write.

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use iam_application::{IamAccessGuard, IamError, OperationRequest, Principal};
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

    fn request(&self) -> OperationRequest<'_> {
        OperationRequest {
            method: &self.method,
            template: &self.template,
            path: &self.path,
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
    match guard.authorize(&principal, &operation.request()).await {
        Ok(()) => next.run(request).await,
        Err(error) => Problem::from(error).into_response(),
    }
}

#[cfg(test)]
mod tests;
