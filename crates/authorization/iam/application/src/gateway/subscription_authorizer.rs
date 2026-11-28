//! The authorization of a GraphQL operation sent over a WebSocket (Story 11.3, FR-62).
//!
//! A socket on a route flagged `graphql` and `streaming` carries many operations after one
//! authentication, so the [`SubscriptionAuthorizer`] owns three decisions of the connection:
//!
//! - the token rule of `connection_init`: the token of the upgrade request wins; only when the
//!   request carries none is the `authorization` member of the `connection_init` payload read;
//! - the route decision on the authenticated principal, taken once per connection before any
//!   upstream socket exists;
//! - the decision of every `subscribe` or `start` message, and of every query or mutation sent
//!   over the socket, with the analyzer and the limits of Story 10.8. The root fields of a
//!   `Subscription` operation are coordinates like any other, and the decision is all or nothing:
//!   one coordinate the principal does not hold denies the whole operation.
//!
//! An allowed operation also names the permission keys it rests on, which the registry keeps with
//! the operation so that it can be decided again.

use std::sync::Arc;

use iam_domain::{Credential, DecisionReason, PolicyVersion};

use super::graphql_request::GraphQlOperation;
use super::request_authorizer::{
    Authorization, RequestAuthorizer, RouteRequest, TracedAuthorization,
};
use crate::principal::Principal;

/// The authentication scheme the `authorization` member of the payload may carry.
const BEARER: &str = "Bearer";

/// What deciding one operation of a socket found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationVerdict {
    /// The principal holds every key of the operation.
    Allowed {
        /// The version of the snapshot the decision was made on.
        version: PolicyVersion,
        /// The permission keys the operation required, one per coordinate it selects.
        keys: Vec<String>,
    },
    /// The principal may not run it; the reason code never names a coordinate.
    Forbidden(DecisionReason),
    /// The subject is over its parse budget.
    RateLimited,
    /// The decision could not be made on the policy that was read: the operation fails closed.
    Unavailable,
}

/// Decides the operations of the sockets of GraphQL subscriptions.
#[derive(Debug, Clone)]
pub struct SubscriptionAuthorizer {
    authorizer: Arc<RequestAuthorizer>,
}

impl SubscriptionAuthorizer {
    /// A subscription authorizer over the request authorizer of the pipeline, so that a socket is
    /// decided on the same policy, analyzer and limits as a GraphQL request.
    #[must_use]
    pub const fn new(authorizer: Arc<RequestAuthorizer>) -> Self {
        Self { authorizer }
    }

    /// The credential of a connection: `upgrade`, the one of the upgrade request, when it holds a
    /// token, and otherwise the `authorization` member of the `connection_init` payload, with or
    /// without the `Bearer` scheme. A credential that is blank is a missing token.
    #[must_use]
    pub fn connection_credential(
        upgrade: Credential,
        init_authorization: Option<&str>,
    ) -> Credential {
        if !upgrade.is_blank() {
            return upgrade;
        }
        let token = init_authorization.map_or("", bare_token);
        Credential::new(token.to_owned())
    }

    /// Decides whether `principal` may open a socket on the route of `request`, with the key the
    /// decision was made on.
    pub async fn authorize_route(
        &self,
        request: &RouteRequest<'_>,
        principal: &Principal,
    ) -> TracedAuthorization {
        self.authorizer.authorize_traced(request, principal).await
    }

    /// Decides whether `principal` may run `operation`: it needs the key of every coordinate the
    /// document selects, or none of the operation runs.
    pub async fn authorize_operation(
        &self,
        request: &RouteRequest<'_>,
        principal: &Principal,
        operation: &GraphQlOperation,
    ) -> OperationVerdict {
        let decided = self
            .authorizer
            .authorize_graphql_keyed(request, principal, std::slice::from_ref(operation))
            .await;
        let Some((traced, keys)) = decided else {
            return OperationVerdict::RateLimited;
        };
        match traced.authorization {
            Authorization::Allowed(version) => OperationVerdict::Allowed { version, keys },
            Authorization::WouldDeny(_reason) => OperationVerdict::Allowed {
                version: request.snapshot.version(),
                keys,
            },
            Authorization::Denied(reason) => OperationVerdict::Forbidden(reason),
            Authorization::Unavailable | Authorization::AuditUnavailable => {
                OperationVerdict::Unavailable
            }
        }
    }
}

/// The token of a payload value: the text after the `Bearer` scheme when it starts with one, and
/// the trimmed text otherwise.
fn bare_token(value: &str) -> &str {
    let value = value.trim();
    if value.eq_ignore_ascii_case(BEARER) {
        return "";
    }
    match value.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case(BEARER) => token.trim(),
        _ => value,
    }
}

#[cfg(test)]
mod tests;
