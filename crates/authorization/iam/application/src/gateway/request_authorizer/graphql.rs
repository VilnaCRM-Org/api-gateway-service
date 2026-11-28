//! The coordinate authorization of a GraphQL request (Story 10.8, FR-8, FR-60).
//!
//! The documents of the request are analysed into the coordinates they select; the principal must
//! hold every one of them, or none of the request is let through. A denial carries only a reason
//! code, never a coordinate, so it tells nothing about the schema of another service.

use std::sync::Arc;

use iam_domain::{
    AnalyzedDocument, DecisionReason, GqlCoordinate, PermissionFlags, PermissionKey,
    PolicyReadRepository as _, RepositoryError, RequiredKey, ServiceCatalog, ServiceName,
};

use super::{Authorization, RequestAuthorizer, RouteRequest, TracedAuthorization, subject_of};
use crate::error::IamError;
use crate::gateway::graphql_request::{Analysis, GraphQlOperation};
use crate::gateway::snapshot_reads::LoadedSnapshotReads;
use crate::iam_access_guard::{GraphQlOperationRequest, IamAccessGuard};
use crate::principal::Principal;

/// The types whose fields are the root fields of an operation.
const ROOT_TYPES: [&str; 3] = ["Query", "Mutation", "Subscription"];

/// What authorizing a GraphQL request found.
#[derive(Debug, PartialEq, Eq)]
pub enum GraphQlAuthorization {
    /// The request was decided.
    Decided(TracedAuthorization),
    /// The subject has used its parse budget: the answer is 429.
    RateLimited,
}

/// Decides the `operations` of a GraphQL request before the enforcement mode applies; `None` when
/// the subject is over its parse budget.
pub(super) async fn decided(
    authorizer: &RequestAuthorizer,
    request: &RouteRequest<'_>,
    principal: &Principal,
    operations: &[GraphQlOperation],
) -> Option<TracedAuthorization> {
    decided_keyed(authorizer, request, principal, operations)
        .await
        .map(|(traced, _keys)| traced)
}

/// Decides like [`decided`] and also names the permission keys the documents required, which an
/// open subscription operation is registered with (Story 11.3); empty when no key was read.
pub(super) async fn decided_keyed(
    authorizer: &RequestAuthorizer,
    request: &RouteRequest<'_>,
    principal: &Principal,
    operations: &[GraphQlOperation],
) -> Option<(TracedAuthorization, Vec<String>)> {
    let Some(analyzer) = authorizer.graphql.get() else {
        return Some((Authorization::Unavailable.into(), Vec::new()));
    };
    let reads =
        LoadedSnapshotReads::new(Arc::clone(request.snapshot), Arc::clone(&authorizer.cache));
    let read = reads.read_service_catalog(request.service).await;
    let Ok(Some(catalog)) = read else {
        return Some((missing_catalog(&read).into(), Vec::new()));
    };
    let subject = principal.subject().to_string();
    match analyzer.analyze(&catalog, &subject, operations).await {
        Analysis::Analyzed(document) => {
            Some(authorized(authorizer, request, principal, &document).await)
        }
        Analysis::Refused(reason) => Some((Authorization::Denied(reason).into(), Vec::new())),
        Analysis::Unavailable => Some((Authorization::Unavailable.into(), Vec::new())),
        Analysis::RateLimited => None,
    }
}

/// Why no catalogue was read: the service has none, or the policy cannot be read at all.
fn missing_catalog(read: &Result<Option<ServiceCatalog>, RepositoryError>) -> Authorization {
    read.as_ref().map_or(Authorization::Unavailable, |_absent| {
        Authorization::Denied(DecisionReason::UnknownService)
    })
}

/// The decision over the coordinates of the analysed documents, and the keys it was made on.
async fn authorized(
    authorizer: &RequestAuthorizer,
    request: &RouteRequest<'_>,
    principal: &Principal,
    document: &AnalyzedDocument,
) -> (TracedAuthorization, Vec<String>) {
    let decisions = authorizer.decisions(request.snapshot);
    let version = request.snapshot.version();
    if request.service.is_iam() {
        let guard = IamAccessGuard::new(decisions, Arc::clone(&authorizer.commands));
        let traced: TracedAuthorization = iam_graphql(&guard, request, principal, document)
            .await
            .map_or_else(
                || Authorization::Denied(DecisionReason::PermissionMissing),
                |answer| RequestAuthorizer::guarded(answer, version),
            )
            .into();
        return (traced, root_coordinates(document));
    }
    let required = required_keys(request.service, document);
    let keys = required
        .iter()
        .map(|required| required.key().to_string())
        .collect();
    let (outcome, trace) = decisions
        .decide_required_traced(subject_of(principal), &required)
        .await;
    let traced = authorizer.audited(TracedAuthorization {
        authorization: RequestAuthorizer::authorization_of(&outcome, version),
        trace,
        denied: outcome.denied().to_vec(),
        audit_slot: None,
    });
    (traced, keys)
}

/// IAM's own GraphQL route: the rule table of [`IamAccessGuard`] decides the root fields, as it
/// does for the REST operations. An introspection query has no row and a document without a root
/// field has nothing to decide on, so both get `None`, which is a denial.
async fn iam_graphql(
    guard: &IamAccessGuard,
    request: &RouteRequest<'_>,
    principal: &Principal,
    document: &AnalyzedDocument,
) -> Option<Result<(), IamError>> {
    let coordinates = root_coordinates(document);
    if document.introspection() || coordinates.is_empty() {
        return None;
    }
    let selected = GraphQlOperationRequest {
        coordinates: &coordinates,
        services: &[],
        request_id: request.request_id,
    };
    Some(guard.authorize_graphql(principal, &selected).await)
}

/// The `{Type}.{field}` texts of the root fields that the documents select.
fn root_coordinates(document: &AnalyzedDocument) -> Vec<String> {
    document
        .coordinates()
        .iter()
        .filter(|(coordinate, _flags)| ROOT_TYPES.contains(&coordinate.type_name().as_str()))
        .map(|(coordinate, _flags)| coordinate.to_string())
        .collect()
}

/// The keys that the coordinates of the documents require, with the flags of the type graph, and
/// the introspection key when a document is an introspection query.
fn required_keys(service: &ServiceName, document: &AnalyzedDocument) -> Vec<RequiredKey> {
    let mut required: Vec<RequiredKey> = document
        .coordinates()
        .iter()
        .map(|(coordinate, flags)| RequiredKey::new(coordinate.permission_key(service), flags))
        .collect();
    if document.introspection() {
        let key = PermissionKey::Gql {
            service: service.clone(),
            coordinate: GqlCoordinate::Introspection,
        };
        required.push(RequiredKey::new(key, PermissionFlags::NONE));
    }
    required
}

#[cfg(test)]
mod tests;
