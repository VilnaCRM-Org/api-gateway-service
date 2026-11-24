//! The authorization of IAM's own GraphQL fields (FR-1, FR-4): the same rule as the REST operations.
//!
//! [`IamAuthorizationExtension`] is an `async-graphql` extension. Before a request executes it
//! reads the operation the document selects and collects the root fields that IAM owns (the rows
//! of [`OperationRules::graphql`]). A document that selects none is the template's and passes
//! untouched. A document that selects one needs a [`Principal`] (`UNAUTHENTICATED` without one) and
//! the keys of the row of every IAM root field (`FORBIDDEN` for a caller that lacks one, with the
//! refusal offered to the audit log by the [`IamAccessGuard`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_graphql::extensions::{
    Extension, ExtensionContext, ExtensionFactory, NextPrepareRequest,
};
use async_graphql::parser::parse_query;
use async_graphql::parser::types::{
    DocumentOperations, ExecutableDocument, OperationDefinition, OperationType, Selection,
    SelectionSet,
};
use async_graphql::{Request, ServerError, ServerResult};
use async_trait::async_trait;

use crate::error::IamError;
use crate::graphql::iam_problem_to_graphql_error;
use crate::iam_access_guard::{GraphQlOperationRequest, IamAccessGuard};
use crate::operation_rules::OperationRules;
use crate::principal::Principal;
use shared_application::http::Problem;

/// Authorizes the callers of the GraphQL fields that IAM owns.
#[derive(Debug, Clone)]
pub struct IamAuthorizationExtension {
    guard: Arc<IamAccessGuard>,
}

impl IamAuthorizationExtension {
    /// An extension that decides with `guard`.
    #[must_use]
    pub const fn new(guard: Arc<IamAccessGuard>) -> Self {
        Self { guard }
    }
}

impl ExtensionFactory for IamAuthorizationExtension {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(Authorizer {
            guard: Arc::clone(&self.guard),
        })
    }
}

/// The extension of one request.
struct Authorizer {
    guard: Arc<IamAccessGuard>,
}

#[async_trait]
impl Extension for Authorizer {
    async fn prepare_request(
        &self,
        ctx: &ExtensionContext<'_>,
        request: Request,
        next: NextPrepareRequest<'_>,
    ) -> ServerResult<Request> {
        self.prepare(ctx, request, next).await
    }
}

impl Authorizer {
    async fn prepare(
        &self,
        ctx: &ExtensionContext<'_>,
        request: Request,
        next: NextPrepareRequest<'_>,
    ) -> ServerResult<Request> {
        self.authorize(&request).await.map_err(refusal)?;
        next.run(ctx, request).await
    }

    /// Lets the request through unless it selects IAM fields its caller may not use.
    async fn authorize(&self, request: &Request) -> Result<(), IamError> {
        let coordinates = owned_coordinates(request);
        if coordinates.is_empty() {
            return Ok(());
        }
        let principal = caller(request).ok_or(IamError::Unauthenticated)?;
        let selected = GraphQlOperationRequest {
            coordinates: &coordinates,
            request_id: None,
        };
        self.guard.authorize_graphql(principal, &selected).await
    }
}

/// The GraphQL error of a refusal, as the resolvers give it.
fn refusal(error: IamError) -> ServerError {
    let error = iam_problem_to_graphql_error(Problem::from(error));
    ServerError {
        message: error.message,
        source: None,
        locations: Vec::new(),
        path: Vec::new(),
        extensions: error.extensions,
    }
}

/// The caller that the transport put into the request data: `Some` for a valid bearer token.
fn caller(request: &Request) -> Option<&Principal> {
    request
        .data
        .get(&std::any::TypeId::of::<Option<Principal>>())
        .and_then(|data| data.downcast_ref::<Option<Principal>>())
        .and_then(Option::as_ref)
}

/// The coordinates of the IAM root fields that the request's operations select, in order and
/// without repeats. A document that does not parse selects none: execution refuses it.
fn owned_coordinates(request: &Request) -> Vec<String> {
    let Ok(document) = parse_query(&request.query) else {
        return Vec::new();
    };
    let mut coordinates = BTreeSet::new();
    for operation in operations(&document, request.operation_name.as_deref()) {
        collect_operation(&document, operation, &mut coordinates);
    }
    coordinates.into_iter().collect()
}

/// The operations a request may run: the only one of a document, the named one, or every one when
/// the name selects none, so that a request that execution will refuse is still checked.
fn operations<'doc>(
    document: &'doc ExecutableDocument,
    name: Option<&str>,
) -> Vec<&'doc OperationDefinition> {
    match &document.operations {
        DocumentOperations::Single(operation) => vec![&operation.node],
        DocumentOperations::Multiple(all) => {
            let named = name.and_then(|name| all.get(name));
            named.map_or_else(
                || all.values().map(|operation| &operation.node).collect(),
                |operation| vec![&operation.node],
            )
        }
    }
}

/// Adds the IAM coordinates of the root fields of `operation`.
fn collect_operation(
    document: &ExecutableDocument,
    operation: &OperationDefinition,
    coordinates: &mut BTreeSet<String>,
) {
    let root = match operation.ty {
        OperationType::Query => "Query",
        OperationType::Mutation => "Mutation",
        OperationType::Subscription => return,
    };
    let mut visited = BTreeSet::new();
    collect_selection(
        document,
        root,
        &operation.selection_set.node,
        &mut visited,
        coordinates,
    );
}

/// Walks a selection set of a root type through inline fragments and fragment spreads; a fragment
/// is entered once, so a cycle ends.
fn collect_selection(
    document: &ExecutableDocument,
    root: &str,
    selection_set: &SelectionSet,
    visited: &mut BTreeSet<String>,
    coordinates: &mut BTreeSet<String>,
) {
    for selection in &selection_set.items {
        match &selection.node {
            Selection::Field(field) => {
                let coordinate = format!("{root}.{}", field.node.name.node);
                if OperationRules::find_graphql(&coordinate).is_some() {
                    coordinates.insert(coordinate);
                }
            }
            Selection::InlineFragment(fragment) => {
                collect_selection(
                    document,
                    root,
                    &fragment.node.selection_set.node,
                    visited,
                    coordinates,
                );
            }
            Selection::FragmentSpread(spread) => {
                let name = spread.node.fragment_name.node.as_str();
                if let Some(fragment) = document.fragments.get(name)
                    && visited.insert(name.to_owned())
                {
                    collect_selection(
                        document,
                        root,
                        &fragment.node.selection_set.node,
                        visited,
                        coordinates,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
