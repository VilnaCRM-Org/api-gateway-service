//! The merged GraphQL schema: one root per operation type, one field per bounded context.
#![expect(
    clippy::useless_let_if_seq,
    reason = "the MergedObject derive expands to code that triggers this lint"
)]

use async_graphql::{
    EmptySubscription, MergedObject, ObjectType, SDLExportOptions, Schema, SchemaBuilder,
};
use iam_application::graphql::{IamMutation, IamQuery};
use some_module_application::graphql::{ExampleApiResourceMutation, ExampleApiResourceQuery};

/// Query root.
#[derive(Debug, MergedObject, Default)]
pub struct Query(ExampleApiResourceQuery, IamQuery);

/// Mutation root.
#[derive(Debug, MergedObject, Default)]
pub struct Mutation(ExampleApiResourceMutation, IamMutation);

/// The schema type of the service: no subscription.
pub type ApiSchema = Schema<Query, Mutation, EmptySubscription>;

/// The deepest query the schema runs; the standard introspection query stays well below it.
pub const MAX_QUERY_DEPTH: usize = 20;

/// The largest static complexity of a query.
///
/// Every field costs 1, a page costs its page size times its item, and the large `sdl` and `diff`
/// fields cost more, so one request cannot read many multi-megabyte documents through a page or
/// through aliases.
pub const MAX_QUERY_COMPLEXITY: usize = 2_000;

/// A builder for the schema with the depth and complexity limits; the caller adds the state of
/// every context with `.data(..)`: the `SomeModuleState` and the `IamState`.
#[must_use]
pub fn builder() -> SchemaBuilder<Query, Mutation, EmptySubscription> {
    Schema::build(Query::default(), Mutation::default(), EmptySubscription)
        .limit_depth(MAX_QUERY_DEPTH)
        .limit_complexity(MAX_QUERY_COMPLEXITY)
}

/// The schema definition language of the schema, sorted so that it is byte-stable (AD-17).
#[must_use]
pub fn sdl() -> String {
    sorted_sdl(&builder().finish())
}

/// The IAM query root alone, under the name `Query` that the served schema gives it.
#[derive(Debug, MergedObject, Default)]
#[graphql(name = "Query")]
struct IamOwnQuery(IamQuery);

/// The IAM mutation root alone, under the name `Mutation` that the served schema gives it.
#[derive(Debug, MergedObject, Default)]
#[graphql(name = "Mutation")]
struct IamOwnMutation(IamMutation);

/// The SDL of the GraphQL operations that IAM owns, which IAM registers as its own specification
/// at startup (FR-4, FR-45).
///
/// Its roots are named `Query` and `Mutation` like those of the served schema, so the registered
/// coordinates are the `Query.x` and `Mutation.y` that a decision names. It is sorted so that it
/// is byte-stable: the same build always registers the same document, so its content hash finds
/// the version it registered before.
#[must_use]
pub fn iam_sdl() -> String {
    sorted_sdl(
        &Schema::build(
            IamOwnQuery::default(),
            IamOwnMutation::default(),
            EmptySubscription,
        )
        .finish(),
    )
}

/// The sorted, byte-stable SDL of a schema without subscriptions.
fn sorted_sdl<Q, M>(schema: &Schema<Q, M, EmptySubscription>) -> String
where
    Q: ObjectType + 'static,
    M: ObjectType + 'static,
{
    schema.sdl_with_options(
        SDLExportOptions::new()
            .sorted_fields()
            .sorted_arguments()
            .sorted_enum_items()
            .prefer_single_line_descriptions()
            .use_space_ident()
            .indent_width(2),
    )
}

#[cfg(test)]
mod tests;
