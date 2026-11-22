//! GraphQL adapter of the IAM context: the query and mutation roots.
//!
//! The roots have no field yet. An object type without fields is not valid GraphQL, and the
//! `Object` macro of `async-graphql` refuses one at compile time, so the roots are plain types until
//! the first IAM operation exists: that change gives each root its `#[Object]` implementation and
//! the composition root merges both into the schema.

/// Query root of the IAM context.
#[derive(Debug, Default)]
pub struct IamQuery;

/// Mutation root of the IAM context.
#[derive(Debug, Default)]
pub struct IamMutation;

#[cfg(test)]
mod tests;
