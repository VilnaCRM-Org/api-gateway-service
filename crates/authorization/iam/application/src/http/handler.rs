//! REST handlers of the IAM context, and the use-case calls that the GraphQL resolvers share.
//!
//! No operation exists yet. A handler added here takes the IAM state and the problem-aware
//! extractors only (`ApiPath`, `ValidatedQuery`, `ValidatedJson` and `ApiJson`, and the IAM header
//! extractors `IdempotencyKeyHeader` and `IfMatchHeader`); the test of this module checks every
//! handler against that rule.

#[cfg(test)]
mod tests;
