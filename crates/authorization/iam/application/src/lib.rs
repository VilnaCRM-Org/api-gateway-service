//! Bounded context `iam`, application layer: commands, queries and their handlers, event
//! subscribers, application errors and the API-facing adapters (`http` and `graphql`).
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! infrastructure layer. The use-case modules (`command`, `query`, `subscriber`) do not import
//! `axum`, `utoipa` or `async_graphql`, and `error` names nothing of them but the HTTP status of its
//! problem mapping; only `http` and `graphql` may use them freely.

pub mod command;
pub mod error;
pub mod graphql;
pub mod http;
pub mod query;
pub mod subscriber;

pub use error::IamError;
pub use query::get_change_receipt::{GetChangeReceiptQuery, GetChangeReceiptQueryHandler};
pub use query::get_idempotent_replay::{GetIdempotentReplayQuery, GetIdempotentReplayQueryHandler};
pub use query::get_policy_epoch::{GetPolicyEpochQuery, GetPolicyEpochQueryHandler};
