//! Bounded context `iam`, application layer: commands, queries and their handlers, event
//! subscribers, application errors and the API-facing adapters (`http` and `graphql`).
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! infrastructure layer. The use-case modules (`command`, `query`, `subscriber`) do not import
//! `axum`, `utoipa` or `async_graphql`, and `error` names nothing of them but the HTTP status of its
//! problem mapping; only `http` and `graphql` may use them freely.

pub mod command;
pub mod error;
#[cfg(test)]
mod fixtures;
pub mod graphql;
#[cfg(test)]
mod graphql_spec_fixtures;
pub mod http;
pub mod principal;
pub mod query;
pub mod service_catalog_loader;
pub mod subscriber;
#[cfg(test)]
mod user_role_fixtures;

pub use command::assign_user_role::{AssignUserRoleCommand, AssignUserRoleCommandHandler};
pub use command::create_role::{CreateRoleCommand, CreateRoleCommandHandler};
pub use command::load_graphql_spec::{LoadGraphQlSpecCommand, LoadGraphQlSpecCommandHandler};
pub use command::update_role::{DescriptionUpdate, UpdateRoleCommand, UpdateRoleCommandHandler};
pub use error::IamError;
pub use principal::Principal;
pub use query::find_graphql_spec::{FindGraphQlSpecQuery, FindGraphQlSpecQueryHandler};
pub use query::get_change_receipt::{GetChangeReceiptQuery, GetChangeReceiptQueryHandler};
pub use query::get_graphql_spec_diff::{
    GetGraphQlSpecDiffQuery, GetGraphQlSpecDiffQueryHandler, GraphQlSpecView,
};
pub use query::get_idempotent_replay::{GetIdempotentReplayQuery, GetIdempotentReplayQueryHandler};
pub use query::get_policy_epoch::{GetPolicyEpochQuery, GetPolicyEpochQueryHandler};
pub use query::get_role::{GetRoleQuery, GetRoleQueryHandler};
pub use query::get_user_role::{GetUserRoleQuery, GetUserRoleQueryHandler, UserRoleView};
pub use query::list_roles::{ListRolesQuery, ListRolesQueryHandler, RolePage};
pub use query::list_user_roles::{ListUserRolesQuery, ListUserRolesQueryHandler, UserRolePage};
pub use query::resolve_subject_token::{
    ResolveSubjectTokenQuery, ResolveSubjectTokenQueryHandler, TokenResolution,
};
pub use query::resolve_token::{ResolveTokenQuery, ResolveTokenQueryHandler};
pub use service_catalog_loader::ServiceCatalogLoader;
