//! Bounded context `iam`, application layer: commands, queries and their handlers, event
//! subscribers, application errors and the API-facing adapters (`http` and `graphql`).
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! infrastructure layer. The use-case modules (`command`, `query`, `subscriber`) do not import
//! `axum`, `utoipa` or `async_graphql`, and `error` names nothing of them but the HTTP status of its
//! problem mapping; only `http` and `graphql` may use them freely.

pub mod access_decision_service;
pub mod administrator_safeguard;
pub mod command;
pub mod error;
#[cfg(test)]
mod fixtures;
pub mod graphql;
#[cfg(test)]
mod graphql_activation_fixtures;
#[cfg(test)]
mod graphql_permission_fixtures;
#[cfg(test)]
mod graphql_spec_fixtures;
pub mod http;
#[cfg(test)]
mod openapi_spec_fixtures;
pub mod principal;
pub mod query;
pub mod required_key_resolver;
#[cfg(test)]
mod rest_activation_fixtures;
#[cfg(test)]
mod rest_permission_fixtures;
#[cfg(test)]
mod role_permission_fixtures;
pub mod service_catalog_loader;
pub mod singleton_loop;
pub mod subscriber;
#[cfg(test)]
mod user_role_fixtures;

pub use access_decision_service::AccessDecisionService;
pub use administrator_safeguard::{AdministratorSafeguard, Admission, SafeguardPorts};
pub use command::assign_user_role::{AssignUserRoleCommand, AssignUserRoleCommandHandler};
pub use command::bootstrap_iam::{BootstrapIamCommand, BootstrapIamCommandHandler};
pub use command::create_graphql_permissions::{
    ActivationReads, CreateGraphQlPermissionsCommand, CreateGraphQlPermissionsCommandHandler,
};
pub use command::create_rest_permissions::{
    CreateRestPermissionsCommand, CreateRestPermissionsCommandHandler, RestActivationReads,
};
pub use command::create_role::{CreateRoleCommand, CreateRoleCommandHandler};
pub use command::delete_role::{DeleteRoleCommand, DeleteRoleCommandHandler};
pub use command::load_graphql_spec::{LoadGraphQlSpecCommand, LoadGraphQlSpecCommandHandler};
pub use command::load_openapi_spec::{LoadOpenApiSpecCommand, LoadOpenApiSpecCommandHandler};
pub use command::register_own_specs::{RegisterOwnSpecsCommand, RegisterOwnSpecsCommandHandler};
pub use command::revoke_user_role::{
    RevokeUserRoleCommand, RevokeUserRoleCommandHandler, RevokeUserRoleReads,
};
pub use command::set_role_permissions::{
    SetRolePermissionsCommand, SetRolePermissionsCommandHandler, SetRolePermissionsReads,
};
pub use command::update_role::{DescriptionUpdate, UpdateRoleCommand, UpdateRoleCommandHandler};
pub use command::update_user_role::{UpdateUserRoleCommand, UpdateUserRoleCommandHandler};
pub use error::IamError;
pub use principal::Principal;
pub use query::find_graphql_spec::{FindGraphQlSpecQuery, FindGraphQlSpecQueryHandler};
pub use query::find_openapi_spec::{FindOpenApiSpecQuery, FindOpenApiSpecQueryHandler};
pub use query::get_change_receipt::{GetChangeReceiptQuery, GetChangeReceiptQueryHandler};
pub use query::get_graphql_permission::{
    GetGraphQlPermissionQuery, GetGraphQlPermissionQueryHandler,
};
pub use query::get_graphql_permissions::{
    GetGraphQlPermissionsQuery, GetGraphQlPermissionsQueryHandler, GraphQlPermissionPage,
    GraphQlPermissionView, PermissionReads,
};
pub use query::get_graphql_permissions_created::{
    GetGraphQlPermissionsCreatedQuery, GetGraphQlPermissionsCreatedQueryHandler,
};
pub use query::get_graphql_spec::{GetGraphQlSpecQuery, GetGraphQlSpecQueryHandler};
pub use query::get_graphql_spec_diff::{
    GetGraphQlSpecDiffQuery, GetGraphQlSpecDiffQueryHandler, GraphQlSpecView,
};
pub use query::get_graphql_specs::{
    GetGraphQlSpecsQuery, GetGraphQlSpecsQueryHandler, GraphQlSpecPage, GraphQlSpecSummary,
};
pub use query::get_idempotent_replay::{GetIdempotentReplayQuery, GetIdempotentReplayQueryHandler};
pub use query::get_openapi_spec::{GetOpenApiSpecQuery, GetOpenApiSpecQueryHandler};
pub use query::get_openapi_spec_diff::{
    GetOpenApiSpecDiffQuery, GetOpenApiSpecDiffQueryHandler, OpenApiSpecView,
};
pub use query::get_openapi_specs::{
    GetOpenApiSpecsQuery, GetOpenApiSpecsQueryHandler, OpenApiSpecPage, OpenApiSpecSummary,
};
pub use query::get_policy_epoch::{GetPolicyEpochQuery, GetPolicyEpochQueryHandler};
pub use query::get_rest_permission::{GetRestPermissionQuery, GetRestPermissionQueryHandler};
pub use query::get_rest_permissions::{
    GetRestPermissionsQuery, GetRestPermissionsQueryHandler, RestPermissionPage,
    RestPermissionReads, RestPermissionView,
};
pub use query::get_rest_permissions_created::{
    GetRestPermissionsCreatedQuery, GetRestPermissionsCreatedQueryHandler,
};
pub use query::get_role::{GetRoleQuery, GetRoleQueryHandler};
pub use query::get_role_permissions::{
    GetRolePermissionsQuery, GetRolePermissionsQueryHandler, RolePermissions,
};
pub use query::get_user_role::{GetUserRoleQuery, GetUserRoleQueryHandler, UserRoleView};
pub use query::list_roles::{ListRolesQuery, ListRolesQueryHandler, RolePage};
pub use query::list_user_roles::{ListUserRolesQuery, ListUserRolesQueryHandler, UserRolePage};
pub use query::resolve_subject_token::{
    ResolveSubjectTokenQuery, ResolveSubjectTokenQueryHandler, TokenResolution,
};
pub use query::resolve_token::{ResolveTokenQuery, ResolveTokenQueryHandler};
pub use required_key_resolver::RequiredKeyResolver;
pub use service_catalog_loader::ServiceCatalogLoader;
pub use singleton_loop::{
    BatchOutcome, InvalidSingletonInterval, MAX_SINGLETON_INTERVAL, SingletonInterval,
    SingletonLoop, SingletonWork,
};
