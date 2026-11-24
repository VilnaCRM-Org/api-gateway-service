//! Bounded context `iam`, application layer: commands, queries and their handlers, event
//! subscribers, application errors and the API-facing adapters (`http` and `graphql`).
//!
//! This crate depends on the domain layer of its own context and of the shared kernel, never on the
//! infrastructure layer. The use-case modules (`command`, `query`, `subscriber`) do not import
//! `axum`, `utoipa` or `async_graphql`, and `error` names nothing of them but the HTTP status of its
//! problem mapping; only `http` and `graphql` may use them freely.

pub mod access_decision_service;
#[cfg(test)]
mod access_validation_fixtures;
pub mod administrator_safeguard;
pub mod anti_entropy;
pub mod bulk_chunk_router;
#[cfg(test)]
mod bulk_operation_fixtures;
pub mod bulk_operation_runner;
pub mod bulk_role_deletion;
pub mod caller_rule;
pub mod command;
pub mod endpoint_directory;
pub mod endpoint_watcher;
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
pub mod guarded_unit_of_work;
pub mod http;
pub mod iam_access_guard;
#[cfg(test)]
mod openapi_spec_fixtures;
pub mod operation_rules;
pub mod outbox_relay;
pub mod policy_maintenance;
#[cfg(test)]
mod policy_resync_fixtures;
pub mod policy_tail;
pub mod policy_topic_head;
pub mod principal;
pub mod publishing_unit_of_work;
pub mod query;
#[cfg(test)]
mod rate_policy_fixtures;
pub mod rate_policy_values;
#[cfg(test)]
mod rejected_attempt_fixtures;
pub mod rejected_attempt_writer;
pub mod required_key_resolver;
#[cfg(test)]
mod rest_activation_fixtures;
#[cfg(test)]
mod rest_permission_fixtures;
pub mod resync_chunks;
#[cfg(test)]
mod role_permission_fixtures;
#[cfg(test)]
mod route_configuration_fixtures;
#[cfg(test)]
mod route_fixtures;
pub mod service_catalog_loader;
pub mod singleton_loop;
#[cfg(test)]
mod spec_retirement_fixtures;
pub mod subscriber;
#[cfg(test)]
mod upstream_fixtures;
#[cfg(test)]
mod user_role_fixtures;
#[cfg(test)]
mod user_role_permission_fixtures;

pub use access_decision_service::AccessDecisionService;
pub use administrator_safeguard::{AdministratorSafeguard, Admission, SafeguardPorts};
pub use anti_entropy::{
    AntiEntropyAlert, AntiEntropyChecker, AntiEntropyCounters, AntiEntropyPorts,
    AntiEntropySettings, InvalidAntiEntropySettings, TopicAheadHold,
};
pub use bulk_chunk_router::BulkChunkRouter;
pub use bulk_operation_runner::{BulkOperationRunner, BulkRunnerPorts};
pub use bulk_role_deletion::{RoleDeletionChunkCommitter, RoleDeletionPorts};
pub use caller_rule::{CallerRule, target_services};
pub use command::apply_route_configuration::{
    ApplyRouteConfigurationCommand, ApplyRouteConfigurationCommandHandler,
};
pub use command::assign_user_role::{AssignUserRoleCommand, AssignUserRoleCommandHandler};
pub use command::bootstrap_iam::{BootstrapIamCommand, BootstrapIamCommandHandler};
pub use command::create_graphql_permissions::{
    ActivationReads, CreateGraphQlPermissionsCommand, CreateGraphQlPermissionsCommandHandler,
};
pub use command::create_rate_policy::{CreateRatePolicyCommand, CreateRatePolicyCommandHandler};
pub use command::create_rest_permissions::{
    CreateRestPermissionsCommand, CreateRestPermissionsCommandHandler, RestActivationReads,
};
pub use command::create_role::{CreateRoleCommand, CreateRoleCommandHandler};
pub use command::create_route::{CreateRouteCommand, CreateRouteCommandHandler};
pub use command::create_upstream::{CreateUpstreamCommand, CreateUpstreamCommandHandler};
pub use command::delete_rate_policy::{DeleteRatePolicyCommand, DeleteRatePolicyCommandHandler};
pub use command::delete_role::{BulkDeletionPath, DeleteRoleCommand, DeleteRoleCommandHandler};
pub use command::delete_route::{DeleteRouteCommand, DeleteRouteCommandHandler, DeleteRoutePorts};
pub use command::delete_upstream::{
    DeleteUpstreamCommand, DeleteUpstreamCommandHandler, DeleteUpstreamPorts,
};
pub use command::load_graphql_spec::{LoadGraphQlSpecCommand, LoadGraphQlSpecCommandHandler};
pub use command::load_openapi_spec::{LoadOpenApiSpecCommand, LoadOpenApiSpecCommandHandler};
pub use command::record_rejected_attempt::{
    RecordRejectedAttemptCommand, RecordRejectedAttemptCommandHandler,
};
pub use command::register_own_specs::{RegisterOwnSpecsCommand, RegisterOwnSpecsCommandHandler};
pub use command::resync_policy::{
    ResyncPolicyCommand, ResyncPolicyCommandHandler, ResyncPolicyPorts,
};
pub use command::retire_graphql_spec::{RetireGraphQlSpecCommand, RetireGraphQlSpecCommandHandler};
pub use command::retire_openapi_spec::{RetireOpenApiSpecCommand, RetireOpenApiSpecCommandHandler};
pub use command::revoke_user_role::{
    RevokeUserRoleCommand, RevokeUserRoleCommandHandler, RevokeUserRoleReads,
};
pub use command::route_checks::RoutePorts;
pub use command::run_maintenance::{RunMaintenanceCommand, RunMaintenanceCommandHandler};
pub use command::seed_iam_gateway::{
    SeedIamGatewayCommand, SeedIamGatewayCommandHandler, SeedMode,
};
pub use command::set_role_permissions::{
    SetRolePermissionsCommand, SetRolePermissionsCommandHandler, SetRolePermissionsReads,
};
pub use command::update_rate_policy::{UpdateRatePolicyCommand, UpdateRatePolicyCommandHandler};
pub use command::update_role::{DescriptionUpdate, UpdateRoleCommand, UpdateRoleCommandHandler};
pub use command::update_route::{RoutePatch, UpdateRouteCommand, UpdateRouteCommandHandler};
pub use command::update_upstream::{
    UpdateUpstreamCommand, UpdateUpstreamCommandHandler, UpstreamPatch,
};
pub use command::update_user_role::{UpdateUserRoleCommand, UpdateUserRoleCommandHandler};
pub use endpoint_directory::{EndpointDirectory, EndpointView, ZoneSource};
pub use endpoint_watcher::{EndpointWatcher, WatcherSettings};
pub use error::IamError;
pub use guarded_unit_of_work::{GuardReads, GuardedUnitOfWork};
pub use iam_access_guard::{
    AuthorizationUnavailable, GraphQlOperationRequest, IamAccessGuard, OperationRequest,
};
pub use operation_rules::{GraphQlRule, OperationRule, OperationRules, Requirement};
pub use outbox_relay::{OutboxRelay, OutboxRelayPorts, OutboxRelaySettings};
pub use policy_maintenance::{MaintenanceSettings, PolicyMaintenance};
pub use policy_tail::{
    BootstrapAction, BootstrapEntry, BootstrapFailure, BootstrapInput, BootstrapMachine,
    BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, run_bootstrap,
};
pub use policy_topic_head::PolicyTopicHead;
pub use principal::Principal;
pub use publishing_unit_of_work::PublishingUnitOfWork;
pub use query::find_graphql_spec::{FindGraphQlSpecQuery, FindGraphQlSpecQueryHandler};
pub use query::find_openapi_spec::{FindOpenApiSpecQuery, FindOpenApiSpecQueryHandler};
pub use query::get_bulk_operation::{GetBulkOperationQuery, GetBulkOperationQueryHandler};
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
pub use query::get_rate_policy::{GetRatePolicyQuery, GetRatePolicyQueryHandler};
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
pub use query::get_route::{GetRouteQuery, GetRouteQueryHandler};
pub use query::get_route_configuration::{
    GetRouteConfigurationQuery, GetRouteConfigurationQueryHandler, RouteConfiguration,
};
pub use query::get_upstream::{GetUpstreamQuery, GetUpstreamQueryHandler};
pub use query::get_user_role::{GetUserRoleQuery, GetUserRoleQueryHandler, UserRoleView};
pub use query::get_user_role_permissions::{
    GetUserRolePermissionsQuery, GetUserRolePermissionsQueryHandler, UserRolePermissionsView,
};
pub use query::list_bulk_operations::{
    BulkOperationPage, ListBulkOperationsQuery, ListBulkOperationsQueryHandler,
};
pub use query::list_rate_policies::{
    ListRatePoliciesQuery, ListRatePoliciesQueryHandler, RatePolicyPage,
};
pub use query::list_roles::{ListRolesQuery, ListRolesQueryHandler, RolePage};
pub use query::list_routes::{ListRoutesQuery, ListRoutesQueryHandler, RoutePage};
pub use query::list_upstreams::{ListUpstreamsQuery, ListUpstreamsQueryHandler, UpstreamPage};
pub use query::list_user_roles::{ListUserRolesQuery, ListUserRolesQueryHandler, UserRolePage};
pub use query::preview_route_configuration::{
    PreviewRouteConfigurationQuery, PreviewRouteConfigurationQueryHandler,
    RouteConfigurationPreview,
};
pub use query::resolve_subject_token::{
    ResolveSubjectTokenQuery, ResolveSubjectTokenQueryHandler, TokenResolution,
};
pub use query::resolve_token::{ResolveTokenQuery, ResolveTokenQueryHandler};
pub use query::validate_access::{ValidateAccessQuery, ValidateAccessQueryHandler};
pub use query::validate_access_batch::{
    BatchCheck, ValidateAccessBatchQuery, ValidateAccessBatchQueryHandler,
};
pub use rate_policy_values::{RatePolicyPatch, RatePolicyValues};
pub use rejected_attempt_writer::{FLUSH_INTERVAL, FlushOutcome, RejectedAttemptWriter};
pub use required_key_resolver::RequiredKeyResolver;
pub use resync_chunks::{ResyncChunkCommitter, ResyncPorts};
pub use service_catalog_loader::ServiceCatalogLoader;
pub use singleton_loop::{
    BatchOutcome, InvalidSingletonInterval, MAX_SINGLETON_INTERVAL, SingletonInterval,
    SingletonLoop, SingletonWork,
};
