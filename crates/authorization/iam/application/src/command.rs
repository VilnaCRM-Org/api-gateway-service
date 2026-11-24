//! Commands of the IAM context.
//!
//! A command changes state and returns no data; each one gets a module of its own below this one.
//! The caller reads the result of a committed command through its change receipt.

pub mod apply_route_configuration;
pub mod assign_user_role;
pub mod bootstrap_iam;
pub mod create_graphql_permissions;
pub mod create_rate_policy;
pub mod create_rest_permissions;
pub mod create_role;
pub mod create_route;
pub mod create_upstream;
pub mod delete_rate_policy;
pub mod delete_role;
pub mod delete_route;
pub mod delete_upstream;
pub(crate) mod gateway_audit;
pub mod load_graphql_spec;
pub mod load_openapi_spec;
pub mod record_rejected_attempt;
pub mod register_own_specs;
pub mod resync_policy;
pub mod retire_graphql_spec;
pub mod retire_openapi_spec;
pub mod revoke_sessions;
pub mod revoke_user_role;
pub(crate) mod role_deletion;
pub(crate) mod route_checks;
pub(crate) mod route_configuration_plan;
pub mod run_maintenance;
pub mod seed_iam_gateway;
pub mod set_global_token_cutoff;
pub mod set_role_permissions;
pub(crate) mod spec_retirement;
pub mod update_rate_policy;
pub mod update_role;
pub mod update_route;
pub mod update_upstream;
pub mod update_user_role;
