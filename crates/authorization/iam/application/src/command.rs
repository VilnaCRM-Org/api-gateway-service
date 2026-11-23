//! Commands of the IAM context.
//!
//! A command changes state and returns no data; each one gets a module of its own below this one.
//! The caller reads the result of a committed command through its change receipt.

pub mod assign_user_role;
pub mod bootstrap_iam;
pub mod create_graphql_permissions;
pub mod create_rest_permissions;
pub mod create_role;
pub mod delete_role;
pub mod load_graphql_spec;
pub mod load_openapi_spec;
pub mod register_own_specs;
pub mod revoke_user_role;
pub mod set_role_permissions;
pub mod update_role;
pub mod update_user_role;
