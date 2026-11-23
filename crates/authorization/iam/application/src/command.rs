//! Commands of the IAM context.
//!
//! A command changes state and returns no data; each one gets a module of its own below this one.
//! The caller reads the result of a committed command through its change receipt.

pub mod assign_user_role;
pub mod create_role;
pub mod load_graphql_spec;
pub mod update_role;
