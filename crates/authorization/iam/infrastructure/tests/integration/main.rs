//! Integration tests of the IAM migrations and the PostgreSQL adapters; each test runs in its own
//! database.

#[cfg(test)]
mod anti_entropy_store;
#[cfg(test)]
mod bulk_operation_repository;
#[cfg(test)]
mod catalogue_activation;
#[cfg(test)]
mod gateway_configuration;
#[cfg(test)]
mod gateway_preconditions;
#[cfg(test)]
mod graphql_spec_repository;
#[cfg(test)]
mod jwt_access_token_verifier;
#[cfg(test)]
mod kafka_topic_inspector;
#[cfg(test)]
mod kubernetes_watch;
#[cfg(test)]
mod maintenance_store;
#[cfg(test)]
mod migration;
#[cfg(test)]
mod openapi_spec_repository;
#[cfg(test)]
mod outbox_listener;
#[cfg(test)]
mod outbox_store;
#[cfg(test)]
mod policy_log_producer;
#[cfg(test)]
mod policy_log_tail;
#[cfg(test)]
mod policy_read_repository;
#[cfg(test)]
mod policy_state_inventory;
#[cfg(test)]
mod propagation_store;
#[cfg(test)]
mod replay;
#[cfg(test)]
mod repository;
#[cfg(test)]
mod revocation_repository;
#[cfg(test)]
mod revocation_statements;
#[cfg(test)]
mod role_repository;
#[cfg(test)]
mod security_audit_log;
#[cfg(test)]
mod security_audit_migration;
#[cfg(test)]
mod singleton_leadership;
#[cfg(test)]
mod startup_lock;
#[cfg(test)]
mod state_rows;
#[cfg(test)]
mod token_lifetime_floor;
#[cfg(test)]
mod token_resolution;
#[cfg(test)]
mod unit_of_work;
#[cfg(test)]
mod unit_of_work_migration;
#[cfg(test)]
mod user_role_repository;
