//! Integration tests of the IAM migrations and the PostgreSQL adapters; each test runs in its own
//! database.

#[cfg(test)]
mod jwt_access_token_verifier;
#[cfg(test)]
mod migration;
#[cfg(test)]
mod replay;
#[cfg(test)]
mod repository;
#[cfg(test)]
mod security_audit_log;
#[cfg(test)]
mod security_audit_migration;
#[cfg(test)]
mod unit_of_work;
#[cfg(test)]
mod unit_of_work_migration;
