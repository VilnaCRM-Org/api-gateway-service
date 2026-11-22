//! Integration tests of the IAM migrations and the PostgreSQL adapters; each test runs in its own
//! database.

#[cfg(test)]
mod migration;
#[cfg(test)]
mod repository;
#[cfg(test)]
mod security_audit_log;
#[cfg(test)]
mod security_audit_migration;
