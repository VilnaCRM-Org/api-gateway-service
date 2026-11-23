//! Entities and records of the IAM context that are not aggregates.

pub(crate) mod aggregate_event;
pub mod change_receipt;
pub mod event_envelope;
pub mod iam_change;
pub mod idempotency_record;
pub mod security_audit_event;
