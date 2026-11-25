//! The access log of the gateway (FR-50, NFR-20, NFR-24).
//!
//! The request path builds one record per decision with [`AccessRecordBuilder`], which applies the
//! lane rule and the sampling draw, and hands it to the bounded channel with a send that never
//! waits. The [`AccessLogWriter`] drains the channel on a dedicated thread, applies the per-class
//! budgets and writes through the [`iam_domain::AccessLogSink`] port.

pub mod audit_gate;
pub mod builder;
pub mod channel;
pub mod counters;
pub mod decision_api;
pub mod facts;
#[cfg(test)]
mod fixtures;
pub mod recorder;
pub mod writer;

pub use audit_gate::{AuditGate, AuditSlot};
pub use builder::{AccessItem, AccessRecordBuilder};
pub use channel::{AccessLogChannel, AccessLogReceiver, access_log_channel};
pub use counters::AccessLogCounters;
pub use decision_api::{
    BATCH_VALIDATION_TEMPLATE, DECISION_API_HOST, DecisionAccessLog, DecisionCall,
    VALIDATION_TEMPLATE,
};
pub use facts::{
    AccessFacts, DecisionTrace, RequestFacts, ResponseFacts, RouteFacts, VerdictFacts,
};
pub use recorder::AccessRecorder;
pub use writer::{AccessLogWriter, WRITER_TICK};
