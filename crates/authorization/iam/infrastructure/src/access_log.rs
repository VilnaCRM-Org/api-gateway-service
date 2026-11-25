//! Adapters of the access log (FR-50, NFR-20).
//!
//! The sink that writes JSON lines to stdout, the sink that pushes the audit lane to Loki, the sink
//! that routes each lane to its own, and the digest prefix that stands for a credential in a
//! record.

pub mod credential_digest;
pub mod lane_split_sink;
pub mod loki_sink;
pub mod stdout_sink;

pub use credential_digest::credential_digest_prefix;
pub use lane_split_sink::LaneSplitSink;
pub use loki_sink::{BATCH_BYTES, LokiPushAccessLogSink, LokiSinkSettings, LokiTransport};
pub use stdout_sink::{StdoutAccessLogSink, render_entry};
