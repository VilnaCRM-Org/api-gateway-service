//! Adapters of the access log: the sink that writes JSON lines to stdout and the digest prefix
//! that stands for a credential in a record (FR-50, NFR-20).

pub mod credential_digest;
pub mod stdout_sink;

pub use credential_digest::credential_digest_prefix;
pub use stdout_sink::{StdoutAccessLogSink, render_entry};
