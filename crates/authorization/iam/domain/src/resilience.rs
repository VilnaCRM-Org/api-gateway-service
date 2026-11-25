//! The pure rules that protect upstreams from slow or failing endpoints (FR-66).
//!
//! They decide which failed requests are retried, how many retries an upstream can afford and
//! when an endpoint is ejected. Timers, counters and sockets live in the composition root; these
//! rules take their inputs as values.

pub mod outlier_rule;
pub mod retry_budget;
pub mod retry_rule;
