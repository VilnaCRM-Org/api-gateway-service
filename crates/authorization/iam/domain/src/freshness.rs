//! The freshness contract of the gateway (FR-73, NFR-36, ADR 0024).
//!
//! A pod allows a request only while it holds a recent proof that its snapshot contains every
//! acknowledged change: [`FreshnessProof`] is what one successful probe of the state topic shows,
//! and [`FreshnessRule`] judges it against the hard bound and the gaps the watchdog saw.

pub mod hysteresis;
pub mod peer_report;
pub mod probe_error;
pub mod proof;
pub mod readiness;
pub mod rule;
