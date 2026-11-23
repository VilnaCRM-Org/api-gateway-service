//! The policy snapshot of the gateway (FR-71, NFR-16).
//!
//! It holds the assembly of the records of one version, the rules that decide what an offered
//! record means, the ring of applied digests and the read API of a snapshot.

pub mod assembly;
pub mod read;
pub mod ring;
pub mod rules;
