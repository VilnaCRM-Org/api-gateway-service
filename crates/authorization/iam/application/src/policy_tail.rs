//! The `PolicyTail` task of the gateway (FR-71, FR-77).
//!
//! The bootstrap of a pod from the state topic is a pure step function
//! `(state, input) -> (state, actions)` that a driver feeds with the answers of the topic
//! (`architecture.md` section 5.6).
//!
//! Story 9.3 adds the bootstrap part; the tail and the fence of an inconsistency follow in Story
//! 9.4.

pub mod bootstrap;

pub use bootstrap::{
    BootstrapAction, BootstrapEntry, BootstrapFailure, BootstrapInput, BootstrapMachine,
    BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, run_bootstrap,
};
