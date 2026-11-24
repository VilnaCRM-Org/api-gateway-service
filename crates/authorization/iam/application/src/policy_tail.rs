//! The `PolicyTail` task of the gateway (FR-71, FR-77).
//!
//! The bootstrap of a pod from the state topic is a pure step function
//! `(state, input) -> (state, actions)` that a driver feeds with the answers of the topic
//! (`architecture.md` section 5.6).
//!
//! Story 9.3 adds the bootstrap part; Story 9.4 adds the [tail] and the fence of an
//! inconsistency.

pub mod bootstrap;
pub mod tail;

pub use bootstrap::{
    BootstrapAction, BootstrapEntry, BootstrapFailure, BootstrapInput, BootstrapMachine,
    BootstrapOutcome, BootstrapPorts, BootstrapSnapshot, run_bootstrap,
};
pub use tail::{
    ApplyResult, FenceCause, IgnoredProgress, MAX_APPEND_AGE_MS, TailAction, TailApplier, TailEnd,
    TailInput, TailMachine, TailPorts, TailProgress, rebootstrap_delay, run_tail,
};
