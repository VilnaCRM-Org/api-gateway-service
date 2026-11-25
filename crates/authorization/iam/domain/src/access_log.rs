//! The access record of a gateway decision, the lane it is written to and the settings that bound
//! the log (FR-50, NFR-20, NFR-24).
//!
//! Every gateway decision produces one [`AccessRecord`]. It goes to exactly one [`AccessLane`]: the
//! audit lane holds every denial, every decision on an always-audit or sensitive key and every
//! wildcard allow, and the ordinary lane holds the rest, sampled for allows. A record never holds a
//! credential, a cookie, a GraphQL document or a concrete path.

pub mod aggregate;
pub mod kinds;
pub mod record;
pub mod settings;

pub use aggregate::{AccessAggregate, AccessEntry};
pub use kinds::{AccessClass, AccessDecision, AccessLane};
pub use record::AccessRecord;
pub use settings::{
    ClassBudgets, DEFAULT_CHANNEL_CAPACITY, InvalidAccessLogSetting, SampleRate,
    parse_channel_capacity,
};
