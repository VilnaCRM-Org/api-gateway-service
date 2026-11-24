//! The policy state: the keys of the state topic, the full state of each entity, the framing of the
//! records of one versioned transaction and the layout of a service catalogue in chunks (FR-70).

pub mod batch;
pub mod key;
pub mod layout;
pub mod model;
pub mod shadow;

#[cfg(test)]
mod fakes;
