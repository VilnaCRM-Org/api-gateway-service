//! The configuration verdict on the state topic (FR-72): what `iam-control` and the gateway read
//! from Kafka, the rules that turn it into a verdict, and the settings they are applied under.
//!
//! The rules are pure: the infrastructure layer reads the cluster into a [`TopicObservation`] and
//! [`ConfigurationRules::evaluate`] decides. Nothing here names a Kafka client.

pub mod config_gates;
pub mod observation;
pub mod rules;
pub mod verdict;

pub use config_gates::ConfigGates;
pub use observation::{AllowEveryoneEvidence, TopicObservation};
pub use rules::{CONTROL_PRINCIPAL, ConfigurationRules};
pub use verdict::{CheckSource, ConfigurationVerdict, Violation};
