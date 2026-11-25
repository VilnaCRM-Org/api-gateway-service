//! The aggregate record that stands for the records of a class beyond its budget.

use std::time::SystemTime;

use shared_domain::Uuid;

use super::kinds::{AccessClass, AccessLane};
use super::record::AccessRecord;
use crate::value_object::decision_reason::DecisionReason;

/// One record per second, route, status and reason with the number of decisions it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAggregate {
    /// The lane the aggregated records belonged to.
    pub lane: AccessLane,
    /// The class whose budget was exhausted.
    pub class: AccessClass,
    /// The second the aggregate covers, truncated to whole seconds.
    pub window_start: SystemTime,
    /// The matched route, when there was one.
    pub route_id: Option<Uuid>,
    /// The path template of the matched route.
    pub route_template: Option<String>,
    /// The status of the answers.
    pub status: u16,
    /// The reason code of the decisions.
    pub reason: DecisionReason,
    /// How many records were folded into the aggregate.
    pub count: u64,
}

/// What a sink is asked to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessEntry {
    /// The record of one decision.
    Record(Box<AccessRecord>),
    /// The aggregate of the decisions beyond a budget.
    Aggregate(AccessAggregate),
}
