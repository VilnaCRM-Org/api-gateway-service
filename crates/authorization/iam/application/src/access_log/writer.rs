//! The loop that drains the access channel, applies the per-class budgets and writes (FR-50).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use iam_domain::{AccessAggregate, AccessClass, AccessEntry, AccessLogSink, ClassBudgets};
use shared_domain::Clock;

use super::builder::AccessItem;
use super::channel::{AccessLogReceiver, Received};

/// How long the writer waits for the next record before it checks the clock and the stop flag.
pub const WRITER_TICK: Duration = Duration::from_millis(100);

/// What an aggregate stands for: the class, the lane, the route, the status and the reason.
type AggregateKey = (
    &'static str,
    &'static str,
    Option<String>,
    u16,
    &'static str,
);

/// The records of the second that is open: how many each budgeted class wrote, and the
/// aggregates of what went beyond.
#[derive(Debug, Default)]
struct Window {
    second: u64,
    errors: u32,
    audits: u32,
    aggregates: BTreeMap<AggregateKey, AccessAggregate>,
}

impl Window {
    fn opened_at(second: u64) -> Self {
        Self {
            second,
            ..Self::default()
        }
    }

    /// How many records of `class` this second wrote.
    const fn used(&self, class: AccessClass) -> u32 {
        match class {
            AccessClass::Allow => 0,
            AccessClass::Error => self.errors,
            AccessClass::Audit => self.audits,
        }
    }

    /// Counts one written record of `class`.
    const fn count(&mut self, class: AccessClass) {
        match class {
            AccessClass::Allow => {}
            AccessClass::Error => self.errors = self.errors.saturating_add(1),
            AccessClass::Audit => self.audits = self.audits.saturating_add(1),
        }
    }

    /// Folds `item` into the aggregate of its route, status and reason.
    fn fold(&mut self, item: &AccessItem) {
        let record = &item.record;
        let key = (
            item.class.as_str(),
            item.lane.as_str(),
            record.route_id.map(|route| route.to_string()),
            record.status,
            record.reason.as_str(),
        );
        let window_start = second_start(self.second);
        let aggregate = self
            .aggregates
            .entry(key)
            .or_insert_with(|| AccessAggregate {
                lane: item.lane,
                class: item.class,
                window_start,
                route_id: record.route_id,
                route_template: record.route_template.clone(),
                status: record.status,
                reason: record.reason,
                count: 0,
            });
        aggregate.count = aggregate.count.saturating_add(1);
    }
}

/// The start of the whole second `second` after the epoch.
fn second_start(second: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(second))
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// Writes the records of the channel to the sink, within the budget of their class.
///
/// Each class that has a budget (`error` and `audit`) writes at most that many records per second
/// of the `Clock` port; the records beyond it are folded into one aggregate per second, route,
/// status and reason, which is written when the second is over. Allows have no budget: the sample
/// rate bounds them.
#[derive(Debug)]
pub struct AccessLogWriter {
    sink: Arc<dyn AccessLogSink>,
    clock: Arc<dyn Clock>,
    budgets: ClassBudgets,
    window: Window,
}

impl AccessLogWriter {
    /// A writer from the channel to `sink` under `budgets`, reading time from `clock`.
    #[must_use]
    pub fn new(sink: Arc<dyn AccessLogSink>, clock: Arc<dyn Clock>, budgets: ClassBudgets) -> Self {
        let window = Window::opened_at(second_of(clock.now()));
        Self {
            sink,
            clock,
            budgets,
            window,
        }
    }

    /// Writes `item`, or folds it into an aggregate when its class has used its budget.
    pub fn write(&mut self, item: AccessItem) {
        self.tick();
        let within = self
            .budgets
            .of(item.class)
            .is_none_or(|budget| self.window.used(item.class) < budget);
        if within {
            self.window.count(item.class);
            self.sink
                .write(item.lane, &AccessEntry::Record(Box::new(item.record)));
        } else {
            self.window.fold(&item);
        }
    }

    /// Opens the new second when the clock has moved on, which writes the aggregates of the old
    /// one.
    pub fn tick(&mut self) {
        let second = second_of(self.clock.now());
        if second > self.window.second {
            self.finish();
            self.window = Window::opened_at(second);
        }
    }

    /// Writes the aggregates that are pending, the ones of the open second included.
    pub fn finish(&mut self) {
        for aggregate in std::mem::take(&mut self.window.aggregates).into_values() {
            let lane = aggregate.lane;
            self.sink.write(lane, &AccessEntry::Aggregate(aggregate));
        }
    }

    /// Drains `receiver` until `stop` is set or every sender is gone, then writes what is queued
    /// and the pending aggregates.
    pub fn run(mut self, receiver: &AccessLogReceiver, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            match receiver.receive(WRITER_TICK) {
                Received::Item(item) => self.write(*item),
                Received::Idle => self.tick(),
                Received::Closed => break,
            }
        }
        while let Some(item) = receiver.try_next() {
            self.write(item);
        }
        self.finish();
    }
}

/// The whole seconds between the epoch and `time`; zero before the epoch.
fn second_of(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests;
