//! The loop that drains the access channel, applies the per-class budgets and writes (FR-50).

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessAggregate, AccessClass, AccessEntry, AccessLane, AccessLogSink, ClassBudgets,
};
use shared_domain::Clock;

use super::audit_gate::AuditGate;
use super::builder::AccessItem;
use super::channel::{AccessLogReceiver, Received};
use super::counters::AccessLogCounters;

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

/// The audit entries that the log store has not acknowledged, oldest first, and the gate that
/// tells the request path about them (Story 14.2).
#[derive(Debug)]
struct AuditTracking {
    gate: Arc<AuditGate>,
    counters: Arc<AccessLogCounters>,
    waiting: VecDeque<SystemTime>,
    acknowledged: u64,
    published: u64,
}

impl AuditTracking {
    const fn new(gate: Arc<AuditGate>, counters: Arc<AccessLogCounters>) -> Self {
        Self {
            gate,
            counters,
            waiting: VecDeque::new(),
            acknowledged: 0,
            published: 0,
        }
    }

    /// Whether the lane takes one more entry: it does while the gate admits, which is until
    /// `capacity` entries wait or the oldest one has waited longer than the bound.
    fn has_room(&self) -> bool {
        self.gate.admits()
    }

    /// Notes an entry that was handed to the sink at `now`.
    fn written(&mut self, now: SystemTime) {
        self.waiting.push_back(now);
        self.publish();
    }

    /// Drops what the sink acknowledged since the last call, or everything when the sink keeps no
    /// account of acknowledgements.
    fn reconcile(&mut self, acknowledged: Option<u64>) {
        let newly = acknowledged.map_or(u64::MAX, |total| {
            let newly = total.saturating_sub(self.acknowledged);
            self.acknowledged = self.acknowledged.max(total);
            newly
        });
        let count = usize::try_from(newly)
            .map_or(self.waiting.len(), |newly| newly.min(self.waiting.len()));
        self.waiting = self.waiting.split_off(count);
        self.publish();
    }

    /// Publishes the account to the gate and emits `access_log_audit_pending` when it changed.
    fn publish(&mut self) {
        let pending = u64::try_from(self.waiting.len()).unwrap_or(u64::MAX);
        self.gate.publish(pending, self.waiting.front().copied());
        if pending != self.published {
            self.published = pending;
            emit_pending(pending);
        }
    }
}

/// The metric event `access_log_audit_pending`: the audit entries that wait for the log store.
fn emit_pending(pending: u64) {
    tracing::info!(
        target: "metrics",
        metric = "access_log_audit_pending",
        value = pending,
    );
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
    audit: Option<AuditTracking>,
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
            audit: None,
        }
    }

    /// The same writer, which tracks the audit entries that the sink has not acknowledged and
    /// publishes them to `gate`; while the gate is closed (`gate.capacity()` entries wait, or the
    /// oldest has waited too long) an audit entry is dropped and counted in `counters`
    /// (Story 14.2).
    #[must_use]
    pub fn with_audit_gate(
        mut self,
        gate: Arc<AuditGate>,
        counters: Arc<AccessLogCounters>,
    ) -> Self {
        self.audit = Some(AuditTracking::new(gate, counters));
        self
    }

    /// Hands `entry` to the sink; an audit entry that the unacknowledged ones leave no room for is
    /// dropped and counted.
    fn emit(&mut self, lane: AccessLane, class: AccessClass, entry: &AccessEntry) {
        let now = self.clock.now();
        if let (AccessLane::Audit, Some(audit)) = (lane, self.audit.as_mut()) {
            if !audit.has_room() {
                audit.counters.dropped(lane, class);
                return;
            }
            audit.written(now);
        }
        self.sink.write(lane, entry);
    }

    /// Learns from the sink which audit entries the log store acknowledged.
    fn reconcile(&mut self) {
        let acknowledged = self.sink.acknowledged_audit();
        if let Some(audit) = self.audit.as_mut() {
            audit.reconcile(acknowledged);
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
            let entry = AccessEntry::Record(Box::new(item.record));
            self.emit(item.lane, item.class, &entry);
            self.reconcile();
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
        self.reconcile();
    }

    /// Writes the aggregates that are pending, the ones of the open second included.
    pub fn finish(&mut self) {
        for aggregate in std::mem::take(&mut self.window.aggregates).into_values() {
            let (lane, class) = (aggregate.lane, aggregate.class);
            self.emit(lane, class, &AccessEntry::Aggregate(aggregate));
        }
        self.reconcile();
    }

    /// Drains `receiver` until `stop` is set or every sender is gone, then writes what is queued
    /// and the pending aggregates.
    pub fn run(mut self, receiver: &AccessLogReceiver, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            match receiver.receive(WRITER_TICK) {
                Received::Item(item) => {
                    self.channel_has_room();
                    self.write(*item);
                }
                Received::Idle => self.tick(),
                Received::Closed => break,
            }
        }
        while let Some(item) = receiver.try_next() {
            self.write(item);
        }
        self.finish();
        self.sink.flush();
        self.reconcile();
    }

    /// Tells the gate that the channel has room again, since the writer took a record from it.
    fn channel_has_room(&self) {
        if let Some(audit) = self.audit.as_ref() {
            audit.gate.clear_channel_full();
        }
    }
}

/// The whole seconds between the epoch and `time`; zero before the epoch.
fn second_of(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests;
