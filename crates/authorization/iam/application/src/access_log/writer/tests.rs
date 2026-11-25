use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iam_domain::{AccessClass, AccessLane, ClassBudgets, DecisionReason};
use test_support::access_log_sink::RecordingAccessLogSink;
use test_support::clock::ManualClock;

use super::{AccessLogWriter, AuditSlot, Window};
use crate::access_log::channel::access_log_channel;
use crate::access_log::counters::AccessLogCounters;
use crate::access_log::fixtures::{allowed, at, decision_id, denied, error_item, item};

struct Setup {
    writer: AccessLogWriter,
    sink: Arc<RecordingAccessLogSink>,
    clock: Arc<ManualClock>,
}

fn setup(budgets: ClassBudgets) -> Setup {
    let sink = Arc::new(RecordingAccessLogSink::new());
    let clock = Arc::new(ManualClock::at(at(1_800_000_000)));
    let writer = AccessLogWriter::new(
        Arc::<RecordingAccessLogSink>::clone(&sink),
        Arc::<ManualClock>::clone(&clock),
        budgets,
    );
    Setup {
        writer,
        sink,
        clock,
    }
}

#[test]
fn five_thousand_identical_errors_in_one_second_write_the_budget_and_one_aggregate() {
    let Setup {
        mut writer,
        sink,
        clock,
    } = setup(ClassBudgets::new(1_000, 2_000));

    for counter in 0..5_000 {
        writer.write(error_item(counter, 100, 503));
    }
    assert_eq!(sink.records(AccessLane::Access).len(), 1_000);
    assert_eq!(sink.aggregates().len(), 0);
    clock.advance(Duration::from_secs(1));
    writer.tick();

    let aggregates = sink.aggregates();
    assert_eq!(sink.records(AccessLane::Access).len(), 1_000);
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].count, 4_000);
    assert_eq!(aggregates[0].status, 503);
    assert_eq!(aggregates[0].reason, DecisionReason::Unavailable);
    assert_eq!(aggregates[0].class, AccessClass::Error);
    assert_eq!(aggregates[0].lane, AccessLane::Access);
    assert_eq!(aggregates[0].window_start, at(1_800_000_000));
    assert_eq!(
        aggregates[0].route_template.as_deref(),
        Some("/api/orders/{id}")
    );
}

#[test]
fn the_aggregates_are_one_per_route_status_and_reason() {
    let Setup {
        mut writer,
        sink,
        clock,
    } = setup(ClassBudgets::new(1, 1));

    for counter in 0..3 {
        writer.write(error_item(counter, 100, 503));
        writer.write(error_item(counter + 10, 100, 504));
        writer.write(error_item(counter + 20, 200, 503));
    }
    clock.advance(Duration::from_secs(1));
    writer.tick();

    let mut counts: Vec<u64> = sink
        .aggregates()
        .iter()
        .map(|aggregate| aggregate.count)
        .collect();
    counts.sort_unstable();
    assert_eq!(sink.records(AccessLane::Access).len(), 1);
    assert_eq!(counts, [2, 3, 3]);
}

#[test]
fn a_new_second_has_a_new_budget() {
    let Setup {
        mut writer,
        sink,
        clock,
    } = setup(ClassBudgets::new(2, 2));

    for counter in 0..4 {
        writer.write(error_item(counter, 100, 503));
    }
    clock.advance(Duration::from_secs(1));
    for counter in 4..8 {
        writer.write(error_item(counter, 100, 503));
    }

    assert_eq!(sink.records(AccessLane::Access).len(), 4);
    assert_eq!(sink.aggregates().len(), 1);
    assert_eq!(sink.aggregates()[0].count, 2);
}

#[test]
fn the_classes_have_budgets_of_their_own_and_allows_have_none() {
    let Setup {
        mut writer, sink, ..
    } = setup(ClassBudgets::new(1, 2));
    let audit = |counter| {
        let mut facts = denied(DecisionReason::PermissionMissing, 403);
        facts.decision_id = decision_id(counter);
        item(AccessLane::Audit, AccessClass::Audit, facts)
    };

    for counter in 0..3 {
        writer.write(error_item(counter, 100, 503));
        writer.write(audit(counter));
    }
    for _ in 0..10 {
        writer.write(item(AccessLane::Access, AccessClass::Allow, allowed()));
    }
    writer.finish();

    assert_eq!(sink.records(AccessLane::Access).len(), 11);
    assert_eq!(sink.records(AccessLane::Audit).len(), 2);
    let counts: Vec<(AccessLane, u64)> = sink
        .aggregates()
        .iter()
        .map(|aggregate| (aggregate.lane, aggregate.count))
        .collect();
    assert_eq!(counts, [(AccessLane::Audit, 1), (AccessLane::Access, 2)]);
}

#[test]
fn an_aggregate_of_the_audit_lane_is_written_to_the_audit_lane() {
    let Setup {
        mut writer, sink, ..
    } = setup(ClassBudgets::new(1, 1));

    for counter in 0..3 {
        let mut facts = denied(DecisionReason::TokenInvalid, 401);
        facts.decision_id = decision_id(counter);
        writer.write(item(AccessLane::Audit, AccessClass::Audit, facts));
    }
    writer.finish();

    let entries = sink.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].0, AccessLane::Audit);
    assert_eq!(sink.aggregates()[0].class, AccessClass::Audit);
    assert_eq!(sink.aggregates()[0].count, 2);
}

#[test]
fn a_clock_that_goes_backwards_keeps_the_open_second() {
    let Setup {
        mut writer, sink, ..
    } = setup(ClassBudgets::new(1, 1));
    let earlier = Arc::new(ManualClock::at(at(1_700_000_000)));
    writer.clock = earlier;

    writer.write(error_item(1, 100, 503));
    writer.write(error_item(2, 100, 503));
    writer.tick();

    assert_eq!(sink.records(AccessLane::Access).len(), 1);
    assert_eq!(sink.aggregates().len(), 0);
}

#[test]
fn the_loop_writes_what_is_queued_and_the_pending_aggregates_when_the_senders_are_gone() {
    let Setup { writer, sink, .. } = setup(ClassBudgets::new(2, 2));
    let (channel, receiver) = access_log_channel(16, Arc::new(AccessLogCounters::new()));
    for counter in 0..5 {
        channel.offer(error_item(counter, 100, 503));
    }
    drop(channel);

    writer.run(&receiver, &AtomicBool::new(false));

    assert_eq!(sink.records(AccessLane::Access).len(), 2);
    assert_eq!(sink.aggregates().len(), 1);
    assert_eq!(sink.aggregates()[0].count, 3);
}

#[test]
fn the_loop_stops_at_the_flag_and_still_drains_the_queue() {
    let Setup { writer, sink, .. } = setup(ClassBudgets::new(10, 10));
    let (channel, receiver) = access_log_channel(16, Arc::new(AccessLogCounters::new()));
    channel.offer(error_item(1, 100, 503));
    let stop = AtomicBool::new(true);
    assert!(stop.load(Ordering::Acquire));

    writer.run(&receiver, &stop);

    assert_eq!(sink.records(AccessLane::Access).len(), 1);
    drop(channel);
}

#[test]
fn an_unbudgeted_class_has_never_used_any_of_a_window() {
    let window = Window::opened_at(5);

    assert_eq!(window.used(AccessClass::Allow), 0);
    assert_eq!(window.used(AccessClass::Error), 0);
    assert_eq!(window.used(AccessClass::Audit), 0);
}

struct Tracked {
    writer: AccessLogWriter,
    sink: Arc<RecordingAccessLogSink>,
    clock: Arc<ManualClock>,
    gate: Arc<crate::access_log::AuditGate>,
    counters: Arc<AccessLogCounters>,
}

fn tracked(capacity: usize) -> Tracked {
    tracked_with(capacity, ClassBudgets::new(1_000, 1_000))
}

fn tracked_with(capacity: usize, budgets: ClassBudgets) -> Tracked {
    let sink = Arc::new(RecordingAccessLogSink::withholding());
    let clock = Arc::new(ManualClock::at(at(1_800_000_000)));
    let gate = Arc::new(crate::access_log::AuditGate::new(
        Arc::<ManualClock>::clone(&clock),
        Duration::from_secs(5),
        capacity,
    ));
    let counters = Arc::new(AccessLogCounters::new());
    let writer = AccessLogWriter::new(
        Arc::<RecordingAccessLogSink>::clone(&sink),
        Arc::<ManualClock>::clone(&clock),
        budgets,
    )
    .with_audit_gate(Arc::clone(&gate), Arc::clone(&counters));
    Tracked {
        writer,
        sink,
        clock,
        gate,
        counters,
    }
}

fn audit_item(counter: u32) -> crate::access_log::AccessItem {
    let mut facts = denied(DecisionReason::PermissionMissing, 403);
    facts.decision_id = decision_id(counter);
    item(AccessLane::Audit, AccessClass::Audit, facts)
}

/// An audit item that carries the slot its request reserved.
fn admitted_item(counter: u32, slot: AuditSlot) -> crate::access_log::AccessItem {
    audit_item(counter).with_slot(Some(slot))
}

#[test]
fn unacknowledged_audit_records_are_pending_until_the_sink_acknowledges_them() {
    let Tracked {
        mut writer,
        sink,
        clock,
        gate,
        ..
    } = tracked(100);

    writer.write(audit_item(1));
    clock.advance(Duration::from_secs(2));
    writer.write(audit_item(2));
    writer.write(audit_item(3));

    assert_eq!(gate.pending(), 3);
    assert_eq!(gate.oldest_wait(), Duration::from_secs(2));
    sink.acknowledge(2);
    writer.tick();
    assert_eq!(gate.pending(), 1);
    assert_eq!(gate.oldest_wait(), Duration::ZERO);
    sink.acknowledge(1);
    writer.tick();
    assert_eq!(gate.pending(), 0);
    assert!(gate.admits());
}

#[test]
fn an_acknowledged_batch_is_not_counted_twice() {
    let Tracked {
        mut writer,
        sink,
        gate,
        ..
    } = tracked(100);
    writer.write(audit_item(1));
    writer.write(audit_item(2));
    sink.acknowledge(2);
    writer.tick();

    writer.tick();
    writer.write(audit_item(3));

    assert_eq!(gate.pending(), 1);
}

#[test]
fn an_oldest_record_that_waits_beyond_the_bound_closes_the_gate_and_the_acknowledgement_opens_it() {
    let Tracked {
        mut writer,
        sink,
        clock,
        gate,
        ..
    } = tracked(100);
    writer.write(audit_item(1));

    clock.advance(Duration::from_secs(6));
    assert!(!gate.admits());
    sink.acknowledge(1);
    writer.tick();

    assert!(gate.admits());
}

#[test]
fn an_audit_record_beyond_the_capacity_is_dropped_and_counted_and_the_gate_closes() {
    let Tracked {
        mut writer,
        sink,
        gate,
        counters,
        ..
    } = tracked(2);

    writer.write(audit_item(1));
    writer.write(audit_item(2));
    writer.write(audit_item(3));

    assert_eq!(sink.records(AccessLane::Audit).len(), 2);
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        1
    );
    assert!(!gate.admits());
}

#[test]
fn a_sink_without_acknowledgements_leaves_nothing_pending() {
    let sink = Arc::new(RecordingAccessLogSink::new());
    let clock = Arc::new(ManualClock::at(at(1_800_000_000)));
    let gate = Arc::new(crate::access_log::AuditGate::new(
        Arc::<ManualClock>::clone(&clock),
        Duration::from_secs(5),
        10,
    ));
    let mut writer = AccessLogWriter::new(
        Arc::<RecordingAccessLogSink>::clone(&sink),
        clock,
        ClassBudgets::new(1_000, 1_000),
    )
    .with_audit_gate(Arc::clone(&gate), Arc::new(AccessLogCounters::new()));

    writer.write(audit_item(1));

    assert_eq!(gate.pending(), 0);
}

#[test]
fn ordinary_lane_records_are_never_pending() {
    let Tracked {
        mut writer, gate, ..
    } = tracked(10);

    writer.write(error_item(1, 100, 503));

    assert_eq!(gate.pending(), 0);
}

#[test]
fn audit_records_are_dropped_and_counted_while_the_oldest_waits_beyond_the_bound() {
    let Tracked {
        mut writer,
        sink,
        clock,
        gate,
        counters,
    } = tracked(100);
    writer.write(audit_item(1));
    clock.advance(Duration::from_secs(6));

    writer.write(audit_item(2));
    writer.write(audit_item(3));

    assert_eq!(sink.records(AccessLane::Audit).len(), 1);
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        2
    );
    sink.acknowledge(1);
    writer.tick();
    assert!(gate.admits());
    writer.write(audit_item(4));
    assert_eq!(sink.records(AccessLane::Audit).len(), 2);
}

#[test]
fn an_admitted_record_is_written_although_the_buffer_filled_between_admission_and_write() {
    let Tracked {
        mut writer,
        sink,
        gate,
        counters,
        ..
    } = tracked(2);
    let first = gate.reserve().unwrap();
    let second = gate.reserve().unwrap();
    assert!(gate.reserve().is_none());
    // The channel fills while both admitted records are in flight.
    gate.mark_channel_full();

    writer.write(admitted_item(1, first));
    writer.write(admitted_item(2, second));

    assert_eq!(sink.records(AccessLane::Audit).len(), 2);
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        0
    );
    assert_eq!(gate.reserved(), 0);
}

#[test]
fn a_record_without_a_reservation_is_still_dropped_when_the_lane_is_full() {
    let Tracked {
        mut writer,
        sink,
        gate,
        ..
    } = tracked(1);
    gate.mark_channel_full();

    writer.write(audit_item(1));

    assert_eq!(sink.records(AccessLane::Audit).len(), 0);
}

#[test]
fn an_admitted_record_that_is_folded_for_its_budget_gives_its_slot_back() {
    let Tracked {
        mut writer,
        sink,
        gate,
        ..
    } = tracked_with(3, ClassBudgets::new(1_000, 1));
    let first = gate.reserve().unwrap();
    let second = gate.reserve().unwrap();

    writer.write(admitted_item(1, first));
    assert_eq!(gate.reserved(), 1);
    writer.write(admitted_item(2, second));

    assert_eq!(sink.records(AccessLane::Audit).len(), 1);
    assert_eq!(gate.reserved(), 0);
}

#[test]
fn a_record_without_a_slot_does_not_take_the_slot_of_an_admitted_one() {
    let Tracked {
        mut writer,
        sink,
        gate,
        ..
    } = tracked(2);
    let admitted = gate.reserve().unwrap();
    let other = gate.reserve().unwrap();
    assert_eq!(gate.reserved(), 2);

    // A denial or a wildcard allow reaches the writer between admission and write: it never
    // reserved, so it must neither bypass the room check nor give a slot back.
    writer.write(audit_item(1));
    assert_eq!(gate.reserved(), 2);
    assert_eq!(sink.records(AccessLane::Audit).len(), 0);

    writer.write(admitted_item(2, admitted));
    writer.write(admitted_item(3, other));

    assert_eq!(sink.records(AccessLane::Audit).len(), 2);
    assert_eq!(gate.reserved(), 0);
}
