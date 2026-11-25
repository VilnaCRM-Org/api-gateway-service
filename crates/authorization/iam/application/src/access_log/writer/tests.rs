use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iam_domain::{AccessClass, AccessLane, ClassBudgets, DecisionReason};
use test_support::access_log_sink::RecordingAccessLogSink;
use test_support::clock::ManualClock;

use super::{AccessLogWriter, Window};
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
