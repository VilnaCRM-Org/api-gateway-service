use std::time::Duration;

use iam_domain::{PolicyDigestValue, TailBatch};
use rstest::rstest;
use test_support::policy_bootstrap_log::framed_row;
use test_support::policy_tail_log::{batch, timed};
use test_support::rng::FakeRng;

use super::{FenceCause, MAX_APPEND_AGE_MS, TailAction, TailInput, TailMachine, rebootstrap_delay};

const ROLE: &str = "role/0192f6a0-0000-7000-8000-000000000001";
const NOW: i64 = 10_000_000;

fn row(offset: i64, version: i64) -> iam_domain::FramedRecord {
    framed_row(
        offset,
        ROLE,
        Some("a"),
        version,
        (1, 2, PolicyDigestValue::ZERO),
    )
}

fn polled(batch: TailBatch) -> TailInput {
    TailInput::Polled { batch, now_ms: NOW }
}

fn step(machine: TailMachine, input: TailInput) -> (TailMachine, Vec<TailAction>) {
    machine.step(input)
}

#[test]
fn starting_polls_from_the_position_of_the_bootstrap() {
    let (_machine, actions) = step(TailMachine::new(7, 7), TailInput::Start);

    assert_eq!(actions, vec![TailAction::Poll { position: 7 }]);
}

#[test]
fn a_batch_is_handed_to_the_apply_thread_and_moves_the_position_past_its_last_record() {
    let records = vec![timed(row(7, 1), None), timed(row(9, 1), None)];

    let (machine, actions) = step(TailMachine::new(7, 7), polled(batch(records, 7, 10)));

    assert_eq!(actions, vec![TailAction::Apply(vec![row(7, 1), row(9, 1)])]);
    assert_eq!(machine.position(), 10);
}

#[test]
fn after_an_applied_batch_the_next_poll_starts_at_the_new_position() {
    let records = vec![timed(row(7, 1), None)];
    let (machine, _apply) = step(TailMachine::new(7, 7), polled(batch(records, 7, 8)));

    let (_machine, actions) = step(machine, TailInput::Applied);

    assert_eq!(actions, vec![TailAction::Poll { position: 8 }]);
}

#[test]
fn an_idle_tail_polls_again_from_the_same_position() {
    let (machine, actions) = step(TailMachine::new(7, 7), polled(batch(Vec::new(), 0, 7)));

    assert_eq!(actions, vec![TailAction::Poll { position: 7 }]);
    assert_eq!(machine.position(), 7);
}

#[test]
fn a_failed_poll_pauses_and_polls_the_same_position_again() {
    let (_machine, actions) = step(
        TailMachine::new(7, 7),
        TailInput::ReadFailed("down".to_owned()),
    );

    assert_eq!(
        actions,
        vec![TailAction::Backoff, TailAction::Poll { position: 7 }]
    );
}

#[rstest]
#[case::below_the_first_offset(7, 9, 20)]
#[case::above_the_watermark(30, 0, 20)]
fn a_position_outside_the_partition_fences(
    #[case] position: i64,
    #[case] low: i64,
    #[case] high: i64,
) {
    let (_machine, actions) = step(
        TailMachine::new(position, position),
        polled(batch(Vec::new(), low, high)),
    );

    assert_eq!(
        actions,
        vec![TailAction::Fence(FenceCause::OutOfRange {
            position,
            low,
            high
        })]
    );
}

#[test]
fn a_watermark_that_went_backwards_fences() {
    let (machine, _idle) = step(TailMachine::new(7, 7), polled(batch(Vec::new(), 0, 20)));

    let (_machine, actions) = step(machine, polled(batch(Vec::new(), 0, 15)));

    assert_eq!(
        actions,
        vec![TailAction::Fence(FenceCause::WatermarkRegression {
            seen: 20,
            high: 15
        })]
    );
}

#[test]
fn a_batch_that_stops_below_a_watermark_seen_earlier_is_no_regression() {
    let (machine, _idle) = step(TailMachine::new(7, 7), polled(batch(Vec::new(), 0, 20)));
    let records = vec![timed(row(7, 1), None)];

    let (_machine, actions) = step(machine, polled(batch(records, 7, 8)));

    assert_eq!(actions, vec![TailAction::Apply(vec![row(7, 1)])]);
}

#[test]
fn a_record_appended_more_than_an_hour_ago_fences() {
    let old = NOW - MAX_APPEND_AGE_MS - 1;
    let records = vec![timed(row(7, 1), Some(old))];

    let (_machine, actions) = step(TailMachine::new(7, 7), polled(batch(records, 7, 8)));

    assert_eq!(
        actions,
        vec![TailAction::Fence(FenceCause::StaleAppendTime {
            age_ms: MAX_APPEND_AGE_MS + 1
        })]
    );
}

#[test]
fn a_record_appended_exactly_an_hour_ago_is_accepted() {
    let records = vec![timed(row(7, 1), Some(NOW - MAX_APPEND_AGE_MS))];

    let (_machine, actions) = step(TailMachine::new(7, 7), polled(batch(records, 7, 8)));

    assert_eq!(actions, vec![TailAction::Apply(vec![row(7, 1)])]);
}

#[test]
fn a_record_the_bootstrap_already_read_is_history_and_is_not_aged() {
    let old = NOW - MAX_APPEND_AGE_MS * 3;
    let records = vec![timed(row(7, 2), Some(old)), timed(row(9, 2), Some(NOW))];

    let (_machine, actions) = step(TailMachine::new(7, 9), polled(batch(records, 7, 10)));

    assert_eq!(actions, vec![TailAction::Apply(vec![row(7, 2), row(9, 2)])]);
}

#[test]
fn a_topic_that_stamps_create_time_is_not_aged() {
    let records = vec![timed(row(7, 1), None)];

    let (_machine, actions) = step(TailMachine::new(7, 7), polled(batch(records, 7, 8)));

    assert_eq!(actions, vec![TailAction::Apply(vec![row(7, 1)])]);
}

#[test]
fn a_fault_the_apply_thread_reports_fences_and_ends_the_machine() {
    let (machine, actions) = step(
        TailMachine::new(7, 7),
        TailInput::ApplyFenced(FenceCause::Gap { expected: 3 }),
    );

    assert_eq!(
        actions,
        vec![TailAction::Fence(FenceCause::Gap { expected: 3 })]
    );
    let (_machine, after) = step(machine, TailInput::Applied);
    assert_eq!(after, Vec::new(), "a fenced machine asks for nothing");
}

#[test]
fn an_unreadable_record_fences() {
    let (_machine, actions) = step(TailMachine::new(7, 7), TailInput::Unreadable { offset: 8 });

    assert_eq!(
        actions,
        vec![TailAction::Fence(FenceCause::Malformed { offset: 8 })]
    );
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(3_000)]
#[case(30_000)]
fn the_rebootstrap_delay_never_exceeds_the_ready_bound(#[case] bound_ms: u64) {
    let rng = FakeRng::new();
    let bound = Duration::from_millis(bound_ms);

    for _ in 0..200 {
        assert!(rebootstrap_delay(&rng, bound) <= bound);
    }
}

#[test]
fn the_same_seed_draws_the_same_delays() {
    let bound = Duration::from_secs(5);

    let first: Vec<Duration> = (0..5)
        .map(|_| rebootstrap_delay(&FakeRng::seeded(42), bound))
        .collect();
    let again = rebootstrap_delay(&FakeRng::seeded(42), bound);

    assert!(first.iter().all(|delay| *delay == again));
}
