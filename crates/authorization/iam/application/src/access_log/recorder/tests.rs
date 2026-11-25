use std::sync::Arc;

use iam_domain::{AccessClass, AccessLane, DecisionReason, Rng, SampleRate};

use super::AccessRecorder;
use crate::access_log::builder::AccessRecordBuilder;
use crate::access_log::channel::{AccessLogReceiver, access_log_channel};
use crate::access_log::counters::AccessLogCounters;
use crate::access_log::fixtures::{allowed, denied};

#[derive(Debug)]
struct ZeroRng;

impl Rng for ZeroRng {
    fn next_u64(&self) -> u64 {
        0
    }
}

fn recorder(
    rate: SampleRate,
    capacity: usize,
) -> (AccessRecorder, AccessLogReceiver, Arc<AccessLogCounters>) {
    let counters = Arc::new(AccessLogCounters::new());
    let (channel, receiver) = access_log_channel(capacity, Arc::clone(&counters));
    let builder = AccessRecordBuilder::new(Arc::new(ZeroRng), rate);
    (AccessRecorder::new(builder, channel), receiver, counters)
}

#[test]
fn a_recorded_decision_reaches_the_channel_on_its_lane() {
    let (recorder, receiver, _counters) = recorder(SampleRate::ALL, 4);

    recorder.record(allowed());
    recorder.record(denied(DecisionReason::PermissionMissing, 403));

    assert_eq!(receiver.try_next().unwrap().lane, AccessLane::Access);
    assert_eq!(receiver.try_next().unwrap().lane, AccessLane::Audit);
    assert!(receiver.try_next().is_none());
}

#[test]
fn an_allow_that_the_sample_leaves_out_never_reaches_the_channel() {
    let (recorder, receiver, counters) = recorder(SampleRate::NONE, 4);

    recorder.record(allowed());

    assert!(receiver.try_next().is_none());
    assert_eq!(
        counters.dropped_count(AccessLane::Access, AccessClass::Allow),
        0
    );
}

#[test]
fn a_full_channel_counts_the_drop_and_the_call_returns() {
    let (recorder, _receiver, counters) = recorder(SampleRate::ALL, 1);

    for _ in 0..5 {
        recorder.record(denied(DecisionReason::TokenInvalid, 401));
    }

    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Audit),
        4
    );
}
