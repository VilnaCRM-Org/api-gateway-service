use iam_domain::{AccessClass, AccessLane};
use test_support::log::LogRecorder;

use super::AccessLogCounters;

const LANES: [AccessLane; 2] = [AccessLane::Access, AccessLane::Audit];
const CLASSES: [AccessClass; 3] = [AccessClass::Allow, AccessClass::Error, AccessClass::Audit];

#[test]
fn every_lane_and_class_has_its_own_counter() {
    let counters = AccessLogCounters::new();

    for lane in LANES {
        for class in CLASSES {
            assert_eq!(counters.dropped_count(lane, class), 0);
        }
    }
    counters.dropped(AccessLane::Audit, AccessClass::Error);
    counters.dropped(AccessLane::Audit, AccessClass::Error);
    counters.dropped(AccessLane::Access, AccessClass::Allow);

    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Error),
        2
    );
    assert_eq!(
        counters.dropped_count(AccessLane::Access, AccessClass::Allow),
        1
    );
    assert_eq!(
        counters.dropped_count(AccessLane::Access, AccessClass::Error),
        0
    );
    assert_eq!(
        counters.dropped_count(AccessLane::Audit, AccessClass::Allow),
        0
    );
}

#[test]
fn a_drop_emits_the_metric_event_with_its_lane_and_class() {
    let (recorder, _guard) = LogRecorder::install();

    AccessLogCounters::new().dropped(AccessLane::Audit, AccessClass::Audit);

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].target, "metrics");
    assert_eq!(lines[0].field("metric"), Some("access_log_dropped_total"));
    assert_eq!(lines[0].field("lane"), Some("audit"));
    assert_eq!(lines[0].field("class"), Some("audit"));
    assert_eq!(lines[0].field("value"), Some("1"));
}
