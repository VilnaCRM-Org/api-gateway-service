use iam_domain::{KafkaInspectionError, KafkaTopicInspector as _, Violation};

use super::FakeTopicInspector;
use crate::block_on;

#[test]
fn a_passing_inspector_passes_and_counts_its_calls() {
    let inspector = FakeTopicInspector::passing();

    let verdict = block_on(inspector.inspect()).unwrap();

    assert!(verdict.passed());
    assert_eq!(inspector.inspections(), 1);
}

#[test]
fn a_failing_inspector_reports_its_violations() {
    let inspector = FakeTopicInspector::failing(vec![Violation::new("partitions", "1", "2")]);

    let verdict = block_on(inspector.inspect()).unwrap();

    assert!(!verdict.passed());
    assert_eq!(verdict.violations().len(), 1);
}

#[test]
fn an_unreachable_inspector_is_an_error() {
    let inspector = FakeTopicInspector::unreachable();

    let verdict = block_on(inspector.inspect());

    assert!(matches!(verdict, Err(KafkaInspectionError::Unavailable(_))));
}
