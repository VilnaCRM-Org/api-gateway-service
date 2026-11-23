use iam_domain::{PolicyLogError, PolicyLogProducer as _, PolicyLogRecord};

use super::{Answer, FakePolicyLogProducer};
use crate::block_on;

fn record(key: &str) -> PolicyLogRecord {
    PolicyLogRecord {
        topic: "topic".to_owned(),
        key: key.to_owned(),
        partition: None,
        payload: None,
        headers: Vec::new(),
    }
}

#[test]
fn acknowledged_records_get_consecutive_offsets_across_calls() {
    let producer = FakePolicyLogProducer::acknowledging();

    let first = block_on(producer.publish(&[record("a"), record("b")])).unwrap();
    let second = block_on(producer.publish(&[record("c")])).unwrap();

    assert_eq!(first, [0, 1]);
    assert_eq!(second, [2]);
    assert_eq!(producer.batches().len(), 2);
}

#[test]
fn the_script_is_followed_before_the_default() {
    let producer =
        FakePolicyLogProducer::new(&[Answer::Unavailable, Answer::Fenced], Answer::Acknowledge);

    let first = block_on(producer.publish(&[record("a")]));
    let second = block_on(producer.publish(&[record("a")]));
    let third = block_on(producer.publish(&[record("a")]));

    assert!(matches!(first, Err(PolicyLogError::Unavailable(_))));
    assert!(matches!(second, Err(PolicyLogError::Fenced(_))));
    assert_eq!(third.unwrap(), [0]);
    assert_eq!(producer.batches().len(), 3);
}

#[test]
fn a_short_answer_names_one_offset_fewer_than_records() {
    let producer = FakePolicyLogProducer::new(&[], Answer::Short);

    let offsets = block_on(producer.publish(&[record("a"), record("b")])).unwrap();
    let none = block_on(producer.publish(&[])).unwrap();

    assert_eq!(offsets, [0]);
    assert_eq!(none.len(), 0);
}
