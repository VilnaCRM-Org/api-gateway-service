//! Capability 1: headers on a null-value record survive the round trip through the compose broker.

use krafka::Record;

use super::{PARTITION, compose_broker, create_topic, read, tail, unique_topic};

/// The framing headers of every policy-log record (`architecture.md` section 9.2).
const FRAMING_HEADERS: [&str; 8] = [
    "iam-version",
    "iam-seq",
    "iam-count",
    "iam-digest-after",
    "iam-op",
    "iam-schema",
    "iam-log-epoch",
    "iam-relay-epoch",
];

/// One value per header: its name followed by a zero byte and two bytes that are not UTF-8, so that a
/// lossy or text-only path would change it.
fn framing_headers() -> Vec<(String, Vec<u8>)> {
    FRAMING_HEADERS
        .iter()
        .map(|name| {
            let mut value = name.as_bytes().to_vec();
            value.extend_from_slice(&[0x00, 0xff, 0xfe]);
            ((*name).to_owned(), value)
        })
        .collect()
}

fn with_headers(mut record: Record, headers: &[(String, Vec<u8>)]) -> Record {
    for (name, value) in headers {
        record = record.header(name.clone(), value.clone());
    }
    record
}

#[tokio::test]
async fn every_header_of_a_null_value_record_comes_back_byte_identical() {
    let kafka = compose_broker().await;
    let topic = unique_topic("headers");
    create_topic(&kafka, &topic).await;
    let headers = framing_headers();
    let producer = kafka.producer().build().await.unwrap();

    let deleted = producer
        .send(with_headers(
            Record::tombstone(topic.clone(), "row-1").partition(PARTITION),
            &headers,
        ))
        .await
        .unwrap();
    let upserted = producer
        .send(with_headers(
            Record::new(topic.clone(), "row-2-value")
                .key("row-2")
                .partition(PARTITION),
            &headers,
        ))
        .await
        .unwrap();
    producer.flush().await.unwrap();
    drop(producer);
    let consumer = tail(&kafka, &topic, 0).await;
    let records = read(&consumer, 2).await;
    drop(consumer);

    assert_eq!(records.len(), 2, "{records:?}");
    let tombstone = records.first().unwrap();
    let returned: Vec<(String, Option<Vec<u8>>)> = tombstone
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.as_ref().map(|bytes| bytes.to_vec())))
        .collect();
    let expected: Vec<(String, Option<Vec<u8>>)> = headers
        .iter()
        .map(|(name, value)| (name.clone(), Some(value.clone())))
        .collect();
    assert_eq!(tombstone.offset, deleted.offset);
    assert!(tombstone.value.is_none(), "{tombstone:?}");
    assert!(tombstone.is_tombstone());
    assert_eq!(returned, expected);
    let row = &records[1];
    assert_eq!(row.offset, upserted.offset);
    assert_eq!(row.value_str(), Some("row-2-value"));
    assert_eq!(row.headers.len(), FRAMING_HEADERS.len());
}
