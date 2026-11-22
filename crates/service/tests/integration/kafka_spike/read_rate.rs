//! Capability 11: the bootstrap read rate, measured on the compose host and never a gate (NFR-37).
//!
//! The test writes a 200 MiB one-partition topic to the compose broker and reads it from offset 0 with a
//! reader without a group, as a pod bootstraps from the state topic, then prints the rate next to the
//! 100 MB/s target. It is a measurement, not a check of behaviour: it is ignored by `make ci` and run by
//! hand with the command recorded in `docs/spikes/phase-0.md`:
//!
//! ```text
//! make start-deps DEPS=kafka
//! scripts/with-env.sh .env .env.test -- cargo nextest run -p service --test integration \
//!     --run-ignored only kafka_spike::read_rate --no-capture
//! ```

use std::time::Duration;

use krafka::admin::DeleteTopicsOptions;
use krafka::consumer::IsolationLevel;
use krafka::{Compression, Record};

use super::{PARTITION, POLL, compose_broker, create_topic, unique_topic};

/// The size of one record's value: 16 KiB, a large policy-state row.
const RECORD_BYTES: usize = 16 * 1024;

/// The size of the topic: 200 MiB.
const TOPIC_BYTES: usize = 200 * 1024 * 1024;

/// The records of the topic: 12,800.
const RECORDS: usize = TOPIC_BYTES / RECORD_BYTES;

/// The bound of the whole read; a slower read fails the run instead of hanging it.
const READ_DEADLINE: Duration = Duration::from_secs(600);

/// The target of NFR-37, in MB/s (10^6 bytes per second).
const TARGET_MB_PER_SECOND: f64 = 100.0;

#[tokio::test]
#[ignore = "a compose-host measurement (capability 11), run outside make ci with the command in docs/spikes/phase-0.md"]
async fn a_reader_without_a_group_reads_a_200_mib_topic_from_offset_0() {
    let kafka = compose_broker().await;
    let topic = unique_topic("read-rate");
    create_topic(&kafka, &topic).await;
    let producer = kafka
        .producer()
        .compression(Compression::None)
        .batch_size(512 * 1024)
        .linger(Duration::from_millis(5))
        .build()
        .await
        .unwrap();
    let value = vec![0x5a_u8; RECORD_BYTES];
    let mut deliveries = Vec::with_capacity(RECORDS);
    for _ in 0..RECORDS {
        deliveries.push(
            producer
                .enqueue(Record::new(topic.clone(), value.clone()).partition(PARTITION))
                .await
                .unwrap(),
        );
    }
    producer.flush().await.unwrap();
    for delivery in deliveries {
        let written = delivery.await.unwrap();
        assert_eq!(written.partition, PARTITION);
    }
    drop(producer);

    let reader = kafka
        .consumer_without_group()
        .isolation_level(IsolationLevel::ReadCommitted)
        .fetch_max_bytes(64 * 1024 * 1024)
        .max_partition_fetch_bytes(16 * 1024 * 1024)
        .build()
        .await
        .unwrap();
    reader.assign(&topic, vec![PARTITION]).await.unwrap();
    reader.seek(&topic, PARTITION, 0).await.unwrap();
    let started = tokio::time::Instant::now();
    let (mut read, mut bytes) = (0_usize, 0_usize);
    while read < RECORDS && started.elapsed() < READ_DEADLINE {
        for record in reader.poll(POLL).await.unwrap() {
            read = read.saturating_add(1);
            bytes = bytes.saturating_add(record.value.as_deref().map_or(0, <[u8]>::len));
        }
    }
    let elapsed = started.elapsed();
    drop(reader);
    kafka
        .admin()
        .delete_topics([topic.as_str()], DeleteTopicsOptions::default())
        .await
        .unwrap();

    let megabytes = f64::from(u32::try_from(bytes).unwrap()) / 1_000_000.0;
    let rate = megabytes / elapsed.as_secs_f64();
    println!(
        "bootstrap read rate on this host: {rate:.1} MB/s ({megabytes:.1} MB in {:.2} s, {read} records of {RECORD_BYTES} bytes); \
         target {TARGET_MB_PER_SECOND} MB/s, a compose-host measurement and not a gate value",
        elapsed.as_secs_f64()
    );
    assert_eq!(read, RECORDS);
    assert_eq!(bytes, TOPIC_BYTES);
}
