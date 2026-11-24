use std::collections::HashSet;
use std::time::Duration;

use proptest::prelude::*;
use rstest::rstest;

use super::{
    BulkChange, BulkChunker, BulkPacing, ChangeDirection, InvalidBulkChunking, MAX_CHUNK_ENTITIES,
};

fn change(direction: ChangeDirection, entity: u32) -> BulkChange<u32> {
    BulkChange { direction, entity }
}

#[rstest]
#[case(0)]
#[case(MAX_CHUNK_ENTITIES + 1)]
fn refuses_a_chunk_size_outside_one_to_one_thousand(#[case] size: usize) {
    assert_eq!(
        BulkChunker::new(size).unwrap_err(),
        InvalidBulkChunking::ChunkEntities
    );
}

#[rstest]
#[case(1)]
#[case(MAX_CHUNK_ENTITIES)]
fn accepts_the_bounds_of_the_chunk_size(#[case] size: usize) {
    assert_eq!(BulkChunker::new(size).unwrap().chunk_entities(), size);
}

#[test]
fn a_change_above_the_chunk_size_takes_the_bulk_path() {
    let chunker = BulkChunker::new(3).unwrap();

    assert!(!chunker.needs_bulk(3));
    assert!(chunker.needs_bulk(4));
}

#[test]
fn revoke_chunks_precede_grant_chunks_and_each_chunk_is_capped() {
    let chunker = BulkChunker::new(2).unwrap();
    let changes = vec![
        change(ChangeDirection::Grant, 1),
        change(ChangeDirection::Revoke, 2),
        change(ChangeDirection::Grant, 3),
        change(ChangeDirection::Revoke, 4),
        change(ChangeDirection::Revoke, 5),
    ];

    let chunks = chunker.chunk(changes);

    let shape: Vec<_> = chunks
        .iter()
        .map(|chunk| (chunk.direction, chunk.entities.clone()))
        .collect();
    assert_eq!(
        shape,
        vec![
            (ChangeDirection::Revoke, vec![2, 4]),
            (ChangeDirection::Revoke, vec![5]),
            (ChangeDirection::Grant, vec![1, 3]),
        ]
    );
}

#[test]
fn no_change_makes_no_chunk() {
    let chunker = BulkChunker::new(2).unwrap();

    assert_eq!(
        chunker.chunk::<u32>(Vec::new()),
        Vec::<crate::BulkChunk<u32>>::new()
    );
}

proptest! {
    #[test]
    fn chunks_keep_every_entity_once_and_never_grant_before_revoking(
        directions in proptest::collection::vec(any::<bool>(), 0..60),
        size in 1usize..8,
    ) {
        let chunker = BulkChunker::new(size).unwrap();
        let changes: Vec<_> = directions
            .iter()
            .zip(0u32..)
            .map(|(revoke, entity)| {
                change(if *revoke { ChangeDirection::Revoke } else { ChangeDirection::Grant }, entity)
            })
            .collect();

        let chunks = chunker.chunk(changes);

        let mut seen_grant = false;
        let mut entities = HashSet::new();
        for chunk in &chunks {
            prop_assert!(!chunk.entities.is_empty() && chunk.entities.len() <= size);
            seen_grant |= chunk.direction == ChangeDirection::Grant;
            prop_assert!(!(seen_grant && chunk.direction == ChangeDirection::Revoke));
            for entity in &chunk.entities {
                prop_assert!(entities.insert(*entity));
            }
        }
        prop_assert_eq!(entities.len(), directions.len());
    }
}

#[test]
fn refuses_a_zero_rate() {
    assert_eq!(
        BulkPacing::new(0).unwrap_err(),
        InvalidBulkChunking::RecordsPerSecond
    );
}

#[rstest]
#[case(2_000, 10_000, Duration::from_secs(5))]
#[case(2_000, 1_000, Duration::from_millis(500))]
#[case(3, 1, Duration::from_micros(333_334))]
#[case(2_000, 0, Duration::ZERO)]
fn a_chunk_occupies_the_clock_for_its_share_of_the_rate(
    #[case] rate: u64,
    #[case] records: u64,
    #[case] expected: Duration,
) {
    let pacing = BulkPacing::new(rate).unwrap();

    assert_eq!(pacing.records_per_second(), rate);
    assert_eq!(pacing.duration_of(records), expected);
}

#[test]
fn an_enormous_chunk_saturates_instead_of_overflowing() {
    let pacing = BulkPacing::new(1).unwrap();

    assert_eq!(
        pacing.duration_of(u64::MAX),
        Duration::from_micros(u64::MAX)
    );
}
