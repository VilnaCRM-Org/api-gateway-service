//! How a bulk change is cut into versions and how fast the versions are committed.
//!
//! Revoke-type chunks come before grant-type chunks, so no intermediate version grants a key that
//! neither the previous state nor the final state grants (FR-84).

use std::time::Duration;

/// The largest number of entities one version may change.
pub const MAX_CHUNK_ENTITIES: usize = 1_000;

/// A chunk size or a rate outside its bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidBulkChunking {
    /// The chunk size is outside 1 to 1,000.
    #[error("This value must be between 1 and 1000.")]
    ChunkEntities,
    /// The record rate is zero.
    #[error("This value must be 1 or greater.")]
    RecordsPerSecond,
}

/// Whether a change takes access away or gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeDirection {
    /// The change removes or narrows access.
    Revoke,
    /// The change adds or widens access.
    Grant,
}

/// One entity change of a bulk change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkChange<T> {
    /// Whether the change revokes or grants.
    pub direction: ChangeDirection,
    /// The changed entity.
    pub entity: T,
}

/// The entities of one version, all of one direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkChunk<T> {
    /// The direction of every entity of the chunk.
    pub direction: ChangeDirection,
    /// The entities, in the order the change listed them.
    pub entities: Vec<T>,
}

/// Cuts a bulk change into chunks of at most `BULK_CHUNK_ENTITIES` entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkChunker {
    chunk_entities: usize,
}

impl BulkChunker {
    /// A chunker with `chunk_entities` entities per chunk.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkChunking::ChunkEntities`] outside 1 to [`MAX_CHUNK_ENTITIES`].
    pub const fn new(chunk_entities: usize) -> Result<Self, InvalidBulkChunking> {
        if chunk_entities == 0 || chunk_entities > MAX_CHUNK_ENTITIES {
            return Err(InvalidBulkChunking::ChunkEntities);
        }
        Ok(Self { chunk_entities })
    }

    /// The entities per chunk.
    #[must_use]
    pub const fn chunk_entities(self) -> usize {
        self.chunk_entities
    }

    /// Whether a change of `entities` entities must take the bulk path.
    #[must_use]
    pub const fn needs_bulk(self, entities: usize) -> bool {
        entities > self.chunk_entities
    }

    /// The chunks of `changes`: every revoke chunk first, then every grant chunk; the order of the
    /// entities of one direction is kept and no chunk is empty.
    #[must_use]
    pub fn chunk<T>(self, changes: Vec<BulkChange<T>>) -> Vec<BulkChunk<T>> {
        let (revokes, grants): (Vec<_>, Vec<_>) = changes
            .into_iter()
            .partition(|change| change.direction == ChangeDirection::Revoke);
        let mut chunks = Vec::new();
        self.split(ChangeDirection::Revoke, revokes, &mut chunks);
        self.split(ChangeDirection::Grant, grants, &mut chunks);
        chunks
    }

    fn split<T>(
        self,
        direction: ChangeDirection,
        changes: Vec<BulkChange<T>>,
        chunks: &mut Vec<BulkChunk<T>>,
    ) {
        let mut remaining = changes.into_iter().map(|change| change.entity);
        loop {
            let entities: Vec<T> = remaining.by_ref().take(self.chunk_entities).collect();
            if entities.is_empty() {
                return;
            }
            chunks.push(BulkChunk {
                direction,
                entities,
            });
        }
    }
}

/// The rate cap `BULK_MAX_RECORDS_PER_SECOND`: how long a chunk of records occupies the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkPacing {
    records_per_second: u64,
}

impl BulkPacing {
    /// A cap of `records_per_second` records per second.
    ///
    /// # Errors
    ///
    /// [`InvalidBulkChunking::RecordsPerSecond`] for zero.
    pub const fn new(records_per_second: u64) -> Result<Self, InvalidBulkChunking> {
        if records_per_second == 0 {
            return Err(InvalidBulkChunking::RecordsPerSecond);
        }
        Ok(Self { records_per_second })
    }

    /// The records per second.
    #[must_use]
    pub const fn records_per_second(self) -> u64 {
        self.records_per_second
    }

    /// The clock time that `records` records must take at the cap, rounded up to a microsecond.
    #[must_use]
    pub fn duration_of(self, records: u64) -> Duration {
        let micros = u128::from(records)
            .saturating_mul(1_000_000)
            .div_ceil(u128::from(self.records_per_second));
        Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests;
