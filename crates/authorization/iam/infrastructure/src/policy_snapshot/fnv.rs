//! The shard of a key: a stable hash, so every pod places a key in the same shard.

use iam_domain::StateKey;

/// The number of shards of the raw state.
pub(super) const SHARD_COUNT: usize = 4_096;

const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const PRIME: u64 = 0x0100_0000_01b3;

/// The shard that holds `key`.
pub(super) fn shard_of(key: &StateKey) -> usize {
    let hash = key.to_string().bytes().fold(OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    });
    let count = u64::try_from(SHARD_COUNT).unwrap_or(u64::MAX);
    usize::try_from(hash.checked_rem(count).unwrap_or_default()).unwrap_or_default()
}

#[cfg(test)]
mod tests;
