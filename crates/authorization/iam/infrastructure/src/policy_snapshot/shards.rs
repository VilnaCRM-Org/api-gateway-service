//! The raw policy state in copy-on-write shards keyed by `StateKey`.

use std::collections::BTreeMap;
use std::sync::Arc;

use iam_domain::{
    AssignmentState, CompiledRoleSet, PolicyDigestValue, PolicyState, PolicyVersion, StateKey,
};

use super::fnv::{SHARD_COUNT, shard_of};

/// What the builder derives from one entry, kept next to it.
#[derive(Debug, Clone)]
pub(super) enum Derived {
    /// The entry has nothing derived of its own.
    Nothing,
    /// The compiled grants of a role.
    Role(Arc<CompiledRoleSet>),
    /// The interned assignment list of a subject.
    Subject(Arc<[AssignmentState]>),
}

/// One live key: its state, the version it was last changed in and its entity hash.
#[derive(Debug, Clone)]
pub(super) struct Entry {
    pub(super) version: PolicyVersion,
    pub(super) state: PolicyState,
    pub(super) hash: PolicyDigestValue,
    pub(super) derived: Derived,
}

type Shard = BTreeMap<StateKey, Entry>;

/// The 4,096 shards. A shard is cloned when it is written while a published snapshot still holds
/// it, and only then: after that clone the builder holds the only copy until the next publish.
#[derive(Debug, Clone)]
pub(super) struct Shards {
    shards: Vec<Arc<Shard>>,
    copies: usize,
}

impl Shards {
    pub(super) fn new() -> Self {
        Self {
            shards: (0..SHARD_COUNT).map(|_| Arc::new(Shard::new())).collect(),
            copies: 0,
        }
    }

    pub(super) fn get(&self, key: &StateKey) -> Option<&Entry> {
        self.shards.get(shard_of(key))?.get(key)
    }

    pub(super) fn insert(&mut self, key: StateKey, entry: Entry) {
        if let Some(shard) = self.shards.get_mut(shard_of(&key)) {
            if Arc::strong_count(shard) > 1 {
                self.copies = self.copies.saturating_add(1);
            }
            Arc::make_mut(shard).insert(key, entry);
        }
    }

    pub(super) fn remove(&mut self, key: &StateKey) -> Option<Entry> {
        self.get(key)?;
        let shard = self.shards.get_mut(shard_of(key))?;
        if Arc::strong_count(shard) > 1 {
            self.copies = self.copies.saturating_add(1);
        }
        Arc::make_mut(shard).remove(key)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&StateKey, &Entry)> {
        self.shards.iter().flat_map(|shard| shard.iter())
    }

    /// The live entries of the shard at `index`; none for an index outside the range.
    pub(super) fn shard(&self, index: usize) -> impl Iterator<Item = (&StateKey, &Entry)> {
        self.shards
            .get(index)
            .into_iter()
            .flat_map(|shard| shard.iter())
    }

    /// How many shards were cloned since the last call of [`Self::take_copies`].
    #[cfg(test)]
    pub(super) const fn copies(&self) -> usize {
        self.copies
    }

    /// The number of clones since the last call, and a restart of the count.
    pub(super) const fn take_copies(&mut self) -> usize {
        std::mem::replace(&mut self.copies, 0)
    }
}

#[cfg(test)]
mod tests;
