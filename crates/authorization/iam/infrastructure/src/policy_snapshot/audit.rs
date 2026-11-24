//! The check of the derived structures against the raw records (FR-74).
//!
//! For one group of shards it rebuilds, from the raw records alone, the texts of the derived items
//! that decisions read, and reads the same texts from the incremental structures: the compiled role
//! sets and the interned assignment lists of the entries, the role-to-subject reverse index and the
//! route tables of the hosts. Each side is folded into one hash per shard, the same way the derived
//! hash of the snapshot is, and the two hashes must be equal.

use std::collections::BTreeMap;

use iam_domain::{
    CHECK_GROUPS, DerivedMismatch, PolicyDigestValue, PolicyState, RouteHost, StateKey, in_group,
};

use super::derived::{Interner, derive, items};
use super::fnv::{SHARD_COUNT, shard_of};
use super::shards::{Derived, Entry};
use super::working::{Applier, Working};

/// The texts of the held items that live in the index structures, by the shard of their key.
type IndexLines = BTreeMap<usize, Vec<String>>;

/// Checks the shards of `group`; how many it checked.
pub(super) fn audit_group(
    applier: &Applier,
    working: &Working,
    group: usize,
) -> Result<usize, DerivedMismatch> {
    let mut indexed = index_lines(working, group);
    let mut checked = 0_usize;
    for shard in (group..SHARD_COUNT).step_by(CHECK_GROUPS) {
        let mut held = indexed.remove(&shard).unwrap_or_default();
        let mut rebuilt = Vec::new();
        for (key, entry) in working.shards.shard(shard) {
            rebuilt.extend(rebuilt_lines(key, entry));
            held.extend(held_lines(key, entry));
        }
        let (rebuilt, held) = (fold(applier, &rebuilt), fold(applier, &held));
        if rebuilt != held {
            return Err(DerivedMismatch {
                shard,
                rebuilt,
                held,
            });
        }
        checked = checked.saturating_add(1);
    }
    Ok(checked)
}

/// The hash of `lines`: the exclusive or of the hashes of the texts, in any order.
fn fold(applier: &Applier, lines: &[String]) -> PolicyDigestValue {
    lines.iter().fold(PolicyDigestValue::ZERO, |hash, line| {
        hash.combined(applier.item_hash(line))
    })
}

/// The texts the raw record of an entry gives when its structure is derived again from scratch.
fn rebuilt_lines(key: &StateKey, entry: &Entry) -> Vec<String> {
    match derive(&entry.state, &mut Interner::default()) {
        Ok(derived) => items(key, &entry.state, &derived),
        Err(_invalid) => vec![format!("invalid|{key}")],
    }
}

/// The texts of the structures an entry holds itself: its compiled role set or assignment list.
/// The reverse index and the route tables are read from their own structures.
fn held_lines(key: &StateKey, entry: &Entry) -> Vec<String> {
    items(key, &entry.state, &entry.derived)
        .into_iter()
        .filter(|line| !line.starts_with("reverse|") && !line.starts_with("route|"))
        .collect()
}

/// The texts of the reverse index and of the route tables, for the shards of `group`.
fn index_lines(working: &Working, group: usize) -> IndexLines {
    let mut lines = IndexLines::new();
    for (role, subjects) in working.role_subjects.iter() {
        for subject in subjects.iter() {
            let key = StateKey::Subject(subject.clone());
            keep(&mut lines, &key, group, format!("reverse|{role}|{key}"));
        }
    }
    for (host, routes) in working.hosts.iter() {
        for id in &routes.ids {
            let key = StateKey::Route(*id);
            let line = listed_route(working, &key, host);
            keep(&mut lines, &key, group, line);
        }
    }
    lines
}

fn keep(lines: &mut IndexLines, key: &StateKey, group: usize, line: String) {
    let shard = shard_of(key);
    if in_group(shard, group) {
        lines.entry(shard).or_default().push(line);
    }
}

/// The text of a route that a host lists: the one its raw record gives when the record is a route
/// of that host, otherwise a text that no raw record gives.
fn listed_route(working: &Working, key: &StateKey, host: &RouteHost) -> String {
    let Some(entry) = working.shards.get(key) else {
        return format!("orphan|{key}");
    };
    let PolicyState::Route(route) = &entry.state else {
        return format!("orphan|{key}");
    };
    if route.fields.host() != host {
        return format!("orphan|{key}");
    }
    items(key, &entry.state, &Derived::Nothing)
        .pop()
        .unwrap_or_default()
}

/// Drops the derived structure of `key`, as a bug of the incremental maintenance would, and moves
/// the derived hash with it. A test hook: it reports whether the key is live.
pub(super) fn corrupt(applier: &Applier, working: &mut Working, key: &StateKey) -> bool {
    let Some(old) = working.shards.remove(key) else {
        return false;
    };
    let corrupted = Entry {
        derived: Derived::Nothing,
        ..old.clone()
    };
    let moved = items(key, &old.state, &old.derived)
        .into_iter()
        .chain(items(key, &corrupted.state, &corrupted.derived));
    for line in moved {
        working.derived_hash = working.derived_hash.combined(applier.item_hash(&line));
    }
    working.shards.insert(key.clone(), corrupted);
    true
}
