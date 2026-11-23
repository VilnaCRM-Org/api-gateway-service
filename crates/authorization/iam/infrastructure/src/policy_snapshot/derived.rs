//! What is derived from one entry of the raw state: the compiled role sets, the interned
//! assignment lists and the texts that the derived hash counts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use iam_domain::{
    AssignmentState, CompiledRoleSet, GrantStatus, InvalidStateRecord, PermissionGrant,
    PolicyState, RoleId, StateKey,
};

use super::shards::Derived;

/// The interned assignment lists: subjects that hold the same assignments share one list.
#[derive(Debug, Default)]
pub(super) struct Interner {
    lists: BTreeMap<Vec<AssignmentState>, Weak<[AssignmentState]>>,
    pruned_at: usize,
}

/// The size from which dead lists are dropped from the interner.
const PRUNE_FLOOR: usize = 1_024;

impl Interner {
    pub(super) fn intern(&mut self, list: &[AssignmentState]) -> Arc<[AssignmentState]> {
        if let Some(shared) = self.lists.get(list).and_then(Weak::upgrade) {
            return shared;
        }
        let shared: Arc<[AssignmentState]> = Arc::from(list);
        self.lists.insert(list.to_vec(), Arc::downgrade(&shared));
        self.prune();
        shared
    }

    /// The number of distinct lists in use or remembered.
    pub(super) fn len(&self) -> usize {
        self.lists.len()
    }

    fn prune(&mut self) {
        if self.lists.len() < PRUNE_FLOOR || self.lists.len() < self.pruned_at.saturating_mul(2) {
            return;
        }
        self.lists.retain(|_, list| list.strong_count() > 0);
        self.pruned_at = self.lists.len();
    }
}

/// The structure derived from `state`.
pub(super) fn derive(
    state: &PolicyState,
    interner: &mut Interner,
) -> Result<Derived, InvalidStateRecord> {
    match state {
        PolicyState::Role(role) => {
            let grants = role
                .grants
                .iter()
                .map(|grant| {
                    let status = if grant.active {
                        GrantStatus::Active
                    } else {
                        GrantStatus::Orphaned
                    };
                    PermissionGrant::parse(&grant.key).map(|parsed| (parsed, status))
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_error| InvalidStateRecord::Field { field: "grants" })?;
            Ok(Derived::Role(Arc::new(CompiledRoleSet::compile(grants))))
        }
        PolicyState::Subject(subject) => {
            Ok(Derived::Subject(interner.intern(&subject.assignments)))
        }
        PolicyState::Manifest(_)
        | PolicyState::Chunk(_)
        | PolicyState::Upstream(_)
        | PolicyState::Route(_)
        | PolicyState::RatePolicy(_)
        | PolicyState::Head(_) => Ok(Derived::Nothing),
    }
}

/// The distinct roles of an assignment list.
pub(super) fn roles_of(list: &[AssignmentState]) -> BTreeSet<RoleId> {
    list.iter().map(|assignment| assignment.role).collect()
}

/// The texts of the derived items that one entry stands for. The derived hash is the XOR of the
/// hashes of these texts, so adding an entry adds its items and removing it takes them away, in any
/// order.
pub(super) fn items(key: &StateKey, state: &PolicyState, derived: &Derived) -> Vec<String> {
    match (state, derived) {
        (PolicyState::Role(_), Derived::Role(compiled)) => {
            vec![format!("role|{key}|{compiled:?}")]
        }
        (PolicyState::Subject(subject), Derived::Subject(list)) => {
            let mut items = vec![format!("subject|{key}|{list:?}")];
            items.extend(
                roles_of(&subject.assignments)
                    .into_iter()
                    .map(|role| format!("reverse|{role}|{key}")),
            );
            items
        }
        (PolicyState::Route(route), _) => vec![format!(
            "route|{}|{}|{:?}|{}",
            route.fields.host(),
            route.id,
            route.fields.methods(),
            route.fields.path_pattern().as_str()
        )],
        (PolicyState::Upstream(upstream), _) => {
            vec![format!("upstream|{}|{}", upstream.id, upstream.name)]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
