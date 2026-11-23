//! `RestSpecDiff`: what changes between a candidate `OpenAPI` operation set and the active one
//! (FR-34, FR-35).

use std::collections::BTreeMap;

use crate::policy::spec_diff::RoleGrants;
use crate::value_object::identifier::RoleId;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::rest_operation_set::{RestOperationKey, RestOperationSet};
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

/// A removed operation that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedRestGrant {
    /// The removed operation.
    pub operation: RestOperationKey,
    /// The roles that grant its key, in id order.
    pub roles: Vec<RoleId>,
}

/// A wildcard grant of a role that would cover added operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestWildcardGain {
    /// The role.
    pub role: RoleId,
    /// The wildcard pattern it grants.
    pub pattern: WildcardPattern,
    /// The added operations the pattern would cover, in order; never a sensitive one, since a
    /// wildcard never covers a sensitive key.
    pub operations: Vec<RestOperationKey>,
}

/// An operation that would lose the sensitive or the always-audit flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestFlagDowngrade {
    /// The operation.
    pub operation: RestOperationKey,
    /// Its flags in the active set.
    pub before: PermissionFlags,
    /// Its flags in the candidate set.
    pub after: PermissionFlags,
}

/// The difference between a candidate operation set and the active one of one service.
///
/// The candidate holds the operations that would be in effect, the active set is the union of the
/// active versions. The result lists the added and removed operations, the removed operations that
/// roles grant, the wildcard grants that gain added operations and the flag downgrades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestSpecDiff {
    added: Vec<RestOperationKey>,
    removed: Vec<RestOperationKey>,
    removed_grants: Vec<RemovedRestGrant>,
    wildcard_gains: Vec<RestWildcardGain>,
    flag_downgrades: Vec<RestFlagDowngrade>,
}

impl RestSpecDiff {
    /// Compares `candidate` with `active` for `service`, reading the grants of `roles`.
    #[must_use]
    pub fn compute(
        service: &ServiceName,
        candidate: &RestOperationSet,
        active: &RestOperationSet,
        roles: &[RoleGrants<'_>],
    ) -> Self {
        let added = missing_from(candidate, active);
        let removed = missing_from(active, candidate);
        let removed_grants = removed_grants(service, &removed, roles);
        let wildcard_gains = wildcard_gains(service, &added, candidate, roles);
        let flag_downgrades = flag_downgrades(candidate, active);
        Self {
            added,
            removed,
            removed_grants,
            wildcard_gains,
            flag_downgrades,
        }
    }

    /// The operations of the candidate that the active set lacks, in order.
    #[must_use]
    pub fn added(&self) -> &[RestOperationKey] {
        &self.added
    }

    /// The operations of the active set that the candidate lacks, in order.
    #[must_use]
    pub fn removed(&self) -> &[RestOperationKey] {
        &self.removed
    }

    /// The removed operations whose exact key a role grants, in operation order.
    #[must_use]
    pub fn removed_grants(&self) -> &[RemovedRestGrant] {
        &self.removed_grants
    }

    /// The wildcard grants that would cover added operations, in role then pattern order.
    #[must_use]
    pub fn wildcard_gains(&self) -> &[RestWildcardGain] {
        &self.wildcard_gains
    }

    /// The operations of both sets that would lose a flag, in operation order.
    #[must_use]
    pub fn flag_downgrades(&self) -> &[RestFlagDowngrade] {
        &self.flag_downgrades
    }

    /// Whether nothing changes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.flag_downgrades.is_empty()
    }
}

/// The operations of `left` that `right` lacks, in order.
fn missing_from(left: &RestOperationSet, right: &RestOperationSet) -> Vec<RestOperationKey> {
    left.iter()
        .map(|(key, _details)| key)
        .filter(|key| !right.contains(key))
        .cloned()
        .collect()
}

/// The operation that an exact REST key of `service` names.
fn operation_of(key: &PermissionKey, service: &ServiceName) -> Option<RestOperationKey> {
    match key {
        PermissionKey::Rest {
            service: key_service,
            method,
            template,
        } if key_service == service => Some(RestOperationKey {
            method: *method,
            template: PathTemplate::from_stored(template.as_str())?,
        }),
        PermissionKey::Rest { .. } | PermissionKey::Gql { .. } | PermissionKey::Reserved(_) => None,
    }
}

/// The operations of `service` that the grants name by exact key.
fn exact_operations<'grants>(
    service: &'grants ServiceName,
    role: RoleGrants<'grants>,
) -> impl Iterator<Item = RestOperationKey> + 'grants {
    role.grants.iter().filter_map(move |grant| match grant {
        PermissionGrant::Key(key) => operation_of(key, service),
        PermissionGrant::Wildcard(_) => None,
    })
}

/// Every removed operation that at least one role grants by its exact key, with those roles.
fn removed_grants(
    service: &ServiceName,
    removed: &[RestOperationKey],
    roles: &[RoleGrants<'_>],
) -> Vec<RemovedRestGrant> {
    let mut granted: BTreeMap<RestOperationKey, Vec<RoleId>> = BTreeMap::new();
    for role in roles {
        for operation in exact_operations(service, *role) {
            granted.entry(operation).or_default().push(role.role);
        }
    }
    removed
        .iter()
        .filter_map(|operation| {
            let mut roles = granted.remove(operation)?;
            roles.sort_unstable();
            roles.dedup();
            Some(RemovedRestGrant {
                operation: operation.clone(),
                roles,
            })
        })
        .collect()
}

/// Every wildcard grant of a role that would cover at least one added, non-sensitive operation.
fn wildcard_gains(
    service: &ServiceName,
    added: &[RestOperationKey],
    candidate: &RestOperationSet,
    roles: &[RoleGrants<'_>],
) -> Vec<RestWildcardGain> {
    let coverable: Vec<&RestOperationKey> = added
        .iter()
        .filter(|operation| {
            !candidate
                .get_key(operation)
                .is_some_and(|details| details.flags.is_sensitive())
        })
        .collect();
    let mut gains: Vec<RestWildcardGain> = roles
        .iter()
        .flat_map(|role| role_gains(service, &coverable, *role))
        .collect();
    gains.sort_by(|left, right| (left.role, &left.pattern).cmp(&(right.role, &right.pattern)));
    gains.dedup();
    gains
}

/// The gains of the wildcard grants of one role.
fn role_gains<'grants>(
    service: &'grants ServiceName,
    coverable: &'grants [&RestOperationKey],
    role: RoleGrants<'grants>,
) -> impl Iterator<Item = RestWildcardGain> + 'grants {
    role.grants.iter().filter_map(move |grant| {
        let PermissionGrant::Wildcard(pattern) = grant else {
            return None;
        };
        let operations: Vec<RestOperationKey> = coverable
            .iter()
            .filter(|operation| covers(pattern, service, operation))
            .map(|operation| (*operation).clone())
            .collect();
        (!operations.is_empty()).then(|| RestWildcardGain {
            role: role.role,
            pattern: pattern.clone(),
            operations,
        })
    })
}

/// Whether a wildcard pattern covers an operation of `service`.
fn covers(pattern: &WildcardPattern, service: &ServiceName, operation: &RestOperationKey) -> bool {
    match pattern {
        WildcardPattern::RestMethod {
            service: pattern_service,
            method,
        } => pattern_service == service && *method == operation.method,
        WildcardPattern::RestService {
            service: pattern_service,
        } => pattern_service == service,
        WildcardPattern::GqlType { .. } | WildcardPattern::GqlService { .. } => false,
    }
}

/// The operations of both sets whose candidate flags drop a flag of the active set.
fn flag_downgrades(
    candidate: &RestOperationSet,
    active: &RestOperationSet,
) -> Vec<RestFlagDowngrade> {
    active
        .iter()
        .filter_map(|(operation, before)| {
            let after = candidate.get_key(operation)?;
            before
                .flags
                .is_downgraded_by(after.flags)
                .then(|| RestFlagDowngrade {
                    operation: operation.clone(),
                    before: before.flags,
                    after: after.flags,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests;
