//! `SpecDiff`: what changes between a candidate GraphQL coordinate set and the active one (FR-31).

use std::collections::BTreeMap;

use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::identifier::RoleId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_grant::PermissionGrant;
use crate::value_object::permission_grant_set::PermissionGrantSet;
use crate::value_object::service_name::ServiceName;
use crate::value_object::wildcard_pattern::WildcardPattern;

/// The grants of one role, as the diff reads them.
#[derive(Debug, Clone, Copy)]
pub struct RoleGrants<'grants> {
    /// The role.
    pub role: RoleId,
    /// Its grants.
    pub grants: &'grants PermissionGrantSet,
}

/// A removed coordinate that roles grant by its exact key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedGrant {
    /// The removed coordinate.
    pub coordinate: GraphQlCoordinate,
    /// The roles that grant its key, in id order.
    pub roles: Vec<RoleId>,
}

/// A wildcard grant of a role that would cover added coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardGain {
    /// The role.
    pub role: RoleId,
    /// The wildcard pattern it grants.
    pub pattern: WildcardPattern,
    /// The added coordinates the pattern would cover, in order; never a sensitive one, since a
    /// wildcard never covers a sensitive key.
    pub coordinates: Vec<GraphQlCoordinate>,
}

/// A coordinate that would lose the sensitive or the always-audit flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagDowngrade {
    /// The coordinate.
    pub coordinate: GraphQlCoordinate,
    /// Its flags in the active set.
    pub before: PermissionFlags,
    /// Its flags in the candidate set.
    pub after: PermissionFlags,
}

/// The difference between a candidate coordinate set and the active one of one service.
///
/// The candidate holds the coordinates that would be in effect, the active set is the union of
/// the active versions.
///
/// The result lists the added and removed coordinates, the removed coordinates that roles grant,
/// the wildcard grants that gain added coordinates and the flag downgrades.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecDiff {
    added: Vec<GraphQlCoordinate>,
    removed: Vec<GraphQlCoordinate>,
    removed_grants: Vec<RemovedGrant>,
    wildcard_gains: Vec<WildcardGain>,
    flag_downgrades: Vec<FlagDowngrade>,
}

impl SpecDiff {
    /// Compares `candidate` with `active` for `service`, reading the grants of `roles`.
    #[must_use]
    pub fn compute(
        service: &ServiceName,
        candidate: &CoordinateSet,
        active: &CoordinateSet,
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

    /// The coordinates of the candidate that the active set lacks, in order.
    #[must_use]
    pub fn added(&self) -> &[GraphQlCoordinate] {
        &self.added
    }

    /// The coordinates of the active set that the candidate lacks, in order.
    #[must_use]
    pub fn removed(&self) -> &[GraphQlCoordinate] {
        &self.removed
    }

    /// The removed coordinates whose exact key a role grants, in coordinate order.
    #[must_use]
    pub fn removed_grants(&self) -> &[RemovedGrant] {
        &self.removed_grants
    }

    /// The wildcard grants that would cover added coordinates, in role then pattern order.
    #[must_use]
    pub fn wildcard_gains(&self) -> &[WildcardGain] {
        &self.wildcard_gains
    }

    /// The coordinates of both sets that would lose a flag, in coordinate order.
    #[must_use]
    pub fn flag_downgrades(&self) -> &[FlagDowngrade] {
        &self.flag_downgrades
    }

    /// Whether nothing changes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.flag_downgrades.is_empty()
    }
}

/// The coordinates of `left` that `right` lacks, in order.
fn missing_from(left: &CoordinateSet, right: &CoordinateSet) -> Vec<GraphQlCoordinate> {
    left.iter()
        .map(|(coordinate, _flags)| coordinate)
        .filter(|coordinate| !right.contains(coordinate))
        .cloned()
        .collect()
}

/// Every removed coordinate that at least one role grants by its exact key, with those roles.
fn removed_grants(
    service: &ServiceName,
    removed: &[GraphQlCoordinate],
    roles: &[RoleGrants<'_>],
) -> Vec<RemovedGrant> {
    let mut granted: BTreeMap<GraphQlCoordinate, Vec<RoleId>> = BTreeMap::new();
    for role in roles {
        for coordinate in exact_coordinates(service, role.grants) {
            granted.entry(coordinate).or_default().push(role.role);
        }
    }
    removed
        .iter()
        .filter_map(|coordinate| {
            let mut roles = granted.remove(coordinate)?;
            roles.sort_unstable();
            roles.dedup();
            Some(RemovedGrant {
                coordinate: coordinate.clone(),
                roles,
            })
        })
        .collect()
}

/// The coordinates of `service` that the grants name by exact key.
fn exact_coordinates<'grants>(
    service: &'grants ServiceName,
    grants: &'grants PermissionGrantSet,
) -> impl Iterator<Item = GraphQlCoordinate> + 'grants {
    grants.iter().filter_map(move |grant| match grant {
        PermissionGrant::Key(key) => GraphQlCoordinate::from_permission_key(key, service),
        PermissionGrant::Wildcard(_) => None,
    })
}

/// Every wildcard grant of a role that would cover at least one added, non-sensitive coordinate.
fn wildcard_gains(
    service: &ServiceName,
    added: &[GraphQlCoordinate],
    candidate: &CoordinateSet,
    roles: &[RoleGrants<'_>],
) -> Vec<WildcardGain> {
    let coverable: Vec<&GraphQlCoordinate> = added
        .iter()
        .filter(|coordinate| {
            !candidate
                .flags(coordinate)
                .is_some_and(PermissionFlags::is_sensitive)
        })
        .collect();
    let mut gains: Vec<WildcardGain> = roles
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
    coverable: &'grants [&GraphQlCoordinate],
    role: RoleGrants<'grants>,
) -> impl Iterator<Item = WildcardGain> + 'grants {
    role.grants.iter().filter_map(move |grant| {
        let PermissionGrant::Wildcard(pattern) = grant else {
            return None;
        };
        let coordinates: Vec<GraphQlCoordinate> = coverable
            .iter()
            .filter(|coordinate| covers(pattern, service, coordinate))
            .map(|coordinate| (*coordinate).clone())
            .collect();
        (!coordinates.is_empty()).then(|| WildcardGain {
            role: role.role,
            pattern: pattern.clone(),
            coordinates,
        })
    })
}

/// Whether a wildcard pattern covers a coordinate of `service`.
fn covers(
    pattern: &WildcardPattern,
    service: &ServiceName,
    coordinate: &GraphQlCoordinate,
) -> bool {
    match pattern {
        WildcardPattern::GqlType {
            service: pattern_service,
            type_name,
        } => pattern_service == service && type_name == coordinate.type_name(),
        WildcardPattern::GqlService {
            service: pattern_service,
        } => pattern_service == service,
        WildcardPattern::RestMethod { .. } | WildcardPattern::RestService { .. } => false,
    }
}

/// The coordinates of both sets whose candidate flags drop a flag of the active set.
fn flag_downgrades(candidate: &CoordinateSet, active: &CoordinateSet) -> Vec<FlagDowngrade> {
    active
        .iter()
        .filter_map(|(coordinate, before)| {
            let after = candidate.flags(coordinate)?;
            loses_a_flag(before, after).then(|| FlagDowngrade {
                coordinate: coordinate.clone(),
                before,
                after,
            })
        })
        .collect()
}

/// Whether `after` drops the sensitive or the always-audit flag of `before`.
const fn loses_a_flag(before: PermissionFlags, after: PermissionFlags) -> bool {
    (before.is_sensitive() && !after.is_sensitive())
        || (before.is_audit_always() && !after.is_audit_always())
}

#[cfg(test)]
mod tests;
