//! Turns an access check into the keys it requires, against the catalogue of its service (FR-6,
//! FR-7, FR-9).

use iam_domain::{
    AccessCheck, AccessTarget, CoordinateSet, DecisionReason, DecisionVerdict, GraphQlTypeGraph,
    PathNormalizer, PermissionCatalogue, PermissionFlags, PermissionKey, PermissionsTarget,
    RequiredKey, RestOperationMatcher, RestOperationSet, RestTarget, ServiceCatalog, ServiceName,
};

/// Resolves the keys a check requires.
///
/// A REST target is normalised and matched against the templates of the active `OpenAPI` versions
/// of the service. Permission keys are parsed and looked up in the catalogue of the service;
/// reserved `iam:` keys are accepted without a catalogue entry. The GraphQL branch follows in
/// Story 6.7; until then a GraphQL target is refused as `unavailable`, which fails closed.
///
/// A check that cannot be resolved is a verdict, never an error: the `Err` side holds the deny.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequiredKeyResolver;

impl RequiredKeyResolver {
    /// The required keys of `check`, with their catalogue flags.
    ///
    /// # Errors
    ///
    /// The deny verdict of a check that cannot be resolved: `malformed_operation` for a path that
    /// breaks the path rules, `unknown_operation` for a path no template matches or for permission
    /// keys that are unknown or belong to another service (the verdict lists them in `denied`) and
    /// `unavailable` for a GraphQL target.
    pub fn resolve(
        check: &AccessCheck,
        catalog: &ServiceCatalog,
    ) -> Result<Vec<RequiredKey>, DecisionVerdict> {
        match check.target() {
            AccessTarget::Rest(target) => Self::resolve_rest(check.service(), target, catalog),
            AccessTarget::Permissions(target) => {
                Self::resolve_permissions(check.service(), target, catalog)
            }
            AccessTarget::GraphQl(_) => Err(deny(DecisionReason::Unavailable, Vec::new())),
        }
    }

    fn resolve_rest(
        service: &ServiceName,
        target: &RestTarget,
        catalog: &ServiceCatalog,
    ) -> Result<Vec<RequiredKey>, DecisionVerdict> {
        let path = PathNormalizer::normalize(target.path())
            .map_err(|error| deny(error.into(), Vec::new()))?;
        let templates = catalog
            .rest_operations()
            .iter()
            .flat_map(RestOperationSet::iter)
            .filter(|(operation, _)| operation.method == target.method())
            .map(|(operation, _)| &operation.template);
        let key = RestOperationMatcher::match_operation(service, target.method(), &path, templates)
            .map_err(|error| deny(error.into(), Vec::new()))?;
        let flags = rest_flags(service, catalog, &key);
        Ok(vec![RequiredKey::new(key, flags)])
    }

    fn resolve_permissions(
        service: &ServiceName,
        target: &PermissionsTarget,
        catalog: &ServiceCatalog,
    ) -> Result<Vec<RequiredKey>, DecisionVerdict> {
        let rest = PermissionCatalogue::for_rest(service, catalog.rest_operations());
        let coordinates: Vec<CoordinateSet> = catalog
            .type_graphs()
            .iter()
            .map(GraphQlTypeGraph::coordinates)
            .collect();
        let graphql = PermissionCatalogue::for_graphql(service, &coordinates);
        let mut required = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        for raw in target.keys() {
            match lookup(raw, &rest, &graphql) {
                Some(key) => required.push(key),
                None => push_unique(&mut unknown, raw),
            }
        }
        if unknown.is_empty() {
            Ok(required)
        } else {
            Err(deny(DecisionReason::UnknownOperation, unknown))
        }
    }
}

/// The key `raw` names with its flags; `None` when it is not a key, or not one of the catalogues.
fn lookup(
    raw: &str,
    rest: &PermissionCatalogue,
    graphql: &PermissionCatalogue,
) -> Option<RequiredKey> {
    let key = PermissionKey::parse(raw).ok()?;
    let flags = match &key {
        PermissionKey::Reserved(_) => Some(PermissionFlags::NONE),
        PermissionKey::Rest { .. } => rest.flags(&key),
        PermissionKey::Gql { .. } => graphql.flags(&key),
    }?;
    Some(RequiredKey::new(key, flags))
}

/// The flags of a matched REST key: the most restrictive combination over the active versions.
///
/// The matcher builds the key from a template of the same catalogue, so exactly one entry of the
/// catalogue carries it; folding over the entries keeps the flags without an unreachable branch.
fn rest_flags(
    service: &ServiceName,
    catalog: &ServiceCatalog,
    key: &PermissionKey,
) -> PermissionFlags {
    PermissionCatalogue::for_rest(service, catalog.rest_operations())
        .iter()
        .filter(|(known, _)| *known == key)
        .fold(PermissionFlags::NONE, |merged, (_, flags)| {
            merged.most_restrictive(flags)
        })
}

fn push_unique(keys: &mut Vec<String>, raw: &str) {
    if !keys.iter().any(|known| known == raw) {
        keys.push(raw.to_owned());
    }
}

const fn deny(reason: DecisionReason, denied: Vec<String>) -> DecisionVerdict {
    DecisionVerdict::deny(reason, denied)
}

#[cfg(test)]
mod tests;
