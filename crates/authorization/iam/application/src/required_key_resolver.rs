//! Turns an access check into the keys it requires, against the catalogue of its service (FR-6,
//! FR-7, FR-9).

use std::borrow::Cow;

use iam_domain::{
    AccessCheck, AccessTarget, CoordinateSet, DecisionReason, DecisionVerdict, DocumentLimits,
    GqlCoordinate, GraphQlDocumentAnalyzer as _, GraphQlTarget, GraphQlTypeGraph, PathNormalizer,
    PermissionCatalogue, PermissionFlags, PermissionKey, PermissionsTarget, RequiredKey,
    RestOperationMatcher, RestOperationSet, RestTarget, ServiceCatalog, ServiceName,
};

use crate::graphql::document_analyzer::AsyncGraphQlDocumentAnalyzer;

/// Resolves the keys a check requires.
///
/// A REST target is normalised and matched against the templates of the active `OpenAPI` versions
/// of the service. Permission keys are parsed and looked up in the catalogue of the service;
/// reserved `iam:` keys are accepted without a catalogue entry. A GraphQL document is analysed
/// against the union of the active GraphQL versions of the service, under the limits of the
/// decision API, and requires the key of every coordinate it selects, plus `__introspection` when
/// it reads the schema.
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
    /// keys that are unknown or belong to another service (the verdict lists them in `denied`); for a
    /// GraphQL document the reason of its refusal: `limits_exceeded` for a document over a limit,
    /// `malformed_operation` for one that cannot be read and `unknown_operation` for a field no
    /// active version has, or for a service without a GraphQL version.
    pub fn resolve(
        check: &AccessCheck,
        catalog: &ServiceCatalog,
    ) -> Result<Vec<RequiredKey>, DecisionVerdict> {
        match check.target() {
            AccessTarget::Rest(target) => Self::resolve_rest(check.service(), target, catalog),
            AccessTarget::Permissions(target) => {
                Self::resolve_permissions(check.service(), target, catalog)
            }
            AccessTarget::GraphQl(target) => {
                Self::resolve_graphql(check.service(), target, catalog)
            }
        }
    }

    fn resolve_graphql(
        service: &ServiceName,
        target: &GraphQlTarget,
        catalog: &ServiceCatalog,
    ) -> Result<Vec<RequiredKey>, DecisionVerdict> {
        let graph = active_graph(catalog.type_graphs())
            .ok_or_else(|| deny(DecisionReason::UnknownOperation, Vec::new()))?;
        let analyzed = AsyncGraphQlDocumentAnalyzer
            .analyze(
                target.document(),
                target.operation_name(),
                &graph,
                &DocumentLimits::decision_api(),
            )
            .map_err(|refusal| deny(refusal.reason(), Vec::new()))?;
        let mut required: Vec<RequiredKey> = analyzed
            .coordinates()
            .iter()
            .map(|(coordinate, flags)| RequiredKey::new(coordinate.permission_key(service), flags))
            .collect();
        if analyzed.introspection() {
            let key = PermissionKey::Gql {
                service: service.clone(),
                coordinate: GqlCoordinate::Introspection,
            };
            required.push(RequiredKey::new(key, PermissionFlags::NONE));
        }
        Ok(required)
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

/// The graph a document is read against: the only active version, or the union of several;
/// `None` for a service without a GraphQL version.
fn active_graph(graphs: &[GraphQlTypeGraph]) -> Option<Cow<'_, GraphQlTypeGraph>> {
    let mut versions = graphs.iter();
    let first = versions.next()?;
    Some(versions.fold(Cow::Borrowed(first), |merged, version| {
        Cow::Owned(merged.union(version))
    }))
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
