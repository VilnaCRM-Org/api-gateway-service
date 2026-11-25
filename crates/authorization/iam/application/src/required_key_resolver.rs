//! Turns an access check into the keys it requires, against the catalogue of its service (FR-6,
//! FR-7, FR-9).

use iam_domain::{
    AccessCheck, AccessTarget, AnalyzedDocument, CoordinateSet, DecisionReason, DecisionVerdict,
    DocumentLimits, DocumentRefusal, GqlCoordinate, GraphQlDocumentAnalyzer as _, GraphQlTarget,
    GraphQlTypeGraph, PathNormalizer, PermissionCatalogue, PermissionFlags, PermissionKey,
    PermissionsTarget, RequiredKey, RestOperationMatcher, RestOperationSet, RestTarget,
    ServiceCatalog, ServiceName,
};

use crate::graphql::document_analyzer::AsyncGraphQlDocumentAnalyzer;

/// Resolves the keys a check requires.
///
/// A REST target is normalised and matched against the templates of the active `OpenAPI` versions
/// of the service. Permission keys are parsed and looked up in the catalogue of the service;
/// reserved `iam:` keys are accepted without a catalogue entry. A GraphQL document is analysed
/// against each active GraphQL version of the service on its own, under the limits of the decision
/// API, and requires the union of the keys of the versions that resolve it: the key of every
/// coordinate it selects, plus `__introspection` when it reads the schema.
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
    /// `malformed_operation` for one that cannot be read and `unknown_operation` when no active
    /// version resolves it, or for a service without a GraphQL version.
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
        let (resolved, refusals) = analyze_versions(target, catalog.type_graphs());
        if resolved.is_empty() {
            return Err(deny(refusal_reason(&refusals), Vec::new()));
        }
        let mut coordinates = CoordinateSet::new();
        for analyzed in &resolved {
            for (coordinate, flags) in analyzed.coordinates().iter() {
                coordinates.insert(coordinate.clone(), flags);
            }
        }
        let mut required: Vec<RequiredKey> = coordinates
            .iter()
            .map(|(coordinate, flags)| RequiredKey::new(coordinate.permission_key(service), flags))
            .collect();
        if resolved.iter().any(AnalyzedDocument::introspection) {
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

/// Analyses the document against each active version on its own: the versions that resolve it
/// and the refusals of the versions that do not. A field one version declares never lends its
/// return type to another version.
pub(crate) fn analyze_versions(
    target: &GraphQlTarget,
    graphs: &[GraphQlTypeGraph],
) -> (Vec<AnalyzedDocument>, Vec<DocumentRefusal>) {
    let limits = DocumentLimits::decision_api();
    let mut resolved = Vec::new();
    let mut refusals = Vec::new();
    for graph in graphs {
        match AsyncGraphQlDocumentAnalyzer.analyze(
            target.document(),
            target.operation_name(),
            graph,
            &limits,
        ) {
            Ok(analyzed) => resolved.push(analyzed),
            Err(refusal) => refusals.push(refusal),
        }
    }
    (resolved, refusals)
}

/// The reason of the deny when no version resolves the document: a limit first, then a field no
/// version has (`unknown_operation`, which also covers a service without a GraphQL version), and
/// `malformed_operation` only when every version finds the document unreadable.
pub(crate) fn refusal_reason(refusals: &[DocumentRefusal]) -> DecisionReason {
    let limits = refusals
        .iter()
        .find(|refusal| matches!(refusal, DocumentRefusal::LimitsExceeded(_)));
    let malformed = !refusals.is_empty()
        && refusals
            .iter()
            .all(|refusal| matches!(refusal, DocumentRefusal::MalformedOperation));
    match limits {
        Some(refusal) => refusal.reason(),
        None if malformed => DecisionReason::MalformedOperation,
        None => DecisionReason::UnknownOperation,
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
