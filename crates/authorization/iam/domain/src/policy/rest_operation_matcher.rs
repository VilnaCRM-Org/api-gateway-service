//! Matching of a normalised path against the templates of a service (FR-7).

use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::normalized_path::NormalizedPath;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_key::PermissionKey;
use crate::value_object::service_name::ServiceName;

/// No template of the service matches the path; the reason code `unknown_operation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("No operation of the service matches the path.")]
pub struct UnknownOperation;

impl From<UnknownOperation> for DecisionReason {
    /// An unmatched path is the reason code `unknown_operation`.
    fn from(_: UnknownOperation) -> Self {
        Self::UnknownOperation
    }
}

/// How specifically a segment pattern matches: a literal beats a pattern with a `{}` inside text,
/// which beats a bare `{}`.
const LITERAL: u8 = 0;
const EMBEDDED_PARAMETER: u8 = 1;
const BARE_PARAMETER: u8 = 2;

/// Finds the template of a service that a path belongs to and names its permission key.
///
/// A literal segment wins over a parameter at the first segment where two matching templates
/// differ, so `/api/roles/batch` is never taken for `/api/roles/{}`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestOperationMatcher;

impl RestOperationMatcher {
    /// The key `rest:{service}:{METHOD} {template}` of the most specific template that matches.
    ///
    /// # Errors
    ///
    /// [`UnknownOperation`] when no template matches.
    pub fn match_operation<'a, T>(
        service: &ServiceName,
        method: HttpMethod,
        path: &NormalizedPath,
        templates: T,
    ) -> Result<PermissionKey, UnknownOperation>
    where
        T: IntoIterator<Item = &'a PathTemplate>,
    {
        templates
            .into_iter()
            .filter_map(|template| specificity(template, path).map(|rank| (rank, template)))
            .min()
            .map(|(_, template)| PermissionKey::Rest {
                service: service.clone(),
                method,
                template: template.as_rest_template().clone(),
            })
            .ok_or(UnknownOperation)
    }
}

/// The per-segment ranks of a matching template, `None` when the template does not match.
fn specificity(template: &PathTemplate, path: &NormalizedPath) -> Option<Vec<u8>> {
    let patterns: Vec<&str> = template
        .as_str()
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if patterns.len() != path.segments().len() {
        return None;
    }
    patterns
        .into_iter()
        .zip(path.segments())
        .map(|(pattern, segment)| segment_rank(pattern, segment))
        .collect()
}

fn segment_rank(pattern: &str, segment: &str) -> Option<u8> {
    if pattern == "{}" {
        Some(BARE_PARAMETER)
    } else if pattern.contains("{}") {
        matches_embedded(pattern, segment).then_some(EMBEDDED_PARAMETER)
    } else {
        (pattern == segment).then_some(LITERAL)
    }
}

/// Whether `text` fits a pattern such as `{}.json` or `v{}-{}`: the literal parts in order, each
/// `{}` standing for at least one character.
fn matches_embedded(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split("{}");
    let prefix = parts.next().unwrap_or_default();
    let rest: Vec<&str> = parts.collect();
    text.strip_prefix(prefix).is_some_and(|remainder| {
        rest.split_first()
            .is_some_and(|(literal, tail)| consume(remainder, literal, tail))
    })
}

/// `text` starts with a parameter that is followed by `literal` and then by the parts of `tail`.
fn consume(text: &str, literal: &str, tail: &[&str]) -> bool {
    let Some((next, after)) = tail.split_first() else {
        return text.len() > literal.len() && text.ends_with(literal);
    };
    text.match_indices(literal).any(|(at, _)| {
        at > 0
            && text
                .get(at.saturating_add(literal.len())..)
                .is_some_and(|rest| consume(rest, next, after))
    })
}

#[cfg(test)]
mod tests;
