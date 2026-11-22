//! The normalised path template of an `OpenAPI` operation.

use crate::value_object::rest_template::RestTemplate;

/// The path of an `OpenAPI` operation as a permission key names it.
///
/// Parameter names are replaced by `{}` (`/projects/{id}/members` becomes `/projects/{}/members`)
/// and no trailing slash remains, so two paths that differ only in parameter names or a trailing
/// slash are the same template.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathTemplate(RestTemplate);

impl PathTemplate {
    /// Normalises a path of the `paths` object of an `OpenAPI` document; `None` when the path does
    /// not start with `/`, has an unclosed, nested or unnamed `{}` parameter, or breaks a rule of
    /// [`RestTemplate`].
    #[must_use]
    pub fn from_openapi_path(path: &str) -> Option<Self> {
        if !path.starts_with('/') {
            return None;
        }
        let anonymous = anonymise_parameters(path)?;
        let trimmed = anonymous.trim_end_matches('/');
        let template = if trimmed.is_empty() { "/" } else { trimmed };
        RestTemplate::parse(template).map(Self)
    }

    /// Restores a template that the storage holds; `None` unless the text is exactly what
    /// [`Self::from_openapi_path`] would produce, that is, normalised already.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        Self::from_openapi_path(&value.replace("{}", "{p}"))
            .filter(|template| template.as_str() == value)
    }

    /// The template.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The template as the value object of a permission key.
    #[must_use]
    pub const fn as_rest_template(&self) -> &RestTemplate {
        &self.0
    }
}

/// Replaces every `{name}` with `{}`; `None` for an unclosed, empty or nested parameter.
fn anonymise_parameters(path: &str) -> Option<String> {
    let mut anonymous = String::with_capacity(path.len());
    let mut rest = path;
    while let Some((head, tail)) = rest.split_once('{') {
        let (name, after) = tail.split_once('}')?;
        if name.is_empty() || name.contains('{') {
            return None;
        }
        anonymous.push_str(head);
        anonymous.push_str("{}");
        rest = after;
    }
    anonymous.push_str(rest);
    Some(anonymous)
}

impl std::fmt::Display for PathTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
