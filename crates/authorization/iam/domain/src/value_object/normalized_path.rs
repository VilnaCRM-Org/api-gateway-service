//! The path of a request after normalisation.

use crate::value_object::canonical_path::CanonicalPath;

/// The decoded segments of a request path: no empty segment, no `.` or `..` segment, and no
/// segment holding `/`, `\`, `%` or a control character. A path without segments is the root.
///
/// Only [`PathNormalizer`](crate::policy::path_normalizer::PathNormalizer) builds one, so every
/// value has been decoded exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NormalizedPath(Vec<String>);

impl NormalizedPath {
    pub(crate) const fn from_segments(segments: Vec<String>) -> Self {
        Self(segments)
    }

    /// The decoded segments in order.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    /// The re-encoded form that the gateway forwards.
    #[must_use]
    pub fn canonical(&self) -> CanonicalPath {
        CanonicalPath::encode(&self.0)
    }
}

impl std::fmt::Display for NormalizedPath {
    /// `/` followed by the segments joined with `/`, decoded.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("/");
        }
        for segment in &self.0 {
            f.write_str("/")?;
            f.write_str(segment)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
