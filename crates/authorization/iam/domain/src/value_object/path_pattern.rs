//! The path pattern of a route: literal segments, `{name}` parameters and a final `{name:*}`
//! catch-all.

use crate::error::InvalidRoute;

/// One segment of a path pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathSegment {
    /// A fixed segment.
    Literal(String),
    /// `{name}`: any one segment.
    Parameter(String),
    /// `{name:*}`: one or more remaining segments; only the last segment can be one.
    CatchAll(String),
}

impl PathSegment {
    /// Whether the two segments have the same kind and, for literals, the same text; parameter
    /// names are not part of the shape.
    #[must_use]
    pub fn same_shape(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Literal(left), Self::Literal(right)) => left == right,
            (Self::Parameter(_), Self::Parameter(_)) | (Self::CatchAll(_), Self::CatchAll(_)) => {
                true
            }
            _ => false,
        }
    }

    /// Whether this single segment matches every segment that `other` matches; `None` is a
    /// missing segment, which nothing matches.
    fn covers(&self, other: Option<&Self>) -> bool {
        match (self, other) {
            (Self::Literal(left), Some(Self::Literal(right))) => left == right,
            (Self::Parameter(_), Some(Self::Literal(_) | Self::Parameter(_))) => true,
            _ => false,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        let Some(inner) = value
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        else {
            return is_literal(value).then(|| Self::Literal(value.to_owned()));
        };
        inner.strip_suffix(":*").map_or_else(
            || is_name(inner).then(|| Self::Parameter(inner.to_owned())),
            |name| is_name(name).then(|| Self::CatchAll(name.to_owned())),
        )
    }
}

/// A route path pattern such as `/api/orders/{id}` or `/api/{rest:*}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathPattern {
    text: String,
    segments: Vec<PathSegment>,
}

impl PathPattern {
    /// The largest number of characters of a pattern.
    pub const MAX_LENGTH: usize = 2_048;

    /// Parses the pattern.
    ///
    /// # Errors
    ///
    /// [`InvalidRoute::PathPrefix`] when the pattern does not start with `/` and
    /// [`InvalidRoute::PathFormat`] when it is too long, holds an empty segment (a double or a
    /// trailing slash), a malformed segment or a catch-all that is not the last segment.
    pub fn new(value: &str) -> Result<Self, InvalidRoute> {
        let rest = value.strip_prefix('/').ok_or(InvalidRoute::PathPrefix)?;
        if value.len() > Self::MAX_LENGTH {
            return Err(InvalidRoute::PathFormat);
        }
        let segments = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split('/')
                .map(PathSegment::parse)
                .collect::<Option<Vec<_>>>()
                .ok_or(InvalidRoute::PathFormat)?
        };
        let catch_all_inside = segments
            .iter()
            .rev()
            .skip(1)
            .any(|segment| matches!(segment, PathSegment::CatchAll(_)));
        if catch_all_inside {
            return Err(InvalidRoute::PathFormat);
        }
        Ok(Self {
            text: value.to_owned(),
            segments,
        })
    }

    /// The pattern as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The segments, in order; none for the root `/`.
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// Whether the two patterns have the same shape: the same number of segments, the same
    /// literals and parameters and catch-alls in the same places, whatever the parameter names.
    #[must_use]
    pub fn same_shape(&self, other: &Self) -> bool {
        self.segments.len() == other.segments.len()
            && self
                .segments
                .iter()
                .zip(&other.segments)
                .all(|(left, right)| left.same_shape(right))
    }

    /// Whether every path that `other` matches is also matched by this pattern.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        let mut theirs = other.segments.iter();
        for mine in &self.segments {
            let next = theirs.next();
            if matches!(mine, PathSegment::CatchAll(_)) {
                return next.is_some();
            }
            if !mine.covers(next) {
                return false;
            }
        }
        theirs.next().is_none()
    }

    /// Whether this pattern matches every path that `other` matches and more, through a parameter
    /// or a catch-all segment.
    #[must_use]
    pub fn is_broader_than(&self, other: &Self) -> bool {
        self.covers(other) && !self.same_shape(other)
    }
}

impl std::fmt::Display for PathPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// A non-empty segment of URL path characters without braces.
fn is_literal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'%')
        })
}

/// A parameter name: a lower-case letter followed by lower-case letters, digits and underscores.
fn is_name(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests;
