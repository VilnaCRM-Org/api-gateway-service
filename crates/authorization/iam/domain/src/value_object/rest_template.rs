//! The path template of a REST permission key.

/// A path template with anonymous parameters, such as `/api/projects/{}/members`: a leading `/`,
/// visible ASCII only, no `*`, every `{` immediately closed by `}`, at most 2,048 bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RestTemplate(String);

impl RestTemplate {
    /// The largest number of bytes of a template.
    pub const MAX_LENGTH: usize = 2_048;

    /// Validates the template; `None` when it breaks a rule.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let valid = value.starts_with('/')
            && value.len() <= Self::MAX_LENGTH
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'*')
            && !value.replace("{}", "").contains(['{', '}']);
        valid.then(|| Self(value.to_owned()))
    }

    /// The template.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RestTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests;
