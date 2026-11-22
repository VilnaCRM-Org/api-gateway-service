//! The flags of a catalogue entry.

/// Whether a key is sensitive (never covered by a wildcard) and whether every check of it is
/// audited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PermissionFlags {
    sensitive: bool,
    audit_always: bool,
}

impl PermissionFlags {
    /// No flag set.
    pub const NONE: Self = Self {
        sensitive: false,
        audit_always: false,
    };

    /// These flags with `sensitive` set.
    #[must_use]
    pub const fn with_sensitive(self) -> Self {
        Self {
            sensitive: true,
            ..self
        }
    }

    /// These flags with `audit-always` set.
    #[must_use]
    pub const fn with_audit_always(self) -> Self {
        Self {
            audit_always: true,
            ..self
        }
    }

    /// Whether the key is sensitive.
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        self.sensitive
    }

    /// Whether every check of the key is audited.
    #[must_use]
    pub const fn is_audit_always(self) -> bool {
        self.audit_always
    }

    /// The most restrictive combination of two values: a flag set on either side stays set.
    #[must_use]
    pub const fn most_restrictive(self, other: Self) -> Self {
        Self {
            sensitive: self.sensitive || other.sensitive,
            audit_always: self.audit_always || other.audit_always,
        }
    }

    /// Whether `after` drops a flag that these flags set: the sensitive or the always-audit flag.
    #[must_use]
    pub const fn is_downgraded_by(self, after: Self) -> bool {
        (self.sensitive && !after.sensitive) || (self.audit_always && !after.audit_always)
    }
}

#[cfg(test)]
mod tests;
