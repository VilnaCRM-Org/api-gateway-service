//! The operations of an `OpenAPI` document, as far as authorization needs them.

use std::collections::BTreeMap;

use crate::error::InvalidSpec;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;

/// The identity of a REST operation: the method and the normalised path template, which is what
/// the permission key `rest:{service}:{METHOD} {template}` names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RestOperationKey {
    /// The HTTP method.
    pub method: HttpMethod,
    /// The normalised path template.
    pub template: PathTemplate,
}

impl std::fmt::Display for RestOperationKey {
    /// `{METHOD} {template}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.method, self.template)
    }
}

/// What a document says about one operation besides its identity: the `operationId` label and the
/// `x-iam-sensitive` and `x-iam-audit` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestOperationDetails {
    /// The `operationId` of the operation, when the document gives one.
    pub label: Option<String>,
    /// The flags the vendor extensions set.
    pub flags: PermissionFlags,
}

/// One operation of an `OpenAPI` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestOperation {
    /// The HTTP method.
    pub method: HttpMethod,
    /// The normalised path template.
    pub template: PathTemplate,
    /// The `operationId` of the operation, when the document gives one.
    pub label: Option<String>,
    /// The flags the vendor extensions set.
    pub flags: PermissionFlags,
}

/// Distinct operations in key order: at most [`RestOperationSet::MAX_OPERATIONS`], none twice.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestOperationSet(BTreeMap<RestOperationKey, RestOperationDetails>);

impl RestOperationSet {
    /// The largest number of operations of a document (FR-34).
    pub const MAX_OPERATIONS: usize = 5_000;

    /// A set without operations.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Adds an operation.
    ///
    /// # Errors
    ///
    /// [`InvalidSpec::DuplicateOperation`] when an operation with the same method and template is
    /// present and [`InvalidSpec::TooManyOperations`] past [`Self::MAX_OPERATIONS`]; the set is
    /// unchanged then.
    pub fn insert(&mut self, operation: RestOperation) -> Result<(), InvalidSpec> {
        let key = RestOperationKey {
            method: operation.method,
            template: operation.template,
        };
        if self.0.contains_key(&key) {
            return Err(InvalidSpec::DuplicateOperation {
                key: key.to_string(),
            });
        }
        if self.0.len() >= Self::MAX_OPERATIONS {
            return Err(InvalidSpec::TooManyOperations {
                limit: Self::MAX_OPERATIONS,
            });
        }
        self.0.insert(
            key,
            RestOperationDetails {
                label: operation.label,
                flags: operation.flags,
            },
        );
        Ok(())
    }

    /// The details of the operation with the method and the template.
    #[must_use]
    pub fn get(
        &self,
        method: HttpMethod,
        template: &PathTemplate,
    ) -> Option<&RestOperationDetails> {
        self.0.get(&RestOperationKey {
            method,
            template: template.clone(),
        })
    }

    /// The details of the operation with the key.
    #[must_use]
    pub fn get_key(&self, key: &RestOperationKey) -> Option<&RestOperationDetails> {
        self.0.get(key)
    }

    /// Whether the set holds the operation with the key.
    #[must_use]
    pub fn contains(&self, key: &RestOperationKey) -> bool {
        self.0.contains_key(key)
    }

    /// The union of both sets: an operation of both keeps the label of this set and the more
    /// restrictive flags. The union of the active versions of a service is not bound by
    /// [`Self::MAX_OPERATIONS`], which limits one document.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut union = self.clone();
        for (key, details) in &other.0 {
            union
                .0
                .entry(key.clone())
                .and_modify(|stored| stored.flags = stored.flags.most_restrictive(details.flags))
                .or_insert_with(|| details.clone());
        }
        union
    }

    /// The number of operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no operation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The operations with their details, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&RestOperationKey, &RestOperationDetails)> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests;
