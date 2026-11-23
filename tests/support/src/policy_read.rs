//! Policy read repository double of the IAM context.

use std::collections::BTreeMap;

use async_trait::async_trait;
use iam_domain::{
    PolicyReadRepository, RepositoryError, ServiceCatalog, ServiceName, SubjectPolicy, SubjectRef,
};

/// What the double answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Holding,
    Failing,
}

/// A policy read repository that answers from memory: the policy of the subjects and the
/// catalogues of the services it holds, and nothing for any other subject or service.
#[derive(Debug)]
pub struct FakePolicyReadRepository {
    mode: Mode,
    subjects: BTreeMap<SubjectRef, SubjectPolicy>,
    catalogs: BTreeMap<ServiceName, ServiceCatalog>,
}

impl FakePolicyReadRepository {
    /// A repository that holds nothing: every subject has no assignment and no service has an
    /// active version.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: Mode::Holding,
            subjects: BTreeMap::new(),
            catalogs: BTreeMap::new(),
        }
    }

    /// A repository whose every read answers `Unavailable`.
    #[must_use]
    pub const fn failing() -> Self {
        Self {
            mode: Mode::Failing,
            subjects: BTreeMap::new(),
            catalogs: BTreeMap::new(),
        }
    }

    /// The same repository that also holds the policy of `subject`.
    #[must_use]
    pub fn with_subject(mut self, subject: SubjectRef, policy: SubjectPolicy) -> Self {
        self.subjects.insert(subject, policy);
        self
    }

    /// The same repository that also holds the catalogue of the service of `catalog`.
    #[must_use]
    pub fn with_catalog(mut self, catalog: ServiceCatalog) -> Self {
        self.catalogs.insert(catalog.service().clone(), catalog);
        self
    }

    fn failure() -> RepositoryError {
        RepositoryError::Unavailable("in-memory repository failure".into())
    }

    fn subject_policy(&self, subject: &SubjectRef) -> Result<SubjectPolicy, RepositoryError> {
        if self.mode == Mode::Failing {
            return Err(Self::failure());
        }
        Ok(self.subjects.get(subject).cloned().unwrap_or_else(|| {
            SubjectPolicy::new(
                crate::policy_epoch::seeded_policy_epoch(),
                Vec::new(),
                BTreeMap::new(),
            )
        }))
    }

    fn service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        if self.mode == Mode::Failing {
            return Err(Self::failure());
        }
        Ok(self.catalogs.get(service).cloned())
    }
}

impl Default for FakePolicyReadRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PolicyReadRepository for FakePolicyReadRepository {
    async fn read_subject_policy(
        &self,
        subject: &SubjectRef,
    ) -> Result<SubjectPolicy, RepositoryError> {
        self.subject_policy(subject)
    }

    async fn read_service_catalog(
        &self,
        service: &ServiceName,
    ) -> Result<Option<ServiceCatalog>, RepositoryError> {
        self.service_catalog(service)
    }
}

#[cfg(test)]
mod tests;
