//! The health probe of the access log store: the ready endpoint of Loki answers (Story 14.3).

use std::sync::Arc;

use health_check_domain::{Dependency, HealthProbe};
use iam_domain::AccessLogQuery;
use shared_domain::BoxError;

/// Healthy when Loki reports itself ready within the query timeout.
#[derive(Debug)]
pub struct AccessLogStoreProbe {
    store: Arc<dyn AccessLogQuery>,
}

impl AccessLogStoreProbe {
    /// A probe over `store`.
    #[must_use]
    pub fn new(store: Arc<dyn AccessLogQuery>) -> Self {
        Self { store }
    }

    /// Probe logic, kept out of the `#[async_trait]` body so coverage and complexity see it.
    async fn probe(&self) -> Result<(), BoxError> {
        Ok(self.store.ready().await?)
    }
}

#[async_trait::async_trait]
impl HealthProbe for AccessLogStoreProbe {
    fn dependency(&self) -> Dependency {
        Dependency::AccessLogStore
    }

    async fn check(&self) -> Result<(), BoxError> {
        self.probe().await
    }
}

#[cfg(test)]
mod tests;
