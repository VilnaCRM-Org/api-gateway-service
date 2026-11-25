use std::sync::Arc;

use health_check_domain::{Dependency, HealthProbe as _};
use iam_domain::{AccessLogEntry, AccessLogQuery, AccessLogQueryError, AccessLogSearch};
use shared_domain::Uuid;

use super::AccessLogStoreProbe;

/// A store whose ready endpoint answers what a test scripted.
#[derive(Debug)]
struct ScriptedStore(Result<(), AccessLogQueryError>);

#[async_trait::async_trait]
impl AccessLogQuery for ScriptedStore {
    async fn search(
        &self,
        _search: &AccessLogSearch,
    ) -> Result<Vec<AccessLogEntry>, AccessLogQueryError> {
        Ok(Vec::new())
    }

    async fn find(&self, _id: Uuid) -> Result<Option<AccessLogEntry>, AccessLogQueryError> {
        Ok(None)
    }

    async fn ready(&self) -> Result<(), AccessLogQueryError> {
        self.0
    }
}

fn probe(ready: Result<(), AccessLogQueryError>) -> AccessLogStoreProbe {
    AccessLogStoreProbe::new(Arc::new(ScriptedStore(ready)))
}

#[test]
fn the_probe_reports_the_access_log_store() {
    assert_eq!(probe(Ok(())).dependency(), Dependency::AccessLogStore);
}

#[tokio::test]
async fn a_ready_store_is_healthy() {
    assert!(probe(Ok(())).check().await.is_ok());
}

#[tokio::test]
async fn a_store_that_is_not_ready_is_unhealthy_and_says_why() {
    let error = probe(Err(AccessLogQueryError::Unavailable))
        .check()
        .await
        .unwrap_err();

    assert_eq!(error.to_string(), "the access log store is unavailable");
}

#[tokio::test]
async fn a_store_that_does_not_answer_in_time_is_unhealthy() {
    let error = probe(Err(AccessLogQueryError::Timeout))
        .check()
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "the access log store did not answer in time"
    );
}
