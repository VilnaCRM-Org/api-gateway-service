use iam_domain::{AccessLogQuery as _, AccessLogQueryError};

use super::FakeAccessLogQuery;

#[tokio::test]
async fn a_store_is_ready_unless_it_was_made_to_fail() {
    assert_eq!(
        FakeAccessLogQuery::holding(Vec::new()).ready().await,
        Ok(())
    );
    assert_eq!(
        FakeAccessLogQuery::failing(AccessLogQueryError::Timeout)
            .ready()
            .await,
        Err(AccessLogQueryError::Timeout)
    );
}
