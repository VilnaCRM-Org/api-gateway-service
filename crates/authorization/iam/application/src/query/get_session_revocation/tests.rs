use std::sync::Arc;

use iam_domain::{RevocationRepository, SessionRevocationId};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::revocation::FakeRevocationRepository;

use super::{GetSessionRevocationQuery, GetSessionRevocationQueryHandler};
use crate::error::IamError;
use crate::revocation_read_fixtures::{revocation, uuid};

fn handler_over(repository: &Arc<FakeRevocationRepository>) -> GetSessionRevocationQueryHandler {
    let port: Arc<dyn RevocationRepository> = Arc::<FakeRevocationRepository>::clone(repository);
    GetSessionRevocationQueryHandler::new(port)
}

fn query(n: u64) -> GetSessionRevocationQuery {
    GetSessionRevocationQuery {
        id: SessionRevocationId::from_uuid(uuid(n)),
    }
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetSessionRevocationQuery::NAME, "GetSessionRevocationQuery");
}

#[tokio::test]
async fn a_stored_revocation_is_answered_with_its_source_and_actor() {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository.revoke_session(&revocation(1)).await.unwrap();

    let answer = handler_over(&repository).handle(query(1)).await.unwrap();

    assert_eq!(answer, Some(revocation(1)));
}

#[tokio::test]
async fn an_unknown_revocation_is_none() {
    let repository = Arc::new(FakeRevocationRepository::new());

    let answer = handler_over(&repository).handle(query(9)).await.unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository.fail(true);

    let error = handler_over(&repository)
        .handle(query(1))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
