use std::sync::Arc;

use iam_domain::RevocationRepository;
use shared_domain::{Query as _, QueryHandler as _};
use test_support::revocation::FakeRevocationRepository;

use super::{GetGlobalTokenCutoffQuery, GetGlobalTokenCutoffQueryHandler};
use crate::error::IamError;
use crate::revocation_read_fixtures::global_cutoff;

fn handler_over(repository: &Arc<FakeRevocationRepository>) -> GetGlobalTokenCutoffQueryHandler {
    let port: Arc<dyn RevocationRepository> = Arc::<FakeRevocationRepository>::clone(repository);
    GetGlobalTokenCutoffQueryHandler::new(port)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetGlobalTokenCutoffQuery::NAME, "GetGlobalTokenCutoffQuery");
}

#[tokio::test]
async fn the_cutoff_is_answered_with_its_instant_and_actor() {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository
        .set_global_cutoff(&global_cutoff())
        .await
        .unwrap();

    let answer = handler_over(&repository)
        .handle(GetGlobalTokenCutoffQuery)
        .await
        .unwrap();

    assert_eq!(answer, Some(global_cutoff()));
}

#[tokio::test]
async fn a_cutoff_that_was_never_set_is_none() {
    let repository = Arc::new(FakeRevocationRepository::new());

    let answer = handler_over(&repository)
        .handle(GetGlobalTokenCutoffQuery)
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let repository = Arc::new(FakeRevocationRepository::new());
    repository.fail(true);

    let error = handler_over(&repository)
        .handle(GetGlobalTokenCutoffQuery)
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
