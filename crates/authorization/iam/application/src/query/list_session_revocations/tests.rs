use std::sync::Arc;

use iam_domain::{RevocationRepository, RevocationSource, SessionRevocationId};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::revocation::FakeRevocationRepository;

use super::{
    ListSessionRevocationsQuery, ListSessionRevocationsQueryHandler, MAX_PAGE_SIZE,
    SessionRevocationPage,
};
use crate::error::IamError;
use crate::revocation_read_fixtures::{at, revocation, user, uuid};

async fn repository_with(count: u64) -> Arc<FakeRevocationRepository> {
    let repository = Arc::new(FakeRevocationRepository::new());
    for n in 1..=count {
        repository.revoke_session(&revocation(n)).await.unwrap();
    }
    repository
}

fn handler_over(repository: &Arc<FakeRevocationRepository>) -> ListSessionRevocationsQueryHandler {
    let port: Arc<dyn RevocationRepository> = Arc::<FakeRevocationRepository>::clone(repository);
    ListSessionRevocationsQueryHandler::new(port)
}

fn query(limit: u32) -> ListSessionRevocationsQuery {
    ListSessionRevocationsQuery {
        limit,
        after: None,
        user: None,
        source: None,
        from: None,
        until: None,
    }
}

fn numbers(page: &SessionRevocationPage) -> Vec<String> {
    page.revocations
        .iter()
        .map(|record| record.id.to_string())
        .collect()
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(
        ListSessionRevocationsQuery::NAME,
        "ListSessionRevocationsQuery"
    );
}

#[tokio::test]
async fn the_newest_revocation_comes_first_and_a_short_page_has_no_cursor() {
    let repository = repository_with(3).await;

    let page = handler_over(&repository).handle(query(10)).await.unwrap();

    assert_eq!(
        numbers(&page),
        vec![
            uuid(3).to_string(),
            uuid(2).to_string(),
            uuid(1).to_string()
        ]
    );
    assert_eq!(page.next_after, None);
}

#[tokio::test]
async fn a_full_page_names_its_last_revocation_as_the_cursor_and_the_next_page_follows_it() {
    let repository = repository_with(5).await;
    let handler = handler_over(&repository);

    let first = handler.handle(query(2)).await.unwrap();
    let second = handler
        .handle(ListSessionRevocationsQuery {
            after: first.next_after,
            ..query(2)
        })
        .await
        .unwrap();
    let third = handler
        .handle(ListSessionRevocationsQuery {
            after: second.next_after,
            ..query(2)
        })
        .await
        .unwrap();

    assert_eq!(
        first.next_after,
        Some(SessionRevocationId::from_uuid(uuid(4)))
    );
    assert_eq!(
        numbers(&second),
        vec![uuid(3).to_string(), uuid(2).to_string()]
    );
    assert_eq!(numbers(&third), vec![uuid(1).to_string()]);
    assert_eq!(third.next_after, None);
}

#[tokio::test]
async fn the_page_size_is_brought_into_the_allowed_range() {
    let repository = repository_with(3).await;
    let handler = handler_over(&repository);

    let none = handler.handle(query(0)).await.unwrap();
    let huge = handler.handle(query(MAX_PAGE_SIZE + 50)).await.unwrap();

    assert_eq!(none.revocations.len(), 1);
    assert_eq!(huge.revocations.len(), 3);
}

#[tokio::test]
async fn the_filters_keep_the_revocations_that_meet_them() {
    let repository = repository_with(3).await;
    let handler = handler_over(&repository);

    let operator = handler
        .handle(ListSessionRevocationsQuery {
            source: Some(RevocationSource::Operator),
            ..query(10)
        })
        .await
        .unwrap();
    let ranged = handler
        .handle(ListSessionRevocationsQuery {
            from: Some(at(20)),
            until: Some(at(30)),
            ..query(10)
        })
        .await
        .unwrap();
    let of_user = handler
        .handle(ListSessionRevocationsQuery {
            user: Some(user()),
            ..query(10)
        })
        .await
        .unwrap();

    assert_eq!(
        numbers(&operator),
        vec![uuid(3).to_string(), uuid(1).to_string()]
    );
    assert_eq!(numbers(&ranged), vec![uuid(2).to_string()]);
    assert_eq!(of_user.revocations.len(), 3);
}

#[tokio::test]
async fn a_failing_repository_is_a_storage_error() {
    let repository = repository_with(1).await;
    repository.fail(true);

    let error = handler_over(&repository)
        .handle(query(10))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
