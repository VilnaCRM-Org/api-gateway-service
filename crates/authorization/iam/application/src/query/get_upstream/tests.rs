use std::sync::Arc;

use iam_domain::{UpstreamId, UpstreamParts, UpstreamRepository};
use shared_domain::{Query as _, QueryHandler as _};
use test_support::upstream::FakeUpstreamRepository;

use super::{GetUpstreamQuery, GetUpstreamQueryHandler};
use crate::error::IamError;
use crate::upstream_fixtures::upstream_named;

fn id(number: u32) -> UpstreamId {
    UpstreamId::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012x}")).unwrap()
}

fn parts(number: u32) -> UpstreamParts {
    upstream_named(id(number), &format!("upstream-{number}"), "core", 1)
}

fn handler(upstreams: FakeUpstreamRepository) -> GetUpstreamQueryHandler {
    let upstreams: Arc<dyn UpstreamRepository> = Arc::new(upstreams);
    GetUpstreamQueryHandler::new(upstreams)
}

#[test]
fn the_query_is_named_after_its_type() {
    assert_eq!(GetUpstreamQuery::NAME, "GetUpstreamQuery");
}

#[tokio::test]
async fn a_stored_upstream_is_answered_with_its_state() {
    let handler = handler(FakeUpstreamRepository::holding(vec![parts(1), parts(2)]));

    let answer = handler
        .handle(GetUpstreamQuery { id: id(2) })
        .await
        .unwrap();

    assert_eq!(answer, Some(parts(2)));
}

#[tokio::test]
async fn an_unknown_upstream_is_answered_with_none() {
    let handler = handler(FakeUpstreamRepository::holding(vec![parts(1)]));

    let answer = handler
        .handle(GetUpstreamQuery { id: id(9) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_deleted_upstream_is_answered_with_none() {
    let mut deleted = parts(1);
    deleted.deleted_at = Some(deleted.created_at);
    let handler = handler(FakeUpstreamRepository::holding(vec![deleted]));

    let answer = handler
        .handle(GetUpstreamQuery { id: id(1) })
        .await
        .unwrap();

    assert_eq!(answer, None);
}

#[tokio::test]
async fn a_storage_failure_is_the_error_of_the_query() {
    let handler = handler(FakeUpstreamRepository::failing());

    let error = handler
        .handle(GetUpstreamQuery { id: id(1) })
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
