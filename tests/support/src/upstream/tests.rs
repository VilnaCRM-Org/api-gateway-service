use iam_domain::{
    ChangeStatement, RepositoryError, UpstreamName, UpstreamPageQuery, UpstreamRepository as _,
    UpstreamStatement,
};

use super::{FakeUpstreamRepository, upstream, upstream_change};
use crate::block_on;
use crate::seed::TestRng;

fn held(names: &[&str]) -> FakeUpstreamRepository {
    let mut rng = TestRng::from_seed(7);
    FakeUpstreamRepository::holding(
        names
            .iter()
            .map(|name| upstream(&mut rng, name, "core").parts().clone())
            .collect(),
    )
}

#[test]
fn the_fixture_builds_an_upstream_at_version_one_for_the_catalogue_service() {
    let upstream = upstream(&mut TestRng::from_seed(3), "core", "billing");

    assert_eq!(upstream.parts().name.as_str(), "core");
    assert_eq!(
        upstream.parts().settings.catalog_service().as_str(),
        "billing"
    );
    assert_eq!(upstream.parts().settings.service_name(), "core-service");
    assert_eq!(upstream.parts().version.value(), 1);
    assert_eq!(upstream.parts().created_at, upstream.parts().updated_at);
}

#[test]
fn an_upstream_change_runs_one_save_per_statement() {
    let mut rng = TestRng::from_seed(5);
    let upstream = upstream(&mut rng, "core", "core");

    let change = upstream_change(&mut rng, vec![UpstreamStatement::insert(&upstream)]);

    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::from(UpstreamStatement::insert(&upstream))]
    );
}

#[test]
fn an_upstream_is_found_by_its_identifier_and_by_its_name() {
    let repository = held(&["core", "billing"]);
    let name = UpstreamName::new("billing").unwrap();

    let by_name = block_on(repository.find_by_name(&name)).unwrap().unwrap();
    let by_id = block_on(repository.find_by_id(by_name.parts().id))
        .unwrap()
        .unwrap();

    assert_eq!(by_id.parts(), by_name.parts());
    assert!(
        block_on(repository.find_by_name(&UpstreamName::new("other").unwrap()))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_deleted_upstream_is_never_found() {
    let mut rng = TestRng::from_seed(1);
    let mut parts = upstream(&mut rng, "core", "core").parts().clone();
    parts.deleted_at = Some(parts.created_at);
    let repository = FakeUpstreamRepository::holding(vec![parts.clone()]);

    assert!(block_on(repository.find_by_id(parts.id)).unwrap().is_none());
}

#[test]
fn pages_follow_the_order_of_the_identifiers_and_never_repeat_an_upstream() {
    let repository = held(&["a", "b", "c", "d", "e"]);

    let first = block_on(repository.find_page(&UpstreamPageQuery {
        limit: 2,
        after: None,
    }))
    .unwrap();
    let second = block_on(repository.find_page(&UpstreamPageQuery {
        limit: 10,
        after: first.last().map(|upstream| upstream.parts().id),
    }))
    .unwrap();

    assert_eq!(first.len(), 2);
    assert_eq!(second.len(), 3);
    let ids: Vec<_> = first.iter().chain(&second).map(|u| u.parts().id).collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn a_failing_repository_is_unavailable() {
    let repository = FakeUpstreamRepository::failing();

    assert!(matches!(
        block_on(repository.find_page(&UpstreamPageQuery {
            limit: 1,
            after: None
        })),
        Err(RepositoryError::Unavailable(_))
    ));
}
