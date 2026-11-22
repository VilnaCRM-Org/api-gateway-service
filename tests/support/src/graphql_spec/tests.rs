use iam_domain::{
    ChangeStatement, ContentHash, GraphQlSpecPageQuery, GraphQlSpecParts,
    GraphQlSpecRepository as _, GraphQlSpecStatement, RepositoryError, ServiceName, SpecStatus,
};

use super::{
    FakeGraphQlSpecRepository, SDL_FIXTURE, graphql_spec, graphql_spec_change, type_graph_fixture,
};
use crate::block_on;
use crate::seed::TestRng;

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn hash(byte: u8) -> ContentHash {
    ContentHash::new(&[byte; 32]).unwrap()
}

fn page(service: Option<&str>, status: Option<SpecStatus>) -> GraphQlSpecPageQuery {
    GraphQlSpecPageQuery {
        limit: 100,
        after: None,
        service: service.map(service_name),
        status,
    }
}

fn service_name(name: &str) -> ServiceName {
    service(name)
}

fn stored(
    repository: &FakeGraphQlSpecRepository,
    rng: &mut TestRng,
    name: &str,
    status: SpecStatus,
    byte: u8,
) -> GraphQlSpecParts {
    let spec = graphql_spec(rng, &service(name), status, hash(byte));
    repository
        .save(&GraphQlSpecStatement::insert(&spec, format!("# {byte}")))
        .unwrap();
    spec.parts().clone()
}

#[test]
fn the_fixture_graph_holds_six_fields_and_two_possible_types() {
    let graph = type_graph_fixture();

    assert_eq!(graph.field_count(), 6);
    assert!(SDL_FIXTURE.contains("@iamSensitive"));
}

#[test]
fn a_version_is_found_by_id_and_by_service_and_hash() {
    let mut rng = TestRng::from_seed(1);
    let repository = FakeGraphQlSpecRepository::new();
    let parts = stored(&repository, &mut rng, "billing", SpecStatus::Draft, 1);

    let by_id = block_on(repository.find_by_id(parts.id)).unwrap().unwrap();
    let by_hash = block_on(repository.find_by_content_hash(&service("billing"), &hash(1)))
        .unwrap()
        .unwrap();
    let other_service =
        block_on(repository.find_by_content_hash(&service("orders"), &hash(1))).unwrap();

    assert_eq!(by_id.parts(), &parts);
    assert_eq!(by_hash.parts(), &parts);
    assert!(other_service.is_none());
    assert_eq!(
        block_on(repository.find_sdl(parts.id)).unwrap().as_deref(),
        Some("# 1")
    );
}

#[test]
fn the_same_hash_is_a_different_version_for_another_service() {
    let mut rng = TestRng::from_seed(2);
    let repository = FakeGraphQlSpecRepository::new();
    stored(&repository, &mut rng, "billing", SpecStatus::Draft, 1);
    stored(&repository, &mut rng, "orders", SpecStatus::Draft, 1);

    let duplicate = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));
    let refused = repository.save(&GraphQlSpecStatement::insert(&duplicate, String::new()));

    assert_eq!(repository.stored().len(), 2);
    assert!(matches!(refused, Err(RepositoryError::AlreadyExists)));
}

#[test]
fn a_stored_id_is_a_duplicate() {
    let mut rng = TestRng::from_seed(3);
    let repository = FakeGraphQlSpecRepository::new();
    let spec = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));
    repository
        .save(&GraphQlSpecStatement::insert(&spec, String::new()))
        .unwrap();

    let again = repository.save(&GraphQlSpecStatement::insert(&spec, String::new()));

    assert!(matches!(again, Err(RepositoryError::AlreadyExists)));
}

#[test]
fn pages_filter_by_service_and_status_in_id_order() {
    let mut rng = TestRng::from_seed(4);
    let repository = FakeGraphQlSpecRepository::new();
    stored(&repository, &mut rng, "billing", SpecStatus::Draft, 1);
    let active = stored(&repository, &mut rng, "billing", SpecStatus::Active, 2);
    stored(&repository, &mut rng, "orders", SpecStatus::Active, 3);

    let everything = block_on(repository.find_page(&page(None, None))).unwrap();
    let billing = block_on(repository.find_page(&page(Some("billing"), None))).unwrap();
    let billing_active =
        block_on(repository.find_page(&page(Some("billing"), Some(SpecStatus::Active)))).unwrap();
    let after = block_on(repository.find_page(&GraphQlSpecPageQuery {
        limit: 1,
        after: Some(everything[0].parts().id),
        ..page(None, None)
    }))
    .unwrap();

    assert_eq!(everything.len(), 3);
    assert!(
        everything
            .windows(2)
            .all(|pair| pair[0].parts().id < pair[1].parts().id)
    );
    assert_eq!(billing.len(), 2);
    assert_eq!(billing_active.len(), 1);
    assert_eq!(billing_active[0].parts(), &active);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].parts().id, everything[1].parts().id);
}

#[test]
fn the_active_versions_of_a_service_are_listed() {
    let mut rng = TestRng::from_seed(5);
    let repository = FakeGraphQlSpecRepository::new();
    stored(&repository, &mut rng, "billing", SpecStatus::Draft, 1);
    stored(&repository, &mut rng, "billing", SpecStatus::Active, 2);
    stored(&repository, &mut rng, "billing", SpecStatus::Retired, 3);
    stored(&repository, &mut rng, "orders", SpecStatus::Active, 4);

    let active = block_on(repository.find_active(&service("billing"))).unwrap();

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].parts().status, SpecStatus::Active);
}

#[test]
fn a_missing_version_is_not_found() {
    let mut rng = TestRng::from_seed(6);
    let repository = FakeGraphQlSpecRepository::default();
    let spec = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));

    assert!(
        block_on(repository.find_by_id(spec.parts().id))
            .unwrap()
            .is_none()
    );
    assert!(
        block_on(repository.find_sdl(spec.parts().id))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_failing_repository_is_unavailable_everywhere() {
    let mut rng = TestRng::from_seed(7);
    let repository = FakeGraphQlSpecRepository::failing();
    let spec = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));

    assert!(matches!(
        repository.save(&GraphQlSpecStatement::insert(&spec, String::new())),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.find_by_id(spec.parts().id)),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.find_page(&page(None, None))),
        Err(RepositoryError::Unavailable(_))
    ));
    assert_eq!(repository.stored(), Vec::<GraphQlSpecParts>::new());
}

#[test]
fn a_change_carries_the_specification_statements() {
    let mut rng = TestRng::from_seed(8);
    let spec = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));

    let change = graphql_spec_change(
        &mut rng,
        vec![GraphQlSpecStatement::insert(&spec, String::new())],
    );

    assert!(matches!(
        change.parts().statements.as_slice(),
        [ChangeStatement::SaveGraphQlSpec(_)]
    ));
}

#[test]
fn a_draft_has_no_activation_time_and_a_retired_version_has_both() {
    let mut rng = TestRng::from_seed(9);
    let draft = graphql_spec(&mut rng, &service("billing"), SpecStatus::Draft, hash(1));
    let retired = graphql_spec(&mut rng, &service("billing"), SpecStatus::Retired, hash(2));

    assert!(draft.parts().activated_at.is_none());
    assert!(retired.parts().activated_at.is_some());
    assert!(retired.parts().retired_at.is_some());
}
