use iam_domain::{
    GqlName, GraphQlPermission, GraphQlPermissionRepository as _, PermissionFlags, PermissionId,
    PermissionKey, PermissionPageQuery, RepositoryError, ServiceName, SpecId,
};

use super::FakeGraphQlPermissionRepository;
use crate::block_on;

const IDS: [&str; 4] = [
    "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281701",
    "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281702",
    "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281703",
    "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281704",
];

fn service(name: &str) -> ServiceName {
    ServiceName::new(name).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn entry(index: usize, value: &str, flags: PermissionFlags) -> GraphQlPermission {
    GraphQlPermission::create(PermissionId::parse(IDS[index]).unwrap(), key(value), flags).unwrap()
}

fn query() -> PermissionPageQuery {
    PermissionPageQuery {
        limit: 100,
        after: None,
        service: None,
        active: None,
        sensitive: None,
        key_prefix: None,
        type_name: None,
        method: None,
    }
}

fn seeded() -> FakeGraphQlPermissionRepository {
    let repository = FakeGraphQlPermissionRepository::new();
    let mut inactive = entry(3, "gql:orders:Query.list", PermissionFlags::NONE);
    inactive.deactivate();
    for stored in [
        entry(0, "gql:billing:Query.invoices", PermissionFlags::NONE),
        entry(
            1,
            "gql:billing:Mutation.pay",
            PermissionFlags::NONE.with_sensitive(),
        ),
        entry(2, "gql:billing:__introspection", PermissionFlags::NONE),
        inactive,
    ] {
        repository.insert(&stored).unwrap();
    }
    repository
}

fn ids(entries: &[GraphQlPermission]) -> Vec<PermissionId> {
    entries.iter().map(|found| found.parts().id).collect()
}

#[test]
fn a_stored_entry_is_found_by_id_and_an_unknown_id_is_not() {
    let repository = seeded();

    let found = block_on(repository.find_by_id(PermissionId::parse(IDS[1]).unwrap())).unwrap();
    let absent = block_on(repository.find_by_id(PermissionId::from_uuid(
        shared_domain::Uuid::parse("1b7e5d3c-2a19-4f8e-8d6c-5b4a39281709").unwrap(),
    )))
    .unwrap();

    assert_eq!(found.unwrap().parts().key, key("gql:billing:Mutation.pay"));
    assert!(absent.is_none());
}

#[test]
fn a_duplicate_id_or_key_is_refused() {
    let repository = seeded();

    let same_id = repository.insert(&entry(0, "gql:billing:Query.other", PermissionFlags::NONE));
    let same_key = repository.insert(&entry(
        3,
        "gql:billing:Query.invoices",
        PermissionFlags::NONE,
    ));

    assert!(matches!(same_id, Err(RepositoryError::AlreadyExists)));
    assert!(matches!(same_key, Err(RepositoryError::AlreadyExists)));
    assert_eq!(repository.stored().len(), 4);
}

#[test]
fn entries_are_found_by_service_and_keys_in_key_order() {
    let repository = seeded();

    let by_keys = block_on(repository.find_by_keys(
        &service("billing"),
        &[
            key("gql:billing:Query.invoices"),
            key("gql:billing:Mutation.pay"),
            key("gql:orders:Query.list"),
        ],
    ))
    .unwrap();
    let by_service = block_on(repository.find_by_service(&service("billing"))).unwrap();

    assert_eq!(
        ids(&by_keys),
        vec![
            PermissionId::parse(IDS[1]).unwrap(),
            PermissionId::parse(IDS[0]).unwrap()
        ]
    );
    assert_eq!(by_service.len(), 3);
    assert_eq!(by_service[0].parts().key, key("gql:billing:Mutation.pay"));
}

#[test]
fn a_page_follows_the_identifiers_and_the_cursor() {
    let repository = seeded();
    let mut first = query();
    first.limit = 2;
    let page = block_on(repository.find_page(&first)).unwrap();
    let mut next = query();
    next.after = page.last().map(|found| found.parts().id);

    let rest = block_on(repository.find_page(&next)).unwrap();

    assert_eq!(page.len(), 2);
    assert_eq!(
        ids(&rest),
        vec![
            PermissionId::parse(IDS[2]).unwrap(),
            PermissionId::parse(IDS[3]).unwrap()
        ]
    );
}

#[test]
fn a_page_is_filtered_by_service_state_flag_prefix_and_type() {
    let repository = seeded();
    let page = |change: &dyn Fn(&mut PermissionPageQuery)| {
        let mut filtered = query();
        change(&mut filtered);
        ids(&block_on(repository.find_page(&filtered)).unwrap())
    };

    assert_eq!(page(&|q| q.service = Some(service("orders"))).len(), 1);
    assert_eq!(page(&|q| q.active = Some(false)).len(), 1);
    assert_eq!(page(&|q| q.active = Some(true)).len(), 3);
    assert_eq!(page(&|q| q.sensitive = Some(true)).len(), 1);
    assert_eq!(
        page(&|q| q.key_prefix = Some("gql:billing:Query.".to_owned())).len(),
        1
    );
    assert_eq!(
        page(&|q| q.type_name = Some(GqlName::parse("Mutation").unwrap())),
        vec![PermissionId::parse(IDS[1]).unwrap()]
    );
}

#[test]
fn the_failing_repository_answers_unavailable_and_holds_nothing() {
    let repository = FakeGraphQlPermissionRepository::failing();

    assert!(matches!(
        block_on(repository.find_page(&query())),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository.insert(&entry(
            0,
            "gql:billing:Query.invoices",
            PermissionFlags::NONE
        )),
        Err(RepositoryError::Unavailable(_))
    ));
    assert_eq!(repository.stored().len(), 0);
}

#[test]
fn the_default_repository_is_empty() {
    assert_eq!(FakeGraphQlPermissionRepository::default().stored().len(), 0);
}

#[test]
fn the_created_keys_of_a_recorded_activation_are_found_by_version() {
    let repository = FakeGraphQlPermissionRepository::new();
    let spec = SpecId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281709").unwrap();
    let other = SpecId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281710").unwrap();
    repository.record_created_keys(spec, vec![key("gql:billing:Query.invoices")]);

    assert_eq!(
        block_on(repository.find_created_keys(spec)).unwrap(),
        Some(vec![key("gql:billing:Query.invoices")])
    );
    assert_eq!(block_on(repository.find_created_keys(other)).unwrap(), None);
}

#[test]
fn a_failing_repository_cannot_find_created_keys() {
    let spec = SpecId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281709").unwrap();

    let found = block_on(FakeGraphQlPermissionRepository::failing().find_created_keys(spec));

    assert!(matches!(found, Err(RepositoryError::Unavailable(_))));
}
