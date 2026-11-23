use iam_domain::{
    ChangeStatement, HttpMethod, RatePolicyId, RepositoryError, RouteHost, RoutePageQuery,
    RouteParts, RouteRepository as _, RouteStatement, ServiceName, UpstreamId,
};

use super::{FakeRouteRepository, route, route_change, route_draft};
use crate::block_on;
use crate::seed::TestRng;
use crate::unit_of_work::uuid_v7;

fn upstream(rng: &mut TestRng) -> UpstreamId {
    UpstreamId::from_uuid(uuid_v7(rng))
}

fn parts(rng: &mut TestRng, host: &str, service: &str, upstream: UpstreamId) -> RouteParts {
    let draft = route_draft(host, "/users", &[HttpMethod::Get], service, upstream);
    route(rng, &draft).parts().clone()
}

fn query(limit: u32) -> RoutePageQuery {
    RoutePageQuery {
        limit,
        after: None,
        host: None,
        upstream: None,
        service: None,
    }
}

#[test]
fn the_fixture_builds_a_protected_enforced_route_at_version_one() {
    let mut rng = TestRng::from_seed(3);
    let upstream = upstream(&mut rng);

    let route = route(
        &mut rng,
        &route_draft(
            "api.example.com",
            "/users",
            &[HttpMethod::Get],
            "core",
            upstream,
        ),
    );

    let fields = &route.parts().fields;
    assert_eq!(fields.host().as_str(), "api.example.com");
    assert_eq!(fields.upstream_id(), upstream);
    assert!(!fields.flags().anonymous());
    assert_eq!(route.parts().version.value(), 1);
    assert_eq!(route.parts().created_at, route.parts().updated_at);
}

#[test]
fn a_route_change_runs_one_save_per_statement() {
    let mut rng = TestRng::from_seed(5);
    let upstream = upstream(&mut rng);
    let route = route(
        &mut rng,
        &route_draft(
            "api.example.com",
            "/users",
            &[HttpMethod::Get],
            "core",
            upstream,
        ),
    );

    let change = route_change(&mut rng, vec![RouteStatement::insert(&route)]);

    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::from(RouteStatement::insert(&route))]
    );
}

#[test]
fn pages_are_filtered_by_host_upstream_and_service_in_the_order_of_the_identifiers() {
    let mut rng = TestRng::from_seed(7);
    let core = upstream(&mut rng);
    let billing = upstream(&mut rng);
    let routes = vec![
        parts(&mut rng, "a.example.com", "core", core),
        parts(&mut rng, "b.example.com", "core", core),
        parts(&mut rng, "a.example.com", "billing", billing),
    ];
    let repository = FakeRouteRepository::holding(routes);

    let all = block_on(repository.find_page(&query(10))).unwrap();
    let by_host = block_on(repository.find_page(&RoutePageQuery {
        host: Some(RouteHost::new("a.example.com").unwrap()),
        ..query(10)
    }))
    .unwrap();
    let by_upstream = block_on(repository.find_page(&RoutePageQuery {
        upstream: Some(billing),
        ..query(10)
    }))
    .unwrap();
    let by_service = block_on(repository.find_page(&RoutePageQuery {
        service: Some(ServiceName::new("core").unwrap()),
        ..query(10)
    }))
    .unwrap();
    let after_first = block_on(repository.find_page(&RoutePageQuery {
        after: all.first().map(|route| route.parts().id),
        ..query(1)
    }))
    .unwrap();

    assert_eq!(all.len(), 3);
    assert!(
        all.windows(2)
            .all(|pair| pair[0].parts().id < pair[1].parts().id)
    );
    assert_eq!(by_host.len(), 2);
    assert_eq!(by_upstream.len(), 1);
    assert_eq!(by_service.len(), 2);
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].parts().id, all[1].parts().id);
}

#[test]
fn routes_are_found_by_identifier_host_and_counted_by_reference() {
    let mut rng = TestRng::from_seed(9);
    let core = upstream(&mut rng);
    let policy = RatePolicyId::from_uuid(uuid_v7(&mut rng));
    let mut with_policy = parts(&mut rng, "a.example.com", "core", core);
    let mut draft = route_draft("a.example.com", "/orders", &[HttpMethod::Get], "core", core);
    draft.rate_policies = vec![policy];
    with_policy.fields = route(&mut rng, &draft).parts().fields.clone();
    let mut deleted = parts(&mut rng, "a.example.com", "core", core);
    deleted.deleted_at = Some(deleted.created_at);
    let repository = FakeRouteRepository::holding(vec![with_policy.clone(), deleted.clone()]);

    let found = block_on(repository.find_by_id(with_policy.id))
        .unwrap()
        .unwrap();
    let hidden = block_on(repository.find_by_id(deleted.id)).unwrap();
    let on_host =
        block_on(repository.find_by_host(&RouteHost::new("a.example.com").unwrap())).unwrap();

    assert_eq!(found.parts(), &with_policy);
    assert!(hidden.is_none());
    assert_eq!(on_host.len(), 1);
    assert_eq!(block_on(repository.count_by_upstream(core)).unwrap(), 1);
    assert_eq!(
        block_on(repository.count_by_rate_policy(policy)).unwrap(),
        1
    );
}

#[test]
fn a_failing_repository_is_unavailable() {
    let repository = FakeRouteRepository::failing();

    assert!(matches!(
        block_on(repository.find_page(&query(1))),
        Err(RepositoryError::Unavailable(_))
    ));
}
