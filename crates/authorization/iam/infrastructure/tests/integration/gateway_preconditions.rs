//! The preconditions of the gateway configuration that `PgIamUnitOfWork` evaluates under the lock
//! of the policy epoch: the reference checks of the deletion of an upstream and of a rate policy,
//! the targets of a route and its candidate route table. Each test builds a change from a state
//! that a concurrent change then makes stale, which is the interleaving that the check before the
//! commit cannot see.

use std::time::Duration;

use iam_domain::{
    ChangeStatement, EntityVersion, GatewayPrecondition, HttpMethod, IamChange, IamUnitOfWork as _,
    RatePolicy, RatePolicyParts, RatePolicyRepository as _, RatePolicyStatement, RepositoryError,
    Route, RouteConflict, RouteHost, RouteId, RouteParts, RouteRepository as _, RouteSetVersion,
    RouteStatement, Upstream, UpstreamFields, UpstreamId, UpstreamName, UpstreamParts,
    UpstreamRepository as _, UpstreamSettingsDraft, UpstreamStatement,
};
use iam_infrastructure::{
    PgIamUnitOfWork, PgRatePolicyRepository, PgRouteRepository, PgUpstreamRepository,
};
use sqlx::PgPool;
use test_support::gateway_configuration::gateway_change;
use test_support::rate_policy::rate_policy;
use test_support::route::{route, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::upstream;

const HOST: &str = "api.example.com";

async fn commit(pool: &PgPool, change: IamChange) -> Result<(), RepositoryError> {
    PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .map(|_receipt| ())
}

fn later(time: std::time::SystemTime) -> std::time::SystemTime {
    time.checked_add(Duration::from_secs(60)).unwrap()
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

/// The statements that create `upstream`, `policy` and nothing else.
async fn store(pool: &PgPool, rng: &mut TestRng, upstream: &Upstream, policy: Option<&RatePolicy>) {
    let mut statements = vec![ChangeStatement::from(UpstreamStatement::insert(upstream))];
    statements
        .extend(policy.map(|policy| ChangeStatement::from(RatePolicyStatement::insert(policy))));
    commit(pool, gateway_change(rng, statements)).await.unwrap();
}

/// The change that deletes `upstream`, as `DeleteUpstreamCommandHandler` builds it.
fn delete_upstream(rng: &mut TestRng, parts: &UpstreamParts) -> IamChange {
    let deleted = Upstream::restore(UpstreamParts {
        version: version(2),
        updated_at: later(parts.updated_at),
        deleted_at: Some(later(parts.updated_at)),
        ..parts.clone()
    });
    gateway_change(
        rng,
        vec![
            GatewayPrecondition::UpstreamUnreferenced(parts.id).into(),
            UpstreamStatement::update(&deleted, EntityVersion::INITIAL).into(),
        ],
    )
}

/// The change that deletes `policy`, as `DeleteRatePolicyCommandHandler` builds it.
fn delete_rate_policy(rng: &mut TestRng, parts: &RatePolicyParts) -> IamChange {
    let deleted = RatePolicy::restore(RatePolicyParts {
        version: version(2),
        updated_at: later(parts.updated_at),
        deleted_at: Some(later(parts.updated_at)),
        ..parts.clone()
    });
    gateway_change(
        rng,
        vec![
            GatewayPrecondition::RatePolicyUnreferenced(parts.id).into(),
            RatePolicyStatement::update(&deleted, EntityVersion::INITIAL).into(),
        ],
    )
}

/// The change that inserts `route`, as the route handlers build it: the targets, the candidate
/// route table, then the insert.
fn insert_route(rng: &mut TestRng, route: &Route) -> IamChange {
    let parts = route.parts();
    gateway_change(
        rng,
        vec![
            GatewayPrecondition::RouteTargets {
                upstream_id: parts.fields.upstream_id(),
                service: parts.fields.service().clone(),
                rate_policies: parts.fields.rate_policies().to_vec(),
            }
            .into(),
            GatewayPrecondition::RouteTable(Box::new(parts.clone())).into(),
            RouteStatement::insert(route).into(),
        ],
    )
}

fn route_on(rng: &mut TestRng, path: &str, upstream: UpstreamId) -> Route {
    route(
        rng,
        &route_draft(HOST, path, &[HttpMethod::Get], "core", upstream),
    )
}

async fn stored_route(pool: &PgPool, id: RouteId) -> Option<RouteParts> {
    PgRouteRepository::new(pool.clone())
        .find_by_id(id)
        .await
        .unwrap()
        .map(|route| route.parts().clone())
}

async fn upstream_is_stored(pool: &PgPool, name: &str) -> bool {
    PgUpstreamRepository::new(pool.clone())
        .find_by_name(&UpstreamName::new(name).unwrap())
        .await
        .unwrap()
        .is_some()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_upstream_that_no_route_references_is_deleted(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;

    commit(&pool, delete_upstream(&mut rng, core.parts()))
        .await
        .unwrap();

    assert!(!upstream_is_stored(&pool, "core").await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_created_after_the_reference_check_refuses_the_deletion_of_its_upstream(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let deletion = delete_upstream(&mut rng, core.parts());
    let created = route_on(&mut rng, "/users", core.parts().id);
    commit(&pool, insert_route(&mut rng, &created))
        .await
        .unwrap();

    let result = commit(&pool, deletion).await;

    let Err(RepositoryError::ReferencedByRoute(refusal)) = result else {
        panic!("the references refuse the deletion: {result:?}");
    };
    assert_eq!(refusal.count, 1);
    assert!(
        upstream_is_stored(&pool, "core").await,
        "the delete rolled back"
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_created_after_the_reference_check_refuses_the_deletion_of_its_rate_policy(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    let policy = rate_policy(&mut rng, "per-ip");
    store(&pool, &mut rng, &core, Some(&policy)).await;
    let deletion = delete_rate_policy(&mut rng, policy.parts());
    let mut draft = route_draft(HOST, "/users", &[HttpMethod::Get], "core", core.parts().id);
    draft.rate_policies = vec![policy.parts().id];
    let created = route(&mut rng, &draft);
    commit(&pool, insert_route(&mut rng, &created))
        .await
        .unwrap();

    let result = commit(&pool, deletion).await;

    assert!(
        matches!(result, Err(RepositoryError::ReferencedByRoute(_))),
        "{result:?}"
    );
    let stored = PgRatePolicyRepository::new(pool.clone())
        .find_by_id(policy.parts().id)
        .await
        .unwrap();
    assert!(stored.is_some(), "the delete rolled back");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_deleted_route_no_longer_references_its_upstream(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let created = route_on(&mut rng, "/users", core.parts().id);
    commit(&pool, insert_route(&mut rng, &created))
        .await
        .unwrap();
    let removed = Route::restore(RouteParts {
        version: version(2),
        updated_at: later(created.parts().updated_at),
        deleted_at: Some(later(created.parts().updated_at)),
        ..created.parts().clone()
    });
    commit(
        &pool,
        gateway_change(
            &mut rng,
            vec![RouteStatement::update(&removed, EntityVersion::INITIAL).into()],
        ),
    )
    .await
    .unwrap();

    commit(&pool, delete_upstream(&mut rng, core.parts()))
        .await
        .unwrap();

    assert!(!upstream_is_stored(&pool, "core").await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_whose_upstream_was_deleted_after_the_check_is_refused_as_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let on_core = route_on(&mut rng, "/users", core.parts().id);
    let insertion = insert_route(&mut rng, &on_core);
    commit(&pool, delete_upstream(&mut rng, core.parts()))
        .await
        .unwrap();

    let result = commit(&pool, insertion).await;

    assert!(
        matches!(result, Err(RepositoryError::Conflict)),
        "{result:?}"
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_whose_rate_policy_was_deleted_after_the_check_is_refused_as_a_conflict(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    let policy = rate_policy(&mut rng, "per-ip");
    store(&pool, &mut rng, &core, Some(&policy)).await;
    let mut draft = route_draft(HOST, "/users", &[HttpMethod::Get], "core", core.parts().id);
    draft.rate_policies = vec![policy.parts().id];
    let created = route(&mut rng, &draft);
    let insertion = insert_route(&mut rng, &created);
    commit(&pool, delete_rate_policy(&mut rng, policy.parts()))
        .await
        .unwrap();

    let result = commit(&pool, insertion).await;

    assert!(
        matches!(result, Err(RepositoryError::Conflict)),
        "{result:?}"
    );
    assert_eq!(stored_route(&pool, created.parts().id).await, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_whose_upstream_now_serves_another_service_is_refused_as_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let on_core = route_on(&mut rng, "/users", core.parts().id);
    let insertion = insert_route(&mut rng, &on_core);
    let (_name, settings) = UpstreamFields::new(
        "core",
        &UpstreamSettingsDraft {
            catalog_service: "billing".to_owned(),
            ..iam_domain_draft(core.parts())
        },
    )
    .unwrap()
    .into_parts();
    let moved = Upstream::restore(UpstreamParts {
        settings,
        version: version(2),
        updated_at: later(core.parts().updated_at),
        ..core.parts().clone()
    });
    commit(
        &pool,
        gateway_change(
            &mut rng,
            vec![UpstreamStatement::update(&moved, EntityVersion::INITIAL).into()],
        ),
    )
    .await
    .unwrap();

    let result = commit(&pool, insertion).await;

    assert!(
        matches!(result, Err(RepositoryError::Conflict)),
        "{result:?}"
    );
}

/// The draft of the stored settings of an upstream.
fn iam_domain_draft(parts: &UpstreamParts) -> UpstreamSettingsDraft {
    let settings = &parts.settings;
    UpstreamSettingsDraft {
        namespace: settings.namespace().to_owned(),
        service_name: settings.service_name().to_owned(),
        catalog_service: settings.catalog_service().to_string(),
        port: i64::from(settings.port()),
        protocol: settings.protocol(),
        forward_credentials: settings.forward_credentials(),
        connect_timeout_ms: i64::from(settings.connect_timeout_ms()),
        response_timeout_ms: i64::from(settings.response_timeout_ms()),
        concurrency_limit: i64::from(settings.concurrency_limit()),
        retry_budget_percent: i64::from(settings.retry_budget_percent()),
        outlier_threshold: i64::from(settings.outlier_threshold()),
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn two_routes_that_each_passed_an_empty_table_check_cannot_both_commit(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let first = route_on(&mut rng, "/users", core.parts().id);
    let second = route_on(&mut rng, "/users", core.parts().id);
    let first_change = insert_route(&mut rng, &first);
    let second_change = insert_route(&mut rng, &second);

    commit(&pool, first_change).await.unwrap();
    let result = commit(&pool, second_change).await;

    assert!(
        matches!(
            result,
            Err(RepositoryError::RouteTable(
                RouteConflict::SamePattern { .. }
            ))
        ),
        "{result:?}"
    );
    assert!(stored_route(&pool, first.parts().id).await.is_some());
    assert_eq!(stored_route(&pool, second.parts().id).await, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_updated_in_place_does_not_conflict_with_itself(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let created = route_on(&mut rng, "/users", core.parts().id);
    commit(&pool, insert_route(&mut rng, &created))
        .await
        .unwrap();
    let changed = Route::restore(RouteParts {
        version: version(2),
        updated_at: later(created.parts().updated_at),
        ..created.parts().clone()
    });
    let update = gateway_change(
        &mut rng,
        vec![
            GatewayPrecondition::RouteTable(Box::new(changed.parts().clone())).into(),
            RouteStatement::update(&changed, EntityVersion::INITIAL).into(),
        ],
    );

    commit(&pool, update).await.unwrap();

    let found = stored_route(&pool, created.parts().id).await.unwrap();
    assert_eq!(found.version, version(2));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_of_another_host_does_not_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let first = route_on(&mut rng, "/users", core.parts().id);
    let other = route(
        &mut rng,
        &route_draft(
            "other.example.com",
            "/users",
            &[HttpMethod::Get],
            "core",
            core.parts().id,
        ),
    );
    commit(&pool, insert_route(&mut rng, &first)).await.unwrap();

    commit(&pool, insert_route(&mut rng, &other)).await.unwrap();

    assert!(stored_route(&pool, other.parts().id).await.is_some());
}

/// Whether the commit of `change` succeeded.
async fn succeeded(pool: PgPool, change: IamChange) -> bool {
    commit(&pool, change).await.is_ok()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_deletion_and_a_route_creation_that_race_never_both_commit(pool: PgPool) {
    let mut rng = TestRng::from_env();
    for round in 0..10 {
        let name = format!("core-{round}");
        let target = upstream(&mut rng, &name, "core");
        store(&pool, &mut rng, &target, None).await;
        let deletion = delete_upstream(&mut rng, target.parts());
        let on_target = route_on(&mut rng, &format!("/users-{round}"), target.parts().id);
        let creation = insert_route(&mut rng, &on_target);

        let (deleted, created) = tokio::join!(
            tokio::spawn(succeeded(pool.clone(), deletion)),
            tokio::spawn(succeeded(pool.clone(), creation)),
        );

        let (deleted, created) = (deleted.unwrap(), created.unwrap());
        assert!(
            deleted != created,
            "round {round}: exactly one of the deletion ({deleted}) and the route ({created}) commits"
        );
        assert_eq!(
            upstream_is_stored(&pool, &name).await,
            created,
            "round {round}: the upstream stays exactly when the route committed"
        );
    }
}

/// The version of the set that the stored routes of the host hold now: what a plan reads.
async fn planned_version(pool: &PgPool) -> EntityVersion {
    let stored: Vec<RouteParts> = PgRouteRepository::new(pool.clone())
        .find_by_host(&RouteHost::new(HOST).unwrap())
        .await
        .unwrap()
        .iter()
        .map(|route| route.parts().clone())
        .collect();
    RouteSetVersion::of(&stored)
}

/// The change that inserts `routes` as `ApplyRouteConfigurationCommandHandler` builds it: the set
/// version the plan read, the targets of the routes, then the inserts.
fn insert_set(rng: &mut TestRng, planned: EntityVersion, routes: &[Route]) -> IamChange {
    let mut statements: Vec<ChangeStatement> = vec![
        GatewayPrecondition::RouteSetVersion {
            host: RouteHost::new(HOST).unwrap(),
            version: planned,
        }
        .into(),
    ];
    for route in routes {
        let parts = route.parts();
        statements.push(
            GatewayPrecondition::RouteTargets {
                upstream_id: parts.fields.upstream_id(),
                service: parts.fields.service().clone(),
                rate_policies: parts.fields.rate_policies().to_vec(),
            }
            .into(),
        );
    }
    statements.extend(
        routes
            .iter()
            .map(|route| ChangeStatement::from(RouteStatement::insert(route))),
    );
    gateway_change(rng, statements)
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_set_commits_when_the_host_is_unchanged_since_the_plan(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let first = route_on(&mut rng, "/a", core.parts().id);
    let second = route_on(&mut rng, "/b", core.parts().id);
    let planned = planned_version(&pool).await;
    let ids = (first.parts().id, second.parts().id);

    let set = insert_set(&mut rng, planned, &[first, second]);

    commit(&pool, set).await.unwrap();
    assert!(stored_route(&pool, ids.0).await.is_some());
    assert!(stored_route(&pool, ids.1).await.is_some());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_set_whose_upstream_was_deleted_after_the_plan_is_refused_as_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let on_core = route_on(&mut rng, "/users", core.parts().id);
    let planned = planned_version(&pool).await;
    let set = insert_set(&mut rng, planned, std::slice::from_ref(&on_core));
    commit(&pool, delete_upstream(&mut rng, core.parts()))
        .await
        .unwrap();

    let result = commit(&pool, set).await;

    assert!(
        matches!(result, Err(RepositoryError::Conflict)),
        "{result:?}"
    );
    assert_eq!(stored_route(&pool, on_core.parts().id).await, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_set_is_refused_when_a_route_was_created_on_the_host_after_the_plan(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    store(&pool, &mut rng, &core, None).await;
    let planned = planned_version(&pool).await;
    let from_the_set = route_on(&mut rng, "/users", core.parts().id);
    let set = insert_set(&mut rng, planned, std::slice::from_ref(&from_the_set));
    let concurrent = route_on(&mut rng, "/users", core.parts().id);
    commit(&pool, insert_route(&mut rng, &concurrent))
        .await
        .unwrap();

    let result = commit(&pool, set).await;

    assert!(
        matches!(result, Err(RepositoryError::Conflict)),
        "{result:?}"
    );
    assert!(stored_route(&pool, concurrent.parts().id).await.is_some());
    assert_eq!(stored_route(&pool, from_the_set.parts().id).await, None);
}
