//! `PgUpstreamRepository`, `PgRouteRepository`, `PgRatePolicyRepository` and the upstream, route and
//! rate policy statements of `PgIamUnitOfWork`: unique names among records that are not deleted,
//! the foreign keys, the stored order of the rate policies of a route, the state records with the
//! digest and stable filtered pages.

use std::collections::BTreeSet;
use std::time::Duration;

use iam_domain::{
    ChangeStatement, CorsDraft, EntityVersion, HttpMethod, IamChange, IamUnitOfWork as _,
    PolicyState, RateFallback, RateKeyKind, RatePolicy, RatePolicyDraft, RatePolicyFields,
    RatePolicyId, RatePolicyPageQuery, RatePolicyParts, RatePolicyRepository as _, RatePolicyState,
    RatePolicyStatement, RepositoryError, Route, RouteFields, RouteHost, RouteId, RoutePageQuery,
    RouteParts, RouteRepository as _, RouteState, RouteStatement, ServiceName, StateKey,
    StateRecordCodec as _, Upstream, UpstreamFields, UpstreamId, UpstreamName, UpstreamPageQuery,
    UpstreamParts, UpstreamProtocol, UpstreamRepository as _, UpstreamSettingsDraft, UpstreamState,
    UpstreamStatement,
};
use iam_infrastructure::{
    JsonStateRecordCodec, PgIamUnitOfWork, PgRatePolicyRepository, PgRouteRepository,
    PgUpstreamRepository,
};
use sqlx::PgPool;
use test_support::gateway_configuration::gateway_change;
use test_support::rate_policy::{rate_policy, rate_policy_change};
use test_support::route::{route, route_change, route_draft};
use test_support::seed::TestRng;
use test_support::upstream::{upstream, upstream_change};

async fn commit(pool: &PgPool, change: IamChange) -> Result<(), RepositoryError> {
    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .map(|_receipt| ())
}

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

fn later(time: std::time::SystemTime) -> std::time::SystemTime {
    time.checked_add(Duration::from_secs(60)).unwrap()
}

fn insert_upstream(upstream: &Upstream) -> ChangeStatement {
    ChangeStatement::from(UpstreamStatement::insert(upstream))
}

fn insert_rate_policy(policy: &RatePolicy) -> ChangeStatement {
    ChangeStatement::from(RatePolicyStatement::insert(policy))
}

fn insert_route(route: &Route) -> ChangeStatement {
    ChangeStatement::from(RouteStatement::insert(route))
}

/// The upstream at the next version, deleted.
fn deleted_upstream(parts: &UpstreamParts) -> Upstream {
    Upstream::restore(UpstreamParts {
        version: parts.version.next().unwrap(),
        updated_at: later(parts.updated_at),
        deleted_at: Some(later(parts.updated_at)),
        ..parts.clone()
    })
}

fn upstream_draft(port: i64) -> UpstreamSettingsDraft {
    UpstreamSettingsDraft {
        namespace: "platform".to_owned(),
        service_name: "core-service".to_owned(),
        catalog_service: "core".to_owned(),
        port,
        protocol: UpstreamProtocol::H2c,
        forward_credentials: true,
        connect_timeout_ms: 2_000,
        response_timeout_ms: 20_000,
        concurrency_limit: 128,
        retry_budget_percent: 10,
        outlier_threshold: 3,
    }
}

async fn stored_upstream(pool: &PgPool, name: &str) -> Option<UpstreamParts> {
    PgUpstreamRepository::new(pool.clone())
        .find_by_name(&UpstreamName::new(name).unwrap())
        .await
        .unwrap()
        .map(|upstream| upstream.parts().clone())
}

async fn stored_route(pool: &PgPool, id: RouteId) -> Option<RouteParts> {
    PgRouteRepository::new(pool.clone())
        .find_by_id(id)
        .await
        .unwrap()
        .map(|route| route.parts().clone())
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_upstream_name_is_unique_among_upstreams_that_are_not_deleted(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = upstream(&mut rng, "core", "core");
    let second = upstream(&mut rng, "core", "billing");
    commit(
        &pool,
        upstream_change(&mut rng, vec![UpstreamStatement::insert(&first)]),
    )
    .await
    .unwrap();

    let duplicate = commit(
        &pool,
        upstream_change(&mut rng, vec![UpstreamStatement::insert(&second)]),
    )
    .await;

    assert!(matches!(duplicate, Err(RepositoryError::AlreadyExists)));
    let deleted = deleted_upstream(first.parts());
    commit(
        &pool,
        upstream_change(
            &mut rng,
            vec![UpstreamStatement::update(&deleted, EntityVersion::INITIAL)],
        ),
    )
    .await
    .unwrap();
    assert_eq!(stored_upstream(&pool, "core").await, None);
    commit(
        &pool,
        upstream_change(&mut rng, vec![UpstreamStatement::insert(&second)]),
    )
    .await
    .unwrap();
    let reused = stored_upstream(&pool, "core").await.unwrap();
    assert_eq!(&reused, second.parts());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_upstream_is_found_with_its_settings_and_is_updated_at_its_expected_version(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let created = upstream(&mut rng, "core", "core");
    commit(
        &pool,
        upstream_change(&mut rng, vec![UpstreamStatement::insert(&created)]),
    )
    .await
    .unwrap();
    let (_name, settings) = UpstreamFields::new("core", &upstream_draft(9090))
        .unwrap()
        .into_parts();
    let changed = Upstream::restore(UpstreamParts {
        settings,
        system: true,
        version: version(2),
        updated_at: later(created.parts().updated_at),
        ..created.parts().clone()
    });

    let stale = commit(
        &pool,
        upstream_change(
            &mut rng,
            vec![UpstreamStatement::update(&changed, version(5))],
        ),
    )
    .await;
    commit(
        &pool,
        upstream_change(
            &mut rng,
            vec![UpstreamStatement::update(&changed, version(1))],
        ),
    )
    .await
    .unwrap();

    assert!(matches!(stale, Err(RepositoryError::Conflict)));
    let found = stored_upstream(&pool, "core").await.unwrap();
    assert_eq!(found.settings, changed.parts().settings);
    assert_eq!(found.version, version(2));
    assert!(!found.system, "the system flag never changes");
    let by_id = PgUpstreamRepository::new(pool.clone())
        .find_by_id(found.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_id.parts(), &found);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_whose_upstream_does_not_exist_is_rejected_by_the_foreign_key(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let missing = upstream(&mut rng, "core", "core");
    let orphan = route(
        &mut rng,
        &route_draft(
            "api.example.com",
            "/users",
            &[HttpMethod::Get],
            "core",
            missing.parts().id,
        ),
    );

    let result = commit(
        &pool,
        route_change(&mut rng, vec![RouteStatement::insert(&orphan)]),
    )
    .await;

    assert!(matches!(result, Err(RepositoryError::Conflict)));
    assert_eq!(stored_route(&pool, orphan.parts().id).await, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_route_with_three_rate_policies_reads_them_back_in_their_stored_order(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    let policies: Vec<RatePolicy> = ["per-ip", "per-subject", "per-route"]
        .iter()
        .map(|name| rate_policy(&mut rng, name))
        .collect();
    let ids: Vec<RatePolicyId> = policies.iter().map(|policy| policy.parts().id).collect();
    let applied = vec![ids[2], ids[0], ids[1]];
    let mut draft = route_draft(
        "api.example.com",
        "/users",
        &[HttpMethod::Post, HttpMethod::Get],
        "core",
        core.parts().id,
    );
    draft.rate_policies.clone_from(&applied);
    draft.cors = Some(CorsDraft {
        origins: vec!["https://app.example.com".to_owned()],
        methods: vec![HttpMethod::Get],
        headers: vec!["Authorization".to_owned()],
        allow_credentials: true,
        max_age_seconds: 600,
    });
    let created = route(&mut rng, &draft);
    let mut statements = vec![insert_upstream(&core)];
    statements.extend(policies.iter().map(insert_rate_policy));
    statements.push(insert_route(&created));

    commit(&pool, gateway_change(&mut rng, statements))
        .await
        .unwrap();

    let found = stored_route(&pool, created.parts().id).await.unwrap();
    assert_eq!(&found, created.parts());
    assert_eq!(found.fields.rate_policies(), applied);
    let reordered = {
        draft.rate_policies = vec![ids[1], ids[2]];
        Route::restore(RouteParts {
            fields: RouteFields::new(&draft).unwrap(),
            version: version(2),
            updated_at: later(created.parts().updated_at),
            ..created.parts().clone()
        })
    };
    commit(
        &pool,
        route_change(
            &mut rng,
            vec![RouteStatement::update(&reordered, version(1))],
        ),
    )
    .await
    .unwrap();
    let updated = stored_route(&pool, created.parts().id).await.unwrap();
    assert_eq!(updated.fields.rate_policies(), [ids[1], ids[2]]);
    let rate_policies = PgRatePolicyRepository::new(pool.clone());
    let many = rate_policies.find_many(&[ids[2], ids[0]]).await.unwrap();
    let many: Vec<RatePolicyId> = many.iter().map(|policy| policy.parts().id).collect();
    assert_eq!(many, [ids[2], ids[0]]);
    let routes = PgRouteRepository::new(pool.clone());
    assert_eq!(routes.count_by_rate_policy(ids[0]).await.unwrap(), 0);
    assert_eq!(routes.count_by_rate_policy(ids[1]).await.unwrap(), 1);
    assert_eq!(routes.count_by_upstream(core.parts().id).await.unwrap(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rate_policy_name_is_unique_among_rate_policies_that_are_not_deleted(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first = rate_policy(&mut rng, "per-ip");
    let second = rate_policy(&mut rng, "per-ip");
    commit(
        &pool,
        rate_policy_change(&mut rng, vec![RatePolicyStatement::insert(&first)]),
    )
    .await
    .unwrap();

    let duplicate = commit(
        &pool,
        rate_policy_change(&mut rng, vec![RatePolicyStatement::insert(&second)]),
    )
    .await;
    let deleted = RatePolicy::restore(RatePolicyParts {
        version: version(2),
        updated_at: later(first.parts().updated_at),
        deleted_at: Some(later(first.parts().updated_at)),
        ..first.parts().clone()
    });
    commit(
        &pool,
        rate_policy_change(
            &mut rng,
            vec![RatePolicyStatement::update(&deleted, version(1))],
        ),
    )
    .await
    .unwrap();
    commit(
        &pool,
        rate_policy_change(&mut rng, vec![RatePolicyStatement::insert(&second)]),
    )
    .await
    .unwrap();

    assert!(matches!(duplicate, Err(RepositoryError::AlreadyExists)));
    let repository = PgRatePolicyRepository::new(pool.clone());
    assert!(
        repository
            .find_by_id(first.parts().id)
            .await
            .unwrap()
            .is_none()
    );
    let found = repository
        .find_by_id(second.parts().id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.parts(), second.parts());
}

/// The state rows of `iam_outbox`: policy version, record key, payload and digest after the row.
async fn state_rows(pool: &PgPool) -> Vec<(i64, String, Option<String>, Vec<u8>)> {
    sqlx::query_as(
        "SELECT policy_version, record_key, payload, digest_after FROM iam_outbox
        WHERE kind = 'state' ORDER BY position",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn epoch_digest(pool: &PgPool) -> Vec<u8> {
    sqlx::query_scalar("SELECT digest FROM iam_policy_epoch WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The payload of the newest state row of `key`: `Some(None)` for a tombstone, `None` without a row.
async fn newest_payload(pool: &PgPool, key: &str) -> Option<Option<String>> {
    state_rows(pool)
        .await
        .into_iter()
        .rfind(|(_version, record_key, _payload, _digest)| record_key == key)
        .map(|(_version, _key, payload, _digest)| payload)
}

async fn assert_state(pool: &PgPool, key: &StateKey, expected: Option<PolicyState>) {
    let payload = newest_payload(pool, &key.to_string()).await.unwrap();
    let state = payload.map(|payload| JsonStateRecordCodec.decode(key, &payload).unwrap());
    assert_eq!(state, expected, "{key}");
}

async fn assert_head_is_the_digest(pool: &PgPool) {
    let rows = state_rows(pool).await;
    let (_version, key, _payload, digest_after) = rows.last().unwrap();
    assert_eq!(key, "__head");
    assert_eq!(digest_after, &epoch_digest(pool).await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn each_change_writes_the_state_records_and_the_digest_of_the_gateway_configuration(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let core = upstream(&mut rng, "core", "core");
    let policy = rate_policy(&mut rng, "per-ip");
    let mut draft = route_draft(
        "api.example.com",
        "/users",
        &[HttpMethod::Get],
        "core",
        core.parts().id,
    );
    draft.rate_policies = vec![policy.parts().id];
    let created = route(&mut rng, &draft);
    let upstream_key = StateKey::Upstream(core.parts().name.clone());
    let route_key = StateKey::Route(created.parts().id);
    let policy_key = StateKey::RatePolicy(policy.parts().id);

    commit(
        &pool,
        gateway_change(
            &mut rng,
            vec![
                insert_upstream(&core),
                insert_rate_policy(&policy),
                insert_route(&created),
            ],
        ),
    )
    .await
    .unwrap();

    assert_eq!(state_rows(&pool).await.len(), 4);
    assert_state(
        &pool,
        &upstream_key,
        Some(PolicyState::Upstream(UpstreamState::of(core.parts()))),
    )
    .await;
    assert_state(
        &pool,
        &route_key,
        Some(PolicyState::Route(RouteState::of(created.parts()))),
    )
    .await;
    assert_state(
        &pool,
        &policy_key,
        Some(PolicyState::RatePolicy(RatePolicyState::of(policy.parts()))),
    )
    .await;
    assert_head_is_the_digest(&pool).await;

    let (_name, settings) = UpstreamFields::new("core", &upstream_draft(9090))
        .unwrap()
        .into_parts();
    let changed_upstream = Upstream::restore(UpstreamParts {
        settings,
        version: version(2),
        updated_at: later(core.parts().updated_at),
        ..core.parts().clone()
    });
    draft.body_limit = 2_048;
    let changed_route = Route::restore(RouteParts {
        fields: RouteFields::new(&draft).unwrap(),
        version: version(2),
        updated_at: later(created.parts().updated_at),
        ..created.parts().clone()
    });
    let changed_policy = RatePolicy::restore(RatePolicyParts {
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: "per-ip".to_owned(),
            key_kind: RateKeyKind::Subject,
            limit: 200,
            period_seconds: 60,
            burst: 20,
            fallback: RateFallback::Full,
        })
        .unwrap(),
        version: version(2),
        updated_at: later(policy.parts().updated_at),
        ..policy.parts().clone()
    });
    commit(
        &pool,
        gateway_change(
            &mut rng,
            vec![
                ChangeStatement::from(UpstreamStatement::update(&changed_upstream, version(1))),
                ChangeStatement::from(RouteStatement::update(&changed_route, version(1))),
                ChangeStatement::from(RatePolicyStatement::update(&changed_policy, version(1))),
            ],
        ),
    )
    .await
    .unwrap();

    assert_state(
        &pool,
        &upstream_key,
        Some(PolicyState::Upstream(UpstreamState::of(
            changed_upstream.parts(),
        ))),
    )
    .await;
    assert_state(
        &pool,
        &route_key,
        Some(PolicyState::Route(RouteState::of(changed_route.parts()))),
    )
    .await;
    assert_state(
        &pool,
        &policy_key,
        Some(PolicyState::RatePolicy(RatePolicyState::of(
            changed_policy.parts(),
        ))),
    )
    .await;
    assert_head_is_the_digest(&pool).await;

    let deleted_route = Route::restore(RouteParts {
        version: version(3),
        deleted_at: Some(later(changed_route.parts().updated_at)),
        ..changed_route.parts().clone()
    });
    let deleted_policy = RatePolicy::restore(RatePolicyParts {
        version: version(3),
        deleted_at: Some(later(changed_policy.parts().updated_at)),
        ..changed_policy.parts().clone()
    });
    commit(
        &pool,
        gateway_change(
            &mut rng,
            vec![
                ChangeStatement::from(RouteStatement::update(&deleted_route, version(2))),
                ChangeStatement::from(RatePolicyStatement::update(&deleted_policy, version(2))),
                ChangeStatement::from(UpstreamStatement::update(
                    &deleted_upstream(changed_upstream.parts()),
                    version(2),
                )),
            ],
        ),
    )
    .await
    .unwrap();

    assert_state(&pool, &upstream_key, None).await;
    assert_state(&pool, &route_key, None).await;
    assert_state(&pool, &policy_key, None).await;
    assert_head_is_the_digest(&pool).await;
    assert_eq!(epoch_digest(&pool).await, vec![0_u8; 16]);
}

const HOSTS: [&str; 3] = ["a.example.com", "b.example.com", "c.example.com"];
const SERVICES: [&str; 3] = ["core", "billing", "orders"];

/// Every page of the query, followed through the cursor, in the order they come.
async fn pages(repository: &PgRouteRepository, base: RoutePageQuery) -> Vec<RouteId> {
    let mut ids = Vec::new();
    let mut after = None;
    loop {
        let page = repository
            .find_page(&RoutePageQuery {
                after,
                ..base.clone()
            })
            .await
            .unwrap();
        assert!(page.len() <= usize::try_from(base.limit).unwrap());
        let Some(last) = page.last() else {
            return ids;
        };
        after = Some(last.parts().id);
        ids.extend(page.iter().map(|route| route.parts().id));
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn routes_are_listed_by_host_upstream_and_service_in_stable_pages(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let upstreams: Vec<Upstream> = SERVICES
        .iter()
        .map(|service| upstream(&mut rng, service, service))
        .collect();
    commit(
        &pool,
        upstream_change(
            &mut rng,
            upstreams.iter().map(UpstreamStatement::insert).collect(),
        ),
    )
    .await
    .unwrap();
    let mut routes: Vec<RouteParts> = Vec::new();
    for chunk in 0..3_usize {
        let statements: Vec<RouteStatement> = (0..50_usize)
            .map(|offset| {
                let number = chunk
                    .checked_mul(50)
                    .and_then(|base| base.checked_add(offset))
                    .unwrap();
                let target = upstreams[(number / 3) % 3].parts();
                let created = route(
                    &mut rng,
                    &route_draft(
                        HOSTS[number % 3],
                        &format!("/resources/{number}"),
                        &[HttpMethod::Get],
                        target.settings.catalog_service().as_str(),
                        target.id,
                    ),
                );
                routes.push(created.parts().clone());
                RouteStatement::insert(&created)
            })
            .collect();
        commit(&pool, route_change(&mut rng, statements))
            .await
            .unwrap();
    }
    let repository = PgRouteRepository::new(pool.clone());
    let everything = |matches: &dyn Fn(&RouteParts) -> bool| -> Vec<RouteId> {
        let mut ids: Vec<RouteId> = routes
            .iter()
            .filter(|route| matches(route))
            .map(|route| route.id)
            .collect();
        ids.sort();
        ids
    };
    let host = RouteHost::new(HOSTS[1]).unwrap();
    let service = ServiceName::new(SERVICES[2]).unwrap();
    let target = upstreams[0].parts().id;
    let cases: [(RoutePageQuery, Vec<RouteId>); 4] = [
        (
            RoutePageQuery {
                host: Some(host.clone()),
                ..unfiltered(1)
            },
            everything(&|route| route.fields.host() == &host),
        ),
        (
            RoutePageQuery {
                upstream: Some(target),
                ..unfiltered(37)
            },
            everything(&|route| route.fields.upstream_id() == target),
        ),
        (
            RoutePageQuery {
                service: Some(service.clone()),
                ..unfiltered(100)
            },
            everything(&|route| route.fields.service() == &service),
        ),
        (unfiltered(37), everything(&|_route| true)),
    ];

    for (query, expected) in cases {
        let found = pages(&repository, query.clone()).await;
        assert_eq!(found.len(), expected.len(), "{query:?}");
        assert_eq!(found.iter().collect::<BTreeSet<_>>().len(), found.len());
        assert_eq!(found, expected, "{query:?}");
    }
    assert_eq!(everything(&|_route| true).len(), 150);
    assert_eq!(repository.find_by_host(&host).await.unwrap().len(), 50);
    // Route `number` targets upstream `(number / 3) % 3`: 17 of the 50 values of `number / 3` are
    // multiples of 3, and each value covers three routes.
    assert_eq!(repository.count_by_upstream(target).await.unwrap(), 51);
    assert_eq!(
        everything(&|route| route.fields.upstream_id() == target).len(),
        51
    );
}

fn unfiltered(limit: u32) -> RoutePageQuery {
    RoutePageQuery {
        limit,
        after: None,
        host: None,
        upstream: None,
        service: None,
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn upstreams_and_rate_policies_are_listed_in_stable_pages(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let upstreams: Vec<Upstream> = (0..5)
        .map(|index| upstream(&mut rng, &format!("service-{index}"), "core"))
        .collect();
    let policies: Vec<RatePolicy> = (0..5)
        .map(|index| rate_policy(&mut rng, &format!("policy-{index}")))
        .collect();
    commit(
        &pool,
        upstream_change(
            &mut rng,
            upstreams.iter().map(UpstreamStatement::insert).collect(),
        ),
    )
    .await
    .unwrap();
    commit(
        &pool,
        rate_policy_change(
            &mut rng,
            policies.iter().map(RatePolicyStatement::insert).collect(),
        ),
    )
    .await
    .unwrap();
    let upstream_repository = PgUpstreamRepository::new(pool.clone());
    let policy_repository = PgRatePolicyRepository::new(pool.clone());

    let mut found_upstreams = Vec::new();
    let mut after = None;
    loop {
        let page = upstream_repository
            .find_page(&UpstreamPageQuery { limit: 2, after })
            .await
            .unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.parts().id);
        found_upstreams.extend(page.iter().map(|upstream| upstream.parts().id));
    }
    let mut found_policies = Vec::new();
    let mut after = None;
    loop {
        let page = policy_repository
            .find_page(&RatePolicyPageQuery { limit: 2, after })
            .await
            .unwrap();
        let Some(last) = page.last() else { break };
        after = Some(last.parts().id);
        found_policies.extend(page.iter().map(|policy| policy.parts().id));
    }

    let mut expected_upstreams: Vec<UpstreamId> = upstreams
        .iter()
        .map(|upstream| upstream.parts().id)
        .collect();
    expected_upstreams.sort();
    let mut expected_policies: Vec<RatePolicyId> =
        policies.iter().map(|policy| policy.parts().id).collect();
    expected_policies.sort();
    assert_eq!(found_upstreams, expected_upstreams);
    assert_eq!(found_policies, expected_policies);
}
