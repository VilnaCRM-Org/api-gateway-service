use std::collections::BTreeSet;

use super::*;

fn log_epoch(value: i64) -> LogEpoch {
    LogEpoch::new(value).unwrap()
}

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

#[test]
fn a_row_id_is_the_same_for_the_same_place_in_the_log() {
    assert_eq!(
        row_id(log_epoch(0), version(5), 2),
        row_id(log_epoch(0), version(5), 2)
    );
}

#[test]
fn no_two_places_in_the_log_share_a_row_id() {
    let ids: BTreeSet<_> = [
        row_id(log_epoch(0), version(5), 1),
        row_id(log_epoch(0), version(5), 2),
        row_id(log_epoch(0), version(6), 1),
        row_id(log_epoch(1), version(5), 1),
    ]
    .into_iter()
    .collect();

    assert_eq!(ids.len(), 4);
}

#[test]
fn a_time_becomes_whole_microseconds_since_1970() {
    let time = OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();

    assert_eq!(micros(time).unwrap(), 1_700_000_000_123_456);
}

#[test]
fn a_value_out_of_range_is_unavailable_with_its_cause() {
    let error = out_of_range();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        InvalidIamValue::AuditTimestamp.to_string()
    );
}

#[test]
fn an_invalid_state_is_unavailable_with_its_cause() {
    let error = unusable(iam_domain::InvalidStateRecord::Encoding);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert_eq!(
        error.source().unwrap().to_string(),
        "The state cannot be encoded."
    );
}

#[test]
fn the_policy_state_topic_is_iam_policy_state_v1() {
    assert_eq!(POLICY_TOPIC, "iam.policy.state.v1");
}

#[test]
fn only_the_entities_of_the_tables_of_the_change_are_read() {
    let role = RoleId::from_uuid(Uuid::parse("0192f6a0-0000-7000-8000-000000000001").unwrap());
    let subject = SubjectRef::user(Uuid::parse("0192f6a0-0000-7000-8000-000000000002").unwrap());

    assert_eq!(entity(&StateKey::Role(role)), Some(Entity::Role(role)));
    assert_eq!(
        entity(&StateKey::Subject(subject.clone())),
        Some(Entity::Subject(&subject))
    );
    assert_eq!(entity(&StateKey::Head), None);
    assert_eq!(
        entity(&StateKey::GlobalRevocation),
        Some(Entity::Revocation(Revocation::Global))
    );
}

#[test]
fn an_upstream_a_route_and_a_rate_policy_are_read_from_their_tables() {
    let name = UpstreamName::new("core").unwrap();
    let route = RouteId::from_uuid(Uuid::parse("0192f6a0-0000-7000-8000-0000000000a1").unwrap());
    let policy =
        RatePolicyId::from_uuid(Uuid::parse("0192f6a0-0000-7000-8000-0000000000a2").unwrap());

    assert_eq!(
        entity(&StateKey::Upstream(name.clone())),
        Some(Entity::Upstream(&name))
    );
    assert_eq!(entity(&StateKey::Route(route)), Some(Entity::Route(route)));
    assert_eq!(
        entity(&StateKey::RatePolicy(policy)),
        Some(Entity::RatePolicy(policy))
    );
}

#[test]
fn a_revoked_session_and_a_user_cutoff_are_read_from_the_revocation_tables() {
    let session = SessionId::new("sid-1").unwrap();
    let user = Uuid::parse("0192f6a0-0000-7000-8000-0000000000b1").unwrap();

    assert_eq!(
        entity(&StateKey::SessionRevocation(session.clone())),
        Some(Entity::Revocation(Revocation::Session(&session)))
    );
    assert_eq!(
        entity(&StateKey::UserRevocation(user)),
        Some(Entity::Revocation(Revocation::User(user)))
    );
}

/// Stores an active GraphQL version of `orders` whose `Query.order` returns `return_type`.
async fn seed_version(pool: &sqlx::PgPool, (return_type, tag): (&str, u8)) {
    sqlx::query(
        "WITH spec AS (
            INSERT INTO iam_graphql_specs (id, service, content_hash, sdl, status, uploaded_by,
                created_at)
            VALUES (gen_random_uuid(), 'orders', sha256(convert_to($1, 'UTF8')), $1, 'active',
                'system:test', now())
            RETURNING id
        )
        INSERT INTO iam_graphql_spec_fields (spec_id, type_name, field_name, return_type,
            sensitive, audit_always)
        SELECT id, 'Query', 'order', $2, FALSE, FALSE FROM spec",
    )
    .bind(format!("type Query {{ order: {return_type} }} # {tag}"))
    .bind(return_type)
    .execute(pool)
    .await
    .unwrap();
}

async fn published_return_type(pool: &sqlx::PgPool) -> Option<String> {
    sqlx::query(
        "INSERT INTO iam_graphql_permissions (id, permission_key, service, type_name, field_name,
            sensitive, audit_always, created_at)
        VALUES (gen_random_uuid(), 'gql:orders:Query.order', 'orders', 'Query', 'order', FALSE,
            FALSE, now())",
    )
    .execute(pool)
    .await
    .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let service = ServiceName::new("orders").unwrap();
    read_entries(&mut connection, &service)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.key == "gql:orders:Query.order")
        .unwrap()
        .return_type
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn active_versions_that_agree_publish_the_return_type(pool: sqlx::PgPool) {
    seed_version(&pool, ("Order", 1)).await;
    seed_version(&pool, ("Order", 2)).await;

    assert_eq!(published_return_type(&pool).await.as_deref(), Some("Order"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn active_versions_that_disagree_publish_no_return_type(pool: sqlx::PgPool) {
    seed_version(&pool, ("Order", 1)).await;
    seed_version(&pool, ("Parcel", 2)).await;

    assert_eq!(published_return_type(&pool).await, None);
}
