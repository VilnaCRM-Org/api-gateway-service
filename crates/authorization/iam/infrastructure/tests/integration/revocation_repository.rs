//! `PgRevocationRepository` and `PgRevocationView` over the `create_iam_token_revocations`
//! tables: writes and reads, the rules that keep the first session record and never move a
//! cut-off back, the once-per-event inbound record and the constraints of the tables.

use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, ActorRef, GlobalTokenCutoff, InboundEvent, InboundOutcome,
    RepositoryError, RevocationRepository as _, RevocationSource, RevocationStatus,
    RevocationView as _, ServiceName, SessionId, SessionRevocation, SessionRevocationId,
    SessionRevocationSearch, SubjectId, TokenId, TokenIdentity, UserTokenCutoff,
};
use iam_infrastructure::{PgRevocationRepository, PgRevocationView};
use shared_domain::Uuid;
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::PgPool;

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const FIRST: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f00-000000000002";
const NOW: u64 = 1_800_000_000;

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn session(name: &str) -> SessionId {
    SessionId::new(name).unwrap()
}

fn revocation(id: &str, session_name: &str, revoked_at: u64) -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::parse(id).unwrap(),
        session: session(session_name),
        user: user(),
        source: RevocationSource::UserService,
        revoked_by: ActorRef::parse("system:user-service").unwrap(),
        revoked_at: at(revoked_at),
        prune_after: at(revoked_at.checked_add(900).unwrap()),
    }
}

fn user_cutoff(seconds: u64) -> UserTokenCutoff {
    UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(seconds),
        source: RevocationSource::Operator,
        updated_at: at(seconds.checked_add(1).unwrap()),
        prune_after: at(seconds.checked_add(900).unwrap()),
    }
}

fn global_cutoff(seconds: u64) -> GlobalTokenCutoff {
    GlobalTokenCutoff {
        tokens_valid_after: at(seconds),
        set_by: ActorRef::parse(&format!("user:{USER}")).unwrap(),
        set_at: at(seconds.checked_add(2).unwrap()),
    }
}

fn event(id: &str, outcome: InboundOutcome) -> InboundEvent {
    InboundEvent {
        event_id: Uuid::parse(id).unwrap(),
        topic: "user-events".to_owned(),
        partition: 3,
        offset: 42,
        event_type: "SessionRevoked".to_owned(),
        outcome,
        error: None,
        processed_at: at(NOW),
    }
}

fn identity(subject: SubjectId, session_name: Option<&str>) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session_name.map(session),
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    }))
}

fn search() -> SessionRevocationSearch {
    SessionRevocationSearch {
        user: None,
        source: None,
        from: None,
        until: None,
        after: None,
        limit: 10,
    }
}

fn operator_revocation(id: &str, session_name: &str, revoked_at: u64) -> SessionRevocation {
    SessionRevocation {
        source: RevocationSource::Operator,
        revoked_by: ActorRef::parse(&format!("user:{USER}")).unwrap(),
        ..revocation(id, session_name, revoked_at)
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_migrated_database_holds_no_revocation(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool.clone());
    let view = PgRevocationView::new(pool);

    assert!(
        repository
            .session_revocation(&session("session-1"))
            .await
            .unwrap()
            .is_none()
    );
    assert!(repository.user_cutoff(user()).await.unwrap().is_none());
    assert!(repository.global_cutoff().await.unwrap().is_none());
    let status = view
        .status(&identity(SubjectId::User(user()), Some("session-1")))
        .await
        .unwrap();
    assert_eq!(status, RevocationStatus::default());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_session_revocation_is_read_back_and_keeps_its_first_record(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);

    repository
        .revoke_session(&revocation(FIRST, "session-1", NOW))
        .await
        .unwrap();
    repository
        .revoke_session(&revocation(SECOND, "session-1", NOW + 10))
        .await
        .unwrap();

    let stored = repository
        .session_revocation(&session("session-1"))
        .await
        .unwrap();
    assert_eq!(stored, Some(revocation(FIRST, "session-1", NOW)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_record_id_of_another_session_already_exists(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);
    repository
        .revoke_session(&revocation(FIRST, "session-1", NOW))
        .await
        .unwrap();

    let error = repository
        .revoke_session(&revocation(FIRST, "session-2", NOW))
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_user_cutoff_is_read_back_and_never_moves_back(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);

    repository.set_user_cutoff(&user_cutoff(NOW)).await.unwrap();
    repository
        .set_user_cutoff(&user_cutoff(NOW - 100))
        .await
        .unwrap();
    assert_eq!(
        repository.user_cutoff(user()).await.unwrap(),
        Some(user_cutoff(NOW))
    );

    repository
        .set_user_cutoff(&user_cutoff(NOW + 100))
        .await
        .unwrap();
    assert_eq!(
        repository.user_cutoff(user()).await.unwrap(),
        Some(user_cutoff(NOW + 100))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_global_cutoff_is_read_back_and_never_moves_back(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);

    repository
        .set_global_cutoff(&global_cutoff(NOW))
        .await
        .unwrap();
    repository
        .set_global_cutoff(&global_cutoff(NOW - 100))
        .await
        .unwrap();
    assert_eq!(
        repository.global_cutoff().await.unwrap(),
        Some(global_cutoff(NOW))
    );

    repository
        .set_global_cutoff(&global_cutoff(NOW + 100))
        .await
        .unwrap();
    assert_eq!(
        repository.global_cutoff().await.unwrap(),
        Some(global_cutoff(NOW + 100))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_inbound_event_is_recorded_once_per_event_id(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool.clone());

    let first = repository
        .record_inbound_event(&event(FIRST, InboundOutcome::Applied))
        .await
        .unwrap();
    let redelivery = repository
        .record_inbound_event(&event(FIRST, InboundOutcome::Ignored))
        .await
        .unwrap();
    let other = repository
        .record_inbound_event(&InboundEvent {
            error: Some("the record cannot be decoded".to_owned()),
            ..event(SECOND, InboundOutcome::DeadLetter)
        })
        .await
        .unwrap();

    assert!(first);
    assert!(!redelivery);
    assert!(other);
    let outcomes: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT outcome, error FROM iam_inbound_events ORDER BY event_id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        outcomes,
        vec![
            ("applied".to_owned(), None),
            (
                "dead_letter".to_owned(),
                Some("the record cannot be decoded".to_owned())
            ),
        ]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_view_reads_the_session_and_both_cutoffs_of_a_user_token(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool.clone());
    let view = PgRevocationView::new(pool);
    repository
        .revoke_session(&revocation(FIRST, "session-1", NOW))
        .await
        .unwrap();
    repository.set_user_cutoff(&user_cutoff(NOW)).await.unwrap();
    repository
        .set_global_cutoff(&global_cutoff(NOW - 10))
        .await
        .unwrap();

    let revoked = view
        .status(&identity(SubjectId::User(user()), Some("session-1")))
        .await
        .unwrap();
    let other_session = view
        .status(&identity(SubjectId::User(user()), Some("session-2")))
        .await
        .unwrap();

    assert_eq!(
        revoked,
        RevocationStatus {
            session_revoked: true,
            user_cutoff: Some(at(NOW)),
            global_cutoff: Some(at(NOW - 10)),
        }
    );
    assert!(!other_session.session_revoked);
    assert_eq!(other_session.user_cutoff, Some(at(NOW)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_token_is_read_with_the_global_cutoff_only(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool.clone());
    let view = PgRevocationView::new(pool);
    repository.set_user_cutoff(&user_cutoff(NOW)).await.unwrap();
    repository
        .set_global_cutoff(&global_cutoff(NOW - 10))
        .await
        .unwrap();
    let service = SubjectId::Service(ServiceName::new("user-service").unwrap());

    let status = view.status(&identity(service, None)).await.unwrap();

    assert_eq!(
        status,
        RevocationStatus {
            session_revoked: false,
            user_cutoff: None,
            global_cutoff: Some(at(NOW - 10)),
        }
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_primary_key_rejects_an_inbound_event_id_recorded_twice(pool: PgPool) {
    let insert = "INSERT INTO iam_inbound_events \
        (event_id, topic, partition, \"offset\", event_type, outcome, error, processed_at) \
        VALUES ('0190f2a8-7b3c-7d4e-8f00-000000000001', 'user-events', 0, 1, 'SessionRevoked', \
        'applied', NULL, now())";
    sqlx::query(insert).execute(&pool).await.unwrap();

    let error = sqlx::query(insert).execute(&pool).await.unwrap_err();

    let database = error.as_database_error().unwrap();
    assert!(database.is_unique_violation());
    assert_eq!(database.constraint(), Some("iam_inbound_events_pkey"));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_check_constraint_rejects_a_second_global_cutoff_row(pool: PgPool) {
    sqlx::query(
        "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at) \
         VALUES (1, now(), 'system:bootstrap', now())",
    )
    .execute(&pool)
    .await
    .unwrap();

    let error = sqlx::query(
        "INSERT INTO iam_global_token_cutoff (id, tokens_valid_after, set_by, set_at) \
         VALUES (2, now(), 'system:bootstrap', now())",
    )
    .execute(&pool)
    .await
    .unwrap_err();

    let database = error.as_database_error().unwrap();
    assert!(database.is_check_violation());
    assert_eq!(
        database.constraint(),
        Some("iam_global_token_cutoff_id_check")
    );
}

#[tokio::test]
async fn an_unreachable_database_makes_every_call_unavailable() {
    let settings = PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout: Duration::from_millis(200),
        statement_timeout: Duration::from_secs(1),
    };
    let pool = connect_lazy(&settings).unwrap();
    let repository = PgRevocationRepository::new(pool.clone());
    let view = PgRevocationView::new(pool);

    let read = repository.global_cutoff().await.unwrap_err();
    let by_id = repository
        .session_revocation_by_id(SessionRevocationId::parse(FIRST).unwrap())
        .await
        .unwrap_err();
    let searched = repository
        .search_session_revocations(&search())
        .await
        .unwrap_err();
    let write = repository
        .set_global_cutoff(&global_cutoff(NOW))
        .await
        .unwrap_err();
    let status = view
        .status(&identity(SubjectId::User(user()), Some("session-1")))
        .await
        .unwrap_err();

    assert!(matches!(read, RepositoryError::Unavailable(_)));
    assert!(matches!(by_id, RepositoryError::Unavailable(_)));
    assert!(matches!(searched, RepositoryError::Unavailable(_)));
    assert!(matches!(write, RepositoryError::Unavailable(_)));
    assert!(matches!(status, RepositoryError::Unavailable(_)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_session_revocation_is_found_by_its_identifier(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);
    let stored = operator_revocation(FIRST, "session-1", NOW);
    repository.revoke_session(&stored).await.unwrap();

    let found = repository
        .session_revocation_by_id(stored.id)
        .await
        .unwrap();
    let unknown = repository
        .session_revocation_by_id(SessionRevocationId::parse(SECOND).unwrap())
        .await
        .unwrap();

    assert_eq!(found, Some(stored));
    assert_eq!(unknown, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_search_returns_the_newest_revocations_first_and_applies_every_filter(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);
    let old = revocation(FIRST, "session-1", NOW);
    let newer = operator_revocation(SECOND, "session-2", NOW + 10);
    repository.revoke_session(&old).await.unwrap();
    repository.revoke_session(&newer).await.unwrap();

    let all = repository
        .search_session_revocations(&search())
        .await
        .unwrap();
    let operator = repository
        .search_session_revocations(&SessionRevocationSearch {
            source: Some(RevocationSource::Operator),
            ..search()
        })
        .await
        .unwrap();
    let in_range = repository
        .search_session_revocations(&SessionRevocationSearch {
            from: Some(at(NOW)),
            until: Some(at(NOW + 10)),
            ..search()
        })
        .await
        .unwrap();
    let other_user = repository
        .search_session_revocations(&SessionRevocationSearch {
            user: Some(Uuid::parse(FIRST).unwrap()),
            ..search()
        })
        .await
        .unwrap();

    assert_eq!(all, vec![newer.clone(), old.clone()]);
    assert_eq!(operator, vec![newer]);
    assert_eq!(in_range, vec![old]);
    assert_eq!(other_user.len(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn cursor_pages_hold_every_revocation_exactly_once_even_at_one_instant(pool: PgPool) {
    let repository = PgRevocationRepository::new(pool);
    let ids = [
        "0190f2a8-7b3c-7d4e-8f00-000000000011",
        "0190f2a8-7b3c-7d4e-8f00-000000000012",
        "0190f2a8-7b3c-7d4e-8f00-000000000013",
        "0190f2a8-7b3c-7d4e-8f00-000000000014",
        "0190f2a8-7b3c-7d4e-8f00-000000000015",
    ];
    for (index, id) in ids.iter().enumerate() {
        let instant = if index < 3 { NOW } else { NOW + 5 };
        repository
            .revoke_session(&revocation(id, &format!("page-{index}"), instant))
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = repository
            .search_session_revocations(&SessionRevocationSearch {
                after,
                limit: 2,
                ..search()
            })
            .await
            .unwrap();
        seen.extend(page.iter().map(|record| record.id));
        match page.last() {
            Some(last) if page.len() == 2 => after = Some(last.id),
            _ => break,
        }
    }

    assert_eq!(seen.len(), 5);
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 5);
    assert_eq!(
        seen.first().copied(),
        Some(SessionRevocationId::parse(ids[4]).unwrap())
    );
}
