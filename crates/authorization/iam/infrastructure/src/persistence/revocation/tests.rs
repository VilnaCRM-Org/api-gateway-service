use std::error::Error as _;
use std::time::Duration;

use super::*;

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const REVOCATION: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";

fn sql_uuid(text: &str) -> SqlUuid {
    Uuid::parse(text).unwrap().as_uuid()
}

fn stamp(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn session_row() -> SessionRow {
    SessionRow {
        session_id: "session-1".to_owned(),
        id: sql_uuid(REVOCATION),
        user_id: sql_uuid(USER),
        source: "user-service".to_owned(),
        revoked_by: "system:user-service".to_owned(),
        revoked_at: stamp(1_800_000_000),
        prune_after: stamp(1_800_000_900),
    }
}

fn user_cutoff_row() -> UserCutoffRow {
    UserCutoffRow {
        user_id: sql_uuid(USER),
        tokens_valid_after: stamp(1_800_000_000),
        source: "operator".to_owned(),
        updated_at: stamp(1_800_000_001),
        prune_after: stamp(1_800_000_900),
    }
}

fn global_cutoff_row() -> GlobalCutoffRow {
    GlobalCutoffRow {
        tokens_valid_after: stamp(1_800_000_000),
        set_by: format!("user:{USER}"),
        set_at: stamp(1_800_000_002),
    }
}

#[test]
fn a_valid_session_row_is_restored_with_every_column() {
    let revocation = restore_session(&session_row()).unwrap();

    assert_eq!(
        revocation,
        SessionRevocation {
            id: SessionRevocationId::from_uuid(Uuid::parse(REVOCATION).unwrap()),
            session: SessionId::new("session-1").unwrap(),
            user: Uuid::parse(USER).unwrap(),
            source: RevocationSource::UserService,
            revoked_by: ActorRef::parse("system:user-service").unwrap(),
            revoked_at: at(1_800_000_000),
            prune_after: at(1_800_000_900),
        }
    );
}

#[test]
fn a_session_row_with_an_unknown_source_is_unavailable() {
    let row = SessionRow {
        source: "somebody".to_owned(),
        ..session_row()
    };

    let error = restore_session(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_session_row_with_an_invalid_session_id_is_unavailable() {
    let row = SessionRow {
        session_id: String::new(),
        ..session_row()
    };

    let error = restore_session(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_session_row_with_an_invalid_actor_is_unavailable() {
    let row = SessionRow {
        revoked_by: "nobody".to_owned(),
        ..session_row()
    };

    let error = restore_session(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_valid_user_cutoff_row_is_restored_with_every_column() {
    let cutoff = restore_user_cutoff(&user_cutoff_row()).unwrap();

    assert_eq!(
        cutoff,
        UserTokenCutoff {
            user: Uuid::parse(USER).unwrap(),
            tokens_valid_after: at(1_800_000_000),
            source: RevocationSource::Operator,
            updated_at: at(1_800_000_001),
            prune_after: at(1_800_000_900),
        }
    );
}

#[test]
fn a_user_cutoff_row_with_an_unknown_source_is_unavailable() {
    let row = UserCutoffRow {
        source: "somebody".to_owned(),
        ..user_cutoff_row()
    };

    let error = restore_user_cutoff(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_valid_global_cutoff_row_is_restored_with_every_column() {
    let cutoff = restore_global_cutoff(&global_cutoff_row()).unwrap();

    assert_eq!(
        cutoff,
        GlobalTokenCutoff {
            tokens_valid_after: at(1_800_000_000),
            set_by: ActorRef::parse(&format!("user:{USER}")).unwrap(),
            set_at: at(1_800_000_002),
        }
    );
}

#[test]
fn a_global_cutoff_row_with_an_invalid_actor_is_unavailable() {
    let row = GlobalCutoffRow {
        set_by: "nobody".to_owned(),
        ..global_cutoff_row()
    };

    let error = restore_global_cutoff(&row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_time_round_trips_through_its_timestamp_to_the_nanosecond() {
    let time = UNIX_EPOCH + Duration::new(1_800_000_000, 123_456_789);

    let stored = timestamp(time).unwrap();

    assert_eq!(stored.unix_timestamp(), 1_800_000_000);
    assert_eq!(stored.nanosecond(), 123_456_789);
    assert_eq!(system_time(stored), time);
}

#[test]
fn a_time_before_1970_is_unavailable() {
    let error = timestamp(UNIX_EPOCH.checked_sub(Duration::from_secs(1)).unwrap()).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_time_after_the_year_9999_is_unavailable() {
    let error = timestamp(
        UNIX_EPOCH
            .checked_add(Duration::from_hours(70_389_528))
            .unwrap(),
    )
    .unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn a_row_that_is_not_found_is_an_unavailable_repository() {
    assert!(matches!(
        translate(sqlx::Error::RowNotFound),
        RepositoryError::Unavailable(_)
    ));
    assert!(matches!(
        unavailable(sqlx::Error::PoolTimedOut),
        RepositoryError::Unavailable(_)
    ));
}
