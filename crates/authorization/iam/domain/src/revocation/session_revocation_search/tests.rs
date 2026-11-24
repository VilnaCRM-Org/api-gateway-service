use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shared_domain::Uuid;

use super::SessionRevocationSearch;
use crate::revocation::revocation_source::RevocationSource;
use crate::revocation::session_revocation::SessionRevocation;
use crate::value_object::actor_ref::{ActorRef, SystemComponent};
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn uid(number: u64) -> Uuid {
    Uuid::parse(&format!("0190f2a8-7b3c-7d4e-8f10-{number:012}")).unwrap()
}

fn revocation(id: u64, user: u64, source: RevocationSource, seconds: u64) -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::from_uuid(uid(id)),
        session: SessionId::new(&format!("session-{id}")).unwrap(),
        user: uid(user),
        source,
        revoked_by: ActorRef::System(SystemComponent::UserService),
        revoked_at: at(seconds),
        prune_after: at(seconds.saturating_add(1_000)),
    }
}

fn open() -> SessionRevocationSearch {
    SessionRevocationSearch {
        user: None,
        source: None,
        from: None,
        until: None,
        after: None,
        limit: 10,
    }
}

#[test]
fn a_search_without_conditions_keeps_every_revocation() {
    let record = revocation(1, 7, RevocationSource::Operator, 100);

    assert!(open().matches(&record));
}

#[test]
fn the_user_and_the_source_must_both_match() {
    let record = revocation(1, 7, RevocationSource::Operator, 100);
    let user = Some(uid(7));

    assert!(
        SessionRevocationSearch {
            user,
            source: Some(RevocationSource::Operator),
            ..open()
        }
        .matches(&record)
    );
    assert!(
        !SessionRevocationSearch {
            user: Some(uid(8)),
            ..open()
        }
        .matches(&record)
    );
    assert!(
        !SessionRevocationSearch {
            user,
            source: Some(RevocationSource::UserService),
            ..open()
        }
        .matches(&record)
    );
}

#[test]
fn the_time_range_includes_its_start_and_excludes_its_end() {
    let record = revocation(1, 7, RevocationSource::Operator, 100);

    let starting_now = SessionRevocationSearch {
        from: Some(at(100)),
        ..open()
    };
    let ending_now = SessionRevocationSearch {
        until: Some(at(100)),
        ..open()
    };
    let around = SessionRevocationSearch {
        from: Some(at(99)),
        until: Some(at(101)),
        ..open()
    };

    assert!(starting_now.matches(&record));
    assert!(!ending_now.matches(&record));
    assert!(around.matches(&record));
}

#[test]
fn newer_revocations_sort_first_and_the_identifier_breaks_a_tie_downwards() {
    let older = revocation(9, 7, RevocationSource::Operator, 100);
    let newer = revocation(1, 7, RevocationSource::Operator, 200);
    let tied_low = revocation(2, 7, RevocationSource::Operator, 200);

    let mut records = [&older, &tied_low, &newer];
    records.sort_by_key(|record| SessionRevocationSearch::order_key(record));

    let ids: Vec<SessionRevocationId> = records.iter().map(|record| record.id).collect();
    assert_eq!(
        ids,
        vec![
            SessionRevocationId::from_uuid(uid(2)),
            SessionRevocationId::from_uuid(uid(1)),
            SessionRevocationId::from_uuid(uid(9)),
        ]
    );
}
