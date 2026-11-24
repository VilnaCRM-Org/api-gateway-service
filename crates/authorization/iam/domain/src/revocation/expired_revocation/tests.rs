use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{ExpiredRevocation, MAX_TOMBSTONES_PER_RUN};
use crate::state::key::StateKey;
use crate::value_object::session_id::SessionId;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn session() -> ExpiredRevocation {
    ExpiredRevocation::Session {
        session: SessionId::new("sid-1").unwrap(),
        prune_after: at(),
    }
}

fn cutoff() -> ExpiredRevocation {
    ExpiredRevocation::UserCutoff {
        user: Uuid::parse(USER).unwrap(),
        prune_after: at(),
    }
}

#[test]
fn a_session_names_its_revocation_record() {
    let expired = session();

    assert_eq!(
        expired.state_key(),
        StateKey::SessionRevocation(SessionId::new("sid-1").unwrap())
    );
    assert_eq!(expired.kind(), "session_revocation");
    assert_eq!(expired.target_id(), "sid-1");
    assert_eq!(expired.prune_after(), at());
}

#[test]
fn a_user_cutoff_names_its_cutoff_record() {
    let expired = cutoff();

    assert_eq!(
        expired.state_key(),
        StateKey::UserRevocation(Uuid::parse(USER).unwrap())
    );
    assert_eq!(expired.kind(), "user_cutoff");
    assert_eq!(expired.target_id(), USER);
    assert_eq!(expired.prune_after(), at());
}

#[test]
fn one_commit_removes_at_most_five_hundred_records() {
    assert_eq!(MAX_TOMBSTONES_PER_RUN, 500);
}
