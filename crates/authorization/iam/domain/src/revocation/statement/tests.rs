use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::RevocationStatement;
use crate::revocation::global_token_cutoff::GlobalTokenCutoff;
use crate::revocation::revocation_source::RevocationSource;
use crate::revocation::session_revocation::SessionRevocation;
use crate::revocation::user_token_cutoff::UserTokenCutoff;
use crate::state::key::StateKey;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::change_statement::ChangeStatement;
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn session() -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::from_uuid(
            Uuid::parse("00000000-0000-7000-8000-000000000001").unwrap(),
        ),
        session: SessionId::new("sid-1").unwrap(),
        user: user(),
        source: RevocationSource::Operator,
        revoked_by: ActorRef::User(user()),
        revoked_at: at(),
        prune_after: at(),
    }
}

#[test]
fn a_session_statement_names_the_session_record() {
    let statement = RevocationStatement::Session(session());

    assert_eq!(
        statement.state_key(),
        StateKey::SessionRevocation(SessionId::new("sid-1").unwrap())
    );
}

#[test]
fn a_user_cutoff_statement_names_the_user_record() {
    let statement = RevocationStatement::UserCutoff(UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(),
        source: RevocationSource::Operator,
        updated_at: at(),
        prune_after: at(),
    });

    assert_eq!(statement.state_key(), StateKey::UserRevocation(user()));
}

#[test]
fn a_global_cutoff_statement_names_the_global_record() {
    let statement = RevocationStatement::GlobalCutoff(GlobalTokenCutoff {
        tokens_valid_after: at(),
        set_by: ActorRef::User(user()),
        set_at: at(),
    });

    assert_eq!(statement.state_key(), StateKey::GlobalRevocation);
}

#[test]
fn a_revocation_statement_becomes_a_save_revocation_change_statement() {
    let statement = RevocationStatement::Session(session());

    let change = ChangeStatement::from(statement.clone());

    assert_eq!(change, ChangeStatement::SaveRevocation(Box::new(statement)));
    assert_eq!(
        change.state_keys(),
        vec![StateKey::SessionRevocation(
            SessionId::new("sid-1").unwrap()
        )]
    );
}
