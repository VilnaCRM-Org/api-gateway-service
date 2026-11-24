//! Property test of the pruning rule against the token lifetime rule and the revocation rule
//! (FR-79): no token that `TokenLifetimeRule` accepts and a record refuses is ever accepted once
//! the record is tombstoned.
//!
//! Failures replay from `PROPTEST_RNG_SEED`.

use std::time::{Duration, SystemTime};

use proptest::prelude::*;
use shared_domain::Uuid;

use crate::policy::token_lifetime_rule::{TokenLifetimeRule, TokenTimes};
use crate::revocation::prune_policy::PrunePolicy;
use crate::revocation::revocation_rule::{RevocationRule, RevocationStatus};
use crate::value_object::access_token::{AccessToken, AccessTokenParts};
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::SubjectId;
use crate::value_object::token_id::TokenId;
use crate::value_object::token_identity::TokenIdentity;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn identity(issued_at: u64, lifetime: u64) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(issued_at),
        expires_at: at(issued_at.saturating_add(lifetime)),
    }))
}

/// How a record refuses a token: a user cut-off by the `iat`, a revoked session by the session.
#[derive(Debug, Clone, Copy)]
enum Record {
    UserCutoff,
    Session,
}

fn record() -> impl Strategy<Value = Record> {
    prop_oneof![Just(Record::UserCutoff), Just(Record::Session)]
}

/// The status that the record gives while it exists, and the status of a tombstoned record.
fn status(record: Record, cutoff: u64, present: bool) -> RevocationStatus {
    match (record, present) {
        (_, false) => RevocationStatus::default(),
        (Record::UserCutoff, true) => RevocationStatus {
            user_cutoff: Some(at(cutoff)),
            ..RevocationStatus::default()
        },
        (Record::Session, true) => RevocationStatus {
            session_revoked: true,
            ..RevocationStatus::default()
        },
    }
}

proptest! {
    #[test]
    fn a_tombstoned_record_never_lets_through_a_token_it_refused(
        record in record(),
        revoked_at in 1_000_000_u64..2_000_000_000,
        cutoff_delay in 0_u64..=60,
        longest in 1_u64..=1_800,
        lifetime_share in 0_u64..=100,
        skew in 0_u64..=60,
        issued_back in 0_u64..10_000,
        after in 0_u64..100_000,
    ) {
        let cutoff = revoked_at.saturating_add(cutoff_delay);
        let policy = PrunePolicy::new(Duration::from_secs(longest));
        let prune_after = policy.prune_after(at(revoked_at), Some(at(cutoff))).unwrap();
        let prune_secs = prune_after
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lifetime = longest.saturating_mul(lifetime_share).saturating_div(100);
        // A token the record refuses: issued at or before the cut-off instant.
        let issued_at = cutoff.saturating_sub(issued_back);
        let rule = TokenLifetimeRule::new(Duration::from_secs(longest), Duration::from_secs(skew));
        let times = TokenTimes {
            issued_at,
            not_before: None,
            expires_at: issued_at.saturating_add(lifetime),
        };
        let token = identity(issued_at, lifetime);

        // While the record exists the revocation rule refuses the token.
        let before = status(record, cutoff, true);
        prop_assert!(RevocationRule::check(&token, &before).is_err());

        // Once the record is tombstoned, the token lifetime rule refuses the token at every
        // instant at or after `prune_after`.
        let now = at(prune_secs.saturating_add(after));
        let tombstoned = status(record, cutoff, false);
        let accepted = rule.check(times, now).is_ok()
            && RevocationRule::check(&token, &tombstoned).is_ok();
        prop_assert!(!accepted);
    }
}
