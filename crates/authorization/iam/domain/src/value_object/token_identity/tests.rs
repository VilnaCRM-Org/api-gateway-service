use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::TokenIdentity;
use crate::value_object::access_token::{AccessToken, AccessTokenParts};
use crate::value_object::service_name::ServiceName;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::{SubjectId, SubjectKind};
use crate::value_object::token_id::TokenId;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn token(subject: SubjectId, session: Option<&str>) -> AccessToken {
    AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-7").unwrap(),
        roles: vec!["ROLE_USER".to_owned(), "ROLE_ADMIN".to_owned()],
        issued_at: at(1_000),
        expires_at: at(1_900),
    })
}

#[test]
fn the_identity_of_a_user_token_keeps_every_identity_claim() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let identity = TokenIdentity::from(&token(SubjectId::User(id), Some("session-1")));

    assert_eq!(identity.subject(), &SubjectId::User(id));
    assert_eq!(identity.subject_kind(), SubjectKind::User);
    assert_eq!(identity.session().map(SessionId::as_str), Some("session-1"));
    assert_eq!(identity.token_id().as_str(), "jti-7");
    assert_eq!(identity.issued_at(), at(1_000));
    assert_eq!(identity.expires_at(), at(1_900));
}

#[test]
fn the_identity_of_a_service_token_has_no_session() {
    let name = ServiceName::new("billing").unwrap();

    let identity = TokenIdentity::from(&token(SubjectId::Service(name.clone()), None));

    assert_eq!(identity.subject(), &SubjectId::Service(name));
    assert_eq!(identity.subject_kind(), SubjectKind::Service);
    assert_eq!(identity.session(), None);
}

#[test]
fn the_identity_holds_no_role() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let printed = format!(
        "{:?}",
        TokenIdentity::from(&token(SubjectId::User(id), Some("s")))
    );

    assert!(!printed.contains("ROLE_"), "{printed}");
}

#[test]
fn the_identity_keeps_the_audiences_of_the_token() {
    let name = ServiceName::new("billing").unwrap();
    let token = token(SubjectId::Service(name), None)
        .with_audiences(vec!["vilnacrm-api".to_owned(), "vilnacrm-iam".to_owned()]);

    let identity = TokenIdentity::from(&token);

    assert_eq!(
        identity.audiences(),
        ["vilnacrm-api".to_owned(), "vilnacrm-iam".to_owned()]
    );
    assert!(identity.has_audience("vilnacrm-iam"));
    assert!(identity.has_audience("vilnacrm-api"));
    assert!(!identity.has_audience("vilnacrm"));
}

#[test]
fn an_identity_without_audiences_has_none_of_them() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let identity = TokenIdentity::from(&token(SubjectId::User(id), Some("s")));

    assert_eq!(identity.audiences(), Vec::<String>::new());
    assert!(!identity.has_audience("vilnacrm-api"));
}

#[test]
fn the_lifetime_is_the_time_from_issue_to_expiry() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let identity = TokenIdentity::from(&token(SubjectId::User(id), Some("s")));

    assert_eq!(identity.lifetime(), Duration::from_mins(15));
}

#[test]
fn an_expiry_before_the_issue_is_no_lifetime() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();
    let token = AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(id),
        session: Some(SessionId::new("s").unwrap()),
        token_id: TokenId::new("jti-8").unwrap(),
        roles: Vec::new(),
        issued_at: at(2_000),
        expires_at: at(1_000),
    });

    assert_eq!(TokenIdentity::from(&token).lifetime(), Duration::ZERO);
}

#[test]
fn the_identity_keeps_the_roles_claim_as_issued() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let identity = TokenIdentity::from(&token(SubjectId::User(id), Some("s")));

    assert_eq!(
        identity.roles(),
        ["ROLE_USER".to_owned(), "ROLE_ADMIN".to_owned()]
    );
}

#[test]
fn the_printed_identity_names_its_fields_but_no_role() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let printed = format!(
        "{:?}",
        TokenIdentity::from(&token(SubjectId::User(id), Some("session-1")))
    );

    assert!(printed.starts_with("TokenIdentity {"), "{printed}");
    assert!(printed.contains("session-1"), "{printed}");
    assert!(printed.contains("jti-7"), "{printed}");
    assert!(!printed.contains("ROLE_"), "{printed}");
}
