use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, ServiceName, SessionId, SubjectId, SubjectKind, TokenId,
    TokenIdentity,
};
use shared_domain::Uuid;

use super::Principal;

fn identity(subject: SubjectId, session: Option<&str>) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-3").unwrap(),
        roles: vec!["ROLE_ADMIN".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    }))
}

#[test]
fn a_user_principal_keeps_the_subject_the_session_and_the_token_id() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let principal = Principal::from(identity(SubjectId::User(id), Some("session-1")));

    assert_eq!(principal.subject(), &SubjectId::User(id));
    assert_eq!(principal.subject_kind(), SubjectKind::User);
    assert_eq!(
        principal.session().map(SessionId::as_str),
        Some("session-1")
    );
    assert_eq!(principal.token_id().as_str(), "jti-3");
}

#[test]
fn a_service_principal_has_its_service_name_and_no_session() {
    let name = ServiceName::new("billing").unwrap();

    let principal = Principal::from(identity(SubjectId::Service(name.clone()), None));

    assert_eq!(principal.subject(), &SubjectId::Service(name));
    assert_eq!(principal.subject_kind(), SubjectKind::Service);
    assert_eq!(principal.session(), None);
}

#[test]
fn a_principal_prints_no_role() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let printed = format!(
        "{:?}",
        Principal::from(identity(SubjectId::User(id), Some("s")))
    );

    assert!(!printed.contains("ROLE_"), "{printed}");
}

#[test]
fn a_principal_keeps_the_roles_claim_and_the_expiry_of_its_token() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let principal = Principal::from(identity(SubjectId::User(id), Some("s")));

    assert_eq!(principal.roles(), ["ROLE_ADMIN".to_owned()]);
    assert_eq!(
        principal.expires_at(),
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap()
    );
}

#[test]
fn a_printed_principal_names_its_subject_and_token_but_no_role() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let printed = format!(
        "{:?}",
        Principal::from(identity(SubjectId::User(id), Some("session-1")))
    );

    assert!(printed.starts_with("Principal {"), "{printed}");
    assert!(printed.contains("session-1"), "{printed}");
    assert!(printed.contains("jti-3"), "{printed}");
}
