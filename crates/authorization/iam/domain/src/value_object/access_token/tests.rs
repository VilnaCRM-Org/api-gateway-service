use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{AccessToken, AccessTokenParts};
use crate::value_object::service_name::ServiceName;
use crate::value_object::session_id::SessionId;
use crate::value_object::subject::{SubjectId, SubjectKind};
use crate::value_object::token_id::TokenId;

fn parts(subject: SubjectId, session: Option<&str>) -> AccessTokenParts {
    AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_000))
            .unwrap(),
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_900))
            .unwrap(),
    }
}

#[test]
fn a_user_token_exposes_every_claim() {
    let id = Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap();

    let token = AccessToken::new(parts(SubjectId::User(id), Some("session-1")));

    assert_eq!(token.subject(), &SubjectId::User(id));
    assert_eq!(token.subject_kind(), SubjectKind::User);
    assert_eq!(token.session().map(SessionId::as_str), Some("session-1"));
    assert_eq!(token.token_id().as_str(), "jti-1");
    assert_eq!(token.roles(), ["ROLE_USER".to_owned()]);
    assert_eq!(
        token.issued_at(),
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_000))
            .unwrap()
    );
    assert_eq!(
        token.expires_at(),
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_900))
            .unwrap()
    );
}

#[test]
fn a_service_token_has_the_service_kind_and_may_lack_a_session() {
    let name = ServiceName::new("user-service").unwrap();

    let token = AccessToken::new(parts(SubjectId::Service(name.clone()), None));

    assert_eq!(token.subject(), &SubjectId::Service(name));
    assert_eq!(token.subject_kind(), SubjectKind::Service);
    assert_eq!(token.session(), None);
}

#[test]
fn a_new_token_names_no_audience() {
    let token = AccessToken::new(parts(
        SubjectId::Service(ServiceName::new("billing").unwrap()),
        None,
    ));

    assert_eq!(token.audiences(), Vec::<String>::new());
}

#[test]
fn the_audiences_of_the_aud_claim_are_kept_in_order() {
    let token = AccessToken::new(parts(
        SubjectId::Service(ServiceName::new("billing").unwrap()),
        None,
    ))
    .with_audiences(vec!["vilnacrm-api".to_owned(), "vilnacrm-iam".to_owned()]);

    assert_eq!(
        token.audiences(),
        ["vilnacrm-api".to_owned(), "vilnacrm-iam".to_owned()]
    );
    assert_eq!(token.subject_kind(), SubjectKind::Service);
}
