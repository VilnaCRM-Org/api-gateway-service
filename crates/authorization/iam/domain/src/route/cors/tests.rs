use rstest::rstest;

use super::{CorsDraft, CorsPolicy};
use crate::error::InvalidRoute;
use crate::value_object::http_method::HttpMethod;

fn draft() -> CorsDraft {
    CorsDraft {
        origins: vec!["https://app.example.com".to_owned()],
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        headers: vec!["Content-Type".to_owned(), "X-Request-Id".to_owned()],
        allow_credentials: true,
        max_age_seconds: 86_400,
    }
}

#[test]
fn a_valid_draft_is_kept() {
    let policy = CorsPolicy::new(draft()).unwrap();

    assert_eq!(policy.origins(), ["https://app.example.com"]);
    assert_eq!(policy.methods(), [HttpMethod::Get, HttpMethod::Post]);
    assert_eq!(policy.headers(), ["Content-Type", "X-Request-Id"]);
    assert!(policy.allow_credentials());
    assert_eq!(policy.max_age_seconds(), 86_400);
}

#[rstest]
#[case::no_origin(vec![], InvalidRoute::CorsOriginRequired)]
#[case::wildcard(vec!["*".to_owned()], InvalidRoute::CorsOriginFormat)]
#[case::no_scheme(vec!["app.example.com".to_owned()], InvalidRoute::CorsOriginFormat)]
#[case::path(vec!["https://app.example.com/x".to_owned()], InvalidRoute::CorsOriginFormat)]
#[case::empty_authority(vec!["https://".to_owned()], InvalidRoute::CorsOriginFormat)]
fn invalid_origins_are_refused(#[case] origins: Vec<String>, #[case] expected: InvalidRoute) {
    let violations = CorsPolicy::new(CorsDraft { origins, ..draft() }).unwrap_err();

    assert_eq!(violations, vec![expected]);
}

#[test]
fn an_invalid_header_is_refused() {
    let violations = CorsPolicy::new(CorsDraft {
        headers: vec!["Bad Header".to_owned()],
        ..draft()
    })
    .unwrap_err();

    assert_eq!(violations, vec![InvalidRoute::CorsHeaderFormat]);
}

#[rstest]
#[case(-1)]
#[case(86_401)]
#[case(4_294_967_297)]
fn a_max_age_outside_one_day_is_refused(#[case] seconds: i64) {
    let violations = CorsPolicy::new(CorsDraft {
        max_age_seconds: seconds,
        ..draft()
    })
    .unwrap_err();

    assert_eq!(violations, vec![InvalidRoute::CorsMaxAgeRange]);
}

#[test]
fn every_violation_is_reported() {
    let violations = CorsPolicy::new(CorsDraft {
        origins: Vec::new(),
        headers: vec![String::new()],
        max_age_seconds: -1,
        ..draft()
    })
    .unwrap_err();

    assert_eq!(
        violations,
        vec![
            InvalidRoute::CorsOriginRequired,
            InvalidRoute::CorsHeaderFormat,
            InvalidRoute::CorsMaxAgeRange,
        ]
    );
}

#[test]
fn a_zero_max_age_is_allowed() {
    let policy = CorsPolicy::new(CorsDraft {
        max_age_seconds: 0,
        ..draft()
    })
    .unwrap();

    assert_eq!(policy.max_age_seconds(), 0);
}
