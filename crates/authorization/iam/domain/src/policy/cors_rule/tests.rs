use super::CorsRule;
use crate::route::cors::{CorsDraft, CorsPolicy};
use crate::value_object::http_method::HttpMethod;

const CRM: &str = "https://crm.example.test";

fn policy(allow_credentials: bool) -> CorsPolicy {
    CorsPolicy::new(CorsDraft {
        origins: vec![CRM.to_owned()],
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        headers: vec!["Content-Type".to_owned(), "X-Request-Id".to_owned()],
        allow_credentials,
        max_age_seconds: 600,
    })
    .unwrap()
}

#[test]
fn an_allowed_origin_is_granted_with_its_exact_value_and_never_a_wildcard() {
    let policy = policy(true);

    let grant = CorsRule::grant(Some(&policy), CRM).unwrap();

    assert_eq!(grant.origin(), CRM);
    assert!(grant.allow_credentials());
}

#[test]
fn the_grant_follows_the_credentials_flag_of_the_policy() {
    let policy = policy(false);

    assert!(
        !CorsRule::grant(Some(&policy), CRM)
            .unwrap()
            .allow_credentials()
    );
}

#[test]
fn a_foreign_origin_a_different_case_and_a_missing_policy_get_no_grant() {
    let policy = policy(true);

    assert_eq!(
        CorsRule::grant(Some(&policy), "https://evil.example.test"),
        None
    );
    assert_eq!(
        CorsRule::grant(Some(&policy), "https://CRM.example.test"),
        None
    );
    assert_eq!(CorsRule::grant(None, CRM), None);
}

#[test]
fn an_allowed_preflight_answers_with_the_methods_headers_and_max_age_of_the_policy() {
    let policy = policy(true);

    let answer = CorsRule::preflight(
        Some(&policy),
        CRM,
        HttpMethod::Post,
        Some("content-type, X-Request-Id"),
    )
    .unwrap();

    assert_eq!(answer.grant().origin(), CRM);
    assert!(answer.grant().allow_credentials());
    assert_eq!(answer.methods(), "GET, POST");
    assert_eq!(answer.headers(), "Content-Type, X-Request-Id");
    assert_eq!(answer.max_age_seconds(), 600);
}

#[test]
fn a_preflight_without_requested_headers_is_allowed() {
    let policy = policy(true);

    assert!(CorsRule::preflight(Some(&policy), CRM, HttpMethod::Get, None).is_some());
    assert!(CorsRule::preflight(Some(&policy), CRM, HttpMethod::Get, Some(" , ")).is_some());
}

#[test]
fn a_preflight_is_rejected_for_a_foreign_origin_method_or_header_and_without_a_policy() {
    let policy = policy(true);

    assert_eq!(
        CorsRule::preflight(
            Some(&policy),
            "https://evil.example.test",
            HttpMethod::Get,
            None
        ),
        None
    );
    assert_eq!(
        CorsRule::preflight(Some(&policy), CRM, HttpMethod::Delete, None),
        None
    );
    assert_eq!(
        CorsRule::preflight(Some(&policy), CRM, HttpMethod::Get, Some("X-Other")),
        None
    );
    assert_eq!(CorsRule::preflight(None, CRM, HttpMethod::Get, None), None);
}
