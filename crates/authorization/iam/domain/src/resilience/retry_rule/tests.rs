use rstest::rstest;

use super::*;

fn case() -> RetryCase {
    RetryCase {
        policy: RetryPolicy::Idempotent,
        method: HttpMethod::Get,
        graphql: false,
        body: RequestBody::Empty,
        delivery: Delivery::MaybeSent,
        retries_made: 0,
    }
}

#[rstest]
#[case::get(HttpMethod::Get, true)]
#[case::head(HttpMethod::Head, true)]
#[case::put(HttpMethod::Put, true)]
#[case::delete(HttpMethod::Delete, true)]
#[case::options(HttpMethod::Options, true)]
#[case::post(HttpMethod::Post, false)]
#[case::patch(HttpMethod::Patch, false)]
fn a_sent_request_is_retried_only_for_an_idempotent_method(
    #[case] method: HttpMethod,
    #[case] retried: bool,
) {
    let case = RetryCase { method, ..case() };

    assert_eq!(RetryRule::allows(&case), retried);
}

#[rstest]
#[case::idempotent(RetryPolicy::Idempotent, true)]
#[case::none(RetryPolicy::None, false)]
fn a_sent_request_is_retried_only_under_the_idempotent_policy(
    #[case] policy: RetryPolicy,
    #[case] retried: bool,
) {
    let case = RetryCase { policy, ..case() };

    assert_eq!(RetryRule::allows(&case), retried);
}

#[rstest]
#[case::get(HttpMethod::Get)]
#[case::post(HttpMethod::Post)]
#[case::patch(HttpMethod::Patch)]
fn a_request_that_was_not_sent_is_retried_whatever_the_policy(#[case] method: HttpMethod) {
    let case = RetryCase {
        policy: RetryPolicy::None,
        method,
        body: RequestBody::Streamed,
        delivery: Delivery::NotSent,
        ..case()
    };

    assert!(RetryRule::allows(&case));
}

#[rstest]
#[case::empty(RequestBody::Empty, true)]
#[case::small(RequestBody::Buffered(0), true)]
#[case::just_below(RequestBody::Buffered(MAX_BUFFERED_BODY_BYTES - 1), true)]
#[case::at_the_limit(RequestBody::Buffered(MAX_BUFFERED_BODY_BYTES), false)]
#[case::above(RequestBody::Buffered(MAX_BUFFERED_BODY_BYTES + 1), false)]
#[case::streamed(RequestBody::Streamed, false)]
fn a_sent_request_is_retried_only_with_no_body_or_a_small_buffered_one(
    #[case] body: RequestBody,
    #[case] retried: bool,
) {
    let case = RetryCase {
        method: HttpMethod::Put,
        body,
        ..case()
    };

    assert_eq!(RetryRule::allows(&case), retried);
}

#[rstest]
#[case::post(HttpMethod::Post, Delivery::NotSent)]
#[case::put(HttpMethod::Put, Delivery::MaybeSent)]
#[case::put_unsent(HttpMethod::Put, Delivery::NotSent)]
#[case::delete(HttpMethod::Delete, Delivery::MaybeSent)]
fn a_graphql_request_that_may_carry_a_mutation_is_never_retried(
    #[case] method: HttpMethod,
    #[case] delivery: Delivery,
) {
    let case = RetryCase {
        graphql: true,
        method,
        delivery,
        ..case()
    };

    assert!(!RetryRule::allows(&case));
}

#[rstest]
#[case::get(HttpMethod::Get)]
#[case::head(HttpMethod::Head)]
fn a_graphql_query_over_get_follows_the_ordinary_rules(#[case] method: HttpMethod) {
    let case = RetryCase {
        graphql: true,
        method,
        ..case()
    };

    assert!(RetryRule::allows(&case));
}

#[rstest]
#[case::first(0, true)]
#[case::second(1, false)]
#[case::beyond(2, false)]
fn a_request_is_retried_at_most_once(#[case] retries_made: u32, #[case] retried: bool) {
    let case = RetryCase {
        delivery: Delivery::NotSent,
        retries_made,
        ..case()
    };

    assert_eq!(RetryRule::allows(&case), retried);
}
