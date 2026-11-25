//! `RetryRule`: whether a failed request may be sent again (FR-66).

use crate::route::settings::RetryPolicy;
use crate::value_object::http_method::HttpMethod;

/// The largest request body, in bytes, that is buffered so that it can be sent again: 64 KiB. A
/// body of this size or above is streamed and never retried after it was sent.
pub const MAX_BUFFERED_BODY_BYTES: u64 = 64 * 1024;

/// The body of a request, as far as a retry is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBody {
    /// The request has no body.
    Empty,
    /// The body is buffered in memory, with this many bytes, so it can be sent again.
    Buffered(u64),
    /// The body is streamed from the caller and is consumed by the first attempt.
    Streamed,
}

/// What is known about whether the failed attempt reached the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The request provably was not sent: the connection was refused or closed before a write,
    /// the stream was refused (HTTP/2 `REFUSED_STREAM`) or the stream is above the last stream id
    /// of a GOAWAY.
    NotSent,
    /// The request may have been written, so the endpoint may have acted on it.
    MaybeSent,
}

/// The facts of one failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryCase {
    /// The retry policy of the route.
    pub policy: RetryPolicy,
    /// The method of the request.
    pub method: HttpMethod,
    /// Whether the route serves GraphQL.
    pub graphql: bool,
    /// The body of the request.
    pub body: RequestBody,
    /// Whether the attempt reached the endpoint.
    pub delivery: Delivery,
    /// The retries already made for this request.
    pub retries_made: u32,
}

/// The rule that decides whether a failed request is sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryRule;

impl RetryRule {
    /// The most retries a request gets.
    pub const MAX_RETRIES: u32 = 1;

    /// Whether the failed attempt of `case` is retried, on another endpoint.
    ///
    /// A request is retried at most once. A GraphQL request that is no `GET` or `HEAD` may carry
    /// a mutation and is never retried. A request that provably was not sent is retried whatever
    /// the policy. A request that may have been sent is retried only for an idempotent method on
    /// a route with the policy `idempotent`, and only when it has no body or a body buffered
    /// under [`MAX_BUFFERED_BODY_BYTES`].
    #[must_use]
    pub const fn allows(case: &RetryCase) -> bool {
        if case.retries_made >= Self::MAX_RETRIES || Self::may_carry_mutation(case) {
            return false;
        }
        match case.delivery {
            Delivery::NotSent => true,
            Delivery::MaybeSent => Self::resendable(case),
        }
    }

    const fn may_carry_mutation(case: &RetryCase) -> bool {
        case.graphql && !matches!(case.method, HttpMethod::Get | HttpMethod::Head)
    }

    const fn resendable(case: &RetryCase) -> bool {
        let body_fits = match case.body {
            RequestBody::Empty => true,
            RequestBody::Buffered(bytes) => bytes < MAX_BUFFERED_BODY_BYTES,
            RequestBody::Streamed => false,
        };
        matches!(case.policy, RetryPolicy::Idempotent) && Self::idempotent(case.method) && body_fits
    }

    const fn idempotent(method: HttpMethod) -> bool {
        matches!(
            method,
            HttpMethod::Get
                | HttpMethod::Head
                | HttpMethod::Put
                | HttpMethod::Delete
                | HttpMethod::Options
        )
    }
}

#[cfg(test)]
mod tests;
