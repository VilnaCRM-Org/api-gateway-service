//! The scan of the stream registry: which streams must end now, and why (Story 11.1).

use std::time::SystemTime;

use super::registry::Watched;
use super::{CloseReason, Revalidated, StreamFence, Streams};

/// What a stream owes at the moment of the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Due {
    Close(CloseReason),
    Redecide,
}

/// One pass over the registry: closes the streams of a pod that may not serve, and settles every
/// stream whose token expired, that went idle or whose assignment expiry passed.
pub(super) async fn run(streams: &Streams, fence: &dyn StreamFence) {
    if fence.closed() {
        streams.registry.close_all(CloseReason::Fenced);
        return;
    }
    let now = streams.now();
    for watched in streams.registry.watched() {
        settle(streams, &watched, now).await;
    }
}

async fn settle(streams: &Streams, watched: &Watched, now: SystemTime) {
    match due(streams, watched, now) {
        Some(Due::Close(reason)) => streams.registry.close(watched.id, reason),
        Some(Due::Redecide) => redecide(streams, watched).await,
        None => {}
    }
}

fn due(streams: &Streams, watched: &Watched, now: SystemTime) -> Option<Due> {
    if watched.token_expires_at.is_some_and(|at| at <= now) {
        Some(Due::Close(CloseReason::TokenExpired))
    } else if watched.activity.idle_for() >= streams.idle_timeout {
        Some(Due::Close(CloseReason::Idle))
    } else if watched.assignment_expires_at.is_some_and(|at| at <= now) {
        Some(Due::Redecide)
    } else {
        None
    }
}

/// Decides the stream again at the expiry of its assignments: it stays open, with the next expiry
/// to look at, when the current snapshot still allows it, and ends otherwise.
async fn redecide(streams: &Streams, watched: &Watched) {
    let verdict = match streams.decider.get() {
        Some(decider) => decider.decide(&watched.grant).await,
        None => Revalidated::Denied,
    };
    match verdict {
        Revalidated::Allowed { next_expiry } => streams.registry.renew(watched.id, next_expiry),
        Revalidated::Denied => streams.registry.close(watched.id, CloseReason::Revoked),
    }
}

#[cfg(test)]
mod tests;
