//! A double of the reading of one peer pod: the answers it gives, set by the test.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{PeerFreshnessReader, PeerObservation, UpstreamEndpoint};

/// How one peer answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// It reports this.
    Reports(PeerObservation),
    /// It does not answer at all, so the reading times out.
    Hangs,
}

#[derive(Debug, Default)]
struct Script {
    by_address: BTreeMap<String, Answer>,
    fallback: Option<Answer>,
    asked: Vec<String>,
}

/// Peers that answer as the test says: by address, or all alike. A peer with no answer is
/// unreachable and reads as `None`.
#[derive(Debug, Default)]
pub struct FakePeerFreshnessReader {
    script: Mutex<Script>,
}

impl FakePeerFreshnessReader {
    /// A reader whose peers are all unreachable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn script(&self) -> MutexGuard<'_, Script> {
        self.script.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The peer at `address` reports `observation` from now on.
    pub fn report(&self, address: &str, observation: PeerObservation) {
        self.script()
            .by_address
            .insert(address.to_owned(), Answer::Reports(observation));
    }

    /// The peer at `address` never answers from now on.
    pub fn hang(&self, address: &str) {
        self.script()
            .by_address
            .insert(address.to_owned(), Answer::Hangs);
    }

    /// Every peer without an answer of its own reports `observation` from now on.
    pub fn report_all(&self, observation: PeerObservation) {
        self.script().fallback = Some(Answer::Reports(observation));
    }

    /// The addresses asked so far, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        self.script().asked.clone()
    }

    /// Forgets the addresses asked so far.
    pub fn forget_asked(&self) {
        self.script().asked.clear();
    }
}

#[async_trait]
impl PeerFreshnessReader for FakePeerFreshnessReader {
    async fn read(&self, peer: &UpstreamEndpoint) -> Option<PeerObservation> {
        let answer = {
            let mut script = self.script();
            script.asked.push(peer.address().to_owned());
            script
                .by_address
                .get(peer.address())
                .copied()
                .or(script.fallback)
        };
        match answer? {
            Answer::Reports(observation) => Some(observation),
            Answer::Hangs => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests;
