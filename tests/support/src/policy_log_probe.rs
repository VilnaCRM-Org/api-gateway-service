//! A double of the freshness probe: a script of answers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{PolicyLogProbe, ProbeError};

/// A probe that answers with the scripted results in order, and with `Unavailable` once the script
/// is spent.
#[derive(Debug, Default)]
pub struct FakePolicyLogProbe {
    script: Mutex<VecDeque<Result<FreshnessProof, ProbeError>>>,
    probes: AtomicUsize,
}

impl FakePolicyLogProbe {
    /// A probe that answers with `results` in order.
    #[must_use]
    pub fn scripted(results: Vec<Result<FreshnessProof, ProbeError>>) -> Self {
        Self {
            script: Mutex::new(results.into()),
            probes: AtomicUsize::new(0),
        }
    }

    /// How many times the probe ran.
    #[must_use]
    pub fn probes(&self) -> usize {
        self.probes.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PolicyLogProbe for FakePolicyLogProbe {
    async fn probe(&self) -> Result<FreshnessProof, ProbeError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Err(ProbeError::Unavailable("the script is spent".to_owned())))
    }
}

#[cfg(test)]
mod tests;
