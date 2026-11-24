//! Port that proves the freshness of a pod against the state topic (FR-73).

use crate::freshness::probe_error::ProbeError;
use crate::freshness::proof::FreshnessProof;

/// Asks the state topic for the last stable offset, with the checks that make the answer a proof.
#[async_trait::async_trait]
pub trait PolicyLogProbe: std::fmt::Debug + Send + Sync {
    /// One probe. The instant of the proof is read from the boot clock before anything is sent, so
    /// a slow answer never makes the proof look younger than it is.
    ///
    /// # Errors
    ///
    /// A [`ProbeError`] when any check fails: no proof is produced then.
    async fn probe(&self) -> Result<FreshnessProof, ProbeError>;
}
