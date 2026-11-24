//! The pure judgements of the freshness probe: what the replica brokers must agree on, what the
//! probe must never see go backwards, and how a client error reads as a probe error (FR-73).

use iam_domain::ProbeError;
use krafka::KrafkaError;
use krafka::error::ErrorCode;

/// What one broker reports about the state partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Leadership {
    /// The broker that leads the partition.
    pub(super) leader: i32,
    /// The leader epoch.
    pub(super) epoch: i32,
}

/// The smallest number of replica brokers that must answer: a majority of the replica set.
#[must_use]
pub(super) const fn quorum_needed(replicas: usize) -> usize {
    (replicas / 2).saturating_add(1)
}

/// The leadership every view agrees on.
///
/// # Errors
///
/// [`ProbeError::LeaderDisagreement`] when two views differ in the leader or the epoch.
pub(super) fn agreed(own: Leadership, asked: &[Leadership]) -> Result<Leadership, ProbeError> {
    if asked.iter().all(|view| *view == own) {
        Ok(own)
    } else {
        Err(ProbeError::LeaderDisagreement)
    }
}

/// The highest leader epoch and the highest watermark the probe has seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Seen {
    epoch: Option<i32>,
    watermark: Option<i64>,
}

impl Seen {
    /// Admits `epoch`, which must be at least the highest seen.
    ///
    /// # Errors
    ///
    /// [`ProbeError::EpochRegressed`] for a lower epoch.
    pub(super) const fn admit_epoch(&mut self, epoch: i32) -> Result<(), ProbeError> {
        match self.epoch {
            Some(seen) if epoch < seen => Err(ProbeError::EpochRegressed {
                seen,
                reported: epoch,
            }),
            _ => {
                self.epoch = Some(epoch);
                Ok(())
            }
        }
    }

    /// Admits `watermark`, which must be at least the highest seen.
    ///
    /// # Errors
    ///
    /// [`ProbeError::WatermarkRegressed`] for a lower watermark.
    pub(super) const fn admit_watermark(&mut self, watermark: i64) -> Result<(), ProbeError> {
        match self.watermark {
            Some(seen) if watermark < seen => Err(ProbeError::WatermarkRegressed {
                seen,
                reported: watermark,
            }),
            _ => {
                self.watermark = Some(watermark);
                Ok(())
            }
        }
    }
}

/// How a client error reads as a probe error: the three codes that mean the answer cannot be
/// trusted have their own variants, everything else is an unavailable cluster.
#[must_use]
pub(super) fn failure(error: &KrafkaError) -> ProbeError {
    let named = if let KrafkaError::Broker { code, .. } = error {
        [
            (
                ErrorCode::OffsetNotAvailable,
                ProbeError::OffsetNotAvailable,
            ),
            (ErrorCode::FencedLeaderEpoch, ProbeError::FencedLeaderEpoch),
            (
                ErrorCode::UnknownLeaderEpoch,
                ProbeError::UnknownLeaderEpoch,
            ),
        ]
        .into_iter()
        .find(|(named, _error)| named == code)
        .map(|(_named, probe_error)| probe_error)
    } else {
        None
    };
    named.unwrap_or_else(|| ProbeError::Unavailable(error.to_string()))
}

#[cfg(test)]
mod tests;
