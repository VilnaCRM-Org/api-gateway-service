//! The shadow bootstrap: the state rebuilt from the whole topic and compared with its own head and
//! with PostgreSQL.

use std::sync::atomic::Ordering;

use iam_domain::{PolicyHead, ShadowState, ShadowVerdict, StoredHead};
use shared_domain::BoxError;

use super::head::topic_ahead;
use super::{AntiEntropyAlert, AntiEntropyChecker};

/// The shadow bootstrap over the task that owns the ports.
pub(super) struct FullCheck<'a>(pub(super) &'a AntiEntropyChecker);

impl FullCheck<'_> {
    /// Runs the shadow bootstrap. The state is marked healthy only when the digest it rebuilds
    /// equals the digest of the head of the topic and, at the same version, the digest of
    /// PostgreSQL.
    pub(super) async fn check_full(&self) -> Result<(), BoxError> {
        self.0.healthy.store(false, Ordering::SeqCst);
        let Some(shadow) = self.rebuild().await? else {
            return Ok(());
        };
        let stored = self.0.ports.store.head().await?;
        self.judge(shadow.verdict(), stored).await
    }

    /// The state that the topic rebuilds; `None` when a record cannot be applied, which is an
    /// alert.
    async fn rebuild(&self) -> Result<Option<ShadowState>, BoxError> {
        let watermark = self
            .0
            .ports
            .tail
            .watermark()
            .await
            .map_err(|error| self.0.tail_failure(error))?;
        let mut shadow = ShadowState::new();
        let mut next = 0;
        while next < watermark {
            let records = self.0.read(next, watermark).await?;
            let Some(end) = records.last().map(|record| record.offset) else {
                break;
            };
            next = end.saturating_add(1);
            for record in &records {
                let ports = (&*self.0.ports.codec, &*self.0.ports.digest);
                if let Err(error) = shadow.apply(record, ports) {
                    self.0.raise(&AntiEntropyAlert::UnreadableRecord {
                        offset: record.offset,
                        reason: error.to_string(),
                    });
                    return Ok(None);
                }
            }
        }
        Ok(Some(shadow))
    }

    async fn judge(&self, verdict: ShadowVerdict, stored: StoredHead) -> Result<(), BoxError> {
        match verdict {
            ShadowVerdict::Corrupt { head, computed } => {
                self.0.raise(&AntiEntropyAlert::DigestMismatch {
                    version: head.version.value(),
                    expected: head.digest.to_hex(),
                    found: computed.to_hex(),
                });
                Ok(())
            }
            ShadowVerdict::Consistent(head) => self.compare(head, stored).await,
            ShadowVerdict::Empty if stored.version.value() == 0 => {
                self.0.healthy.store(true, Ordering::SeqCst);
                Ok(())
            }
            ShadowVerdict::Empty | ShadowVerdict::Incomplete => self.lagging(stored).await,
        }
    }

    /// Compares the consistent head of the topic with the head of PostgreSQL.
    async fn compare(&self, head: PolicyHead, stored: StoredHead) -> Result<(), BoxError> {
        if head.version > stored.version {
            // The head check of the same run sets the hold when it raised this alert already.
            if !self.0.hold.is_set() {
                self.0.hold.set(true);
                self.0.raise(&topic_ahead(head, stored));
            }
        } else if head.version < stored.version {
            self.lagging(stored).await?;
        } else if head.digest == stored.digest {
            self.0.healthy.store(true, Ordering::SeqCst);
        } else {
            self.0.raise(&AntiEntropyAlert::DigestMismatch {
                version: head.version.value(),
                expected: stored.digest.to_hex(),
                found: head.digest.to_hex(),
            });
        }
        Ok(())
    }

    /// The topic is behind PostgreSQL: the relay is catching up while rows wait, and a loss when
    /// none is left to publish.
    async fn lagging(&self, stored: StoredHead) -> Result<(), BoxError> {
        if self.0.ports.store.unpublished_count().await? == 0 {
            self.0.raise(&AntiEntropyAlert::TopicBehind {
                store: stored.version.value(),
            });
        }
        Ok(())
    }
}
