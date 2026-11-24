//! The highest version that the state topic holds: the version a resync starts above (FR-78).

use std::sync::Arc;

use iam_domain::{
    PolicyLogTail, PolicyLogTailError, PolicyState, PolicyVersion, StateKey, StateRecordCodec,
    TailRecord,
};

use crate::error::IamError;

/// The records read to find the newest head of the topic: one window of this many offsets.
const WINDOW: i64 = 500;

/// How many windows are read backwards before the topic is declared without a head.
const WINDOWS: u32 = 20;

/// The text of the key of the head.
const HEAD_KEY: &str = "__head";

/// Reads the highest `__head` version of the state topic through the bounded reads of the tail.
#[derive(Debug, Clone)]
pub struct PolicyTopicHead {
    tail: Arc<dyn PolicyLogTail>,
    codec: Arc<dyn StateRecordCodec>,
}

impl PolicyTopicHead {
    /// The reader over `tail`, which decodes the heads with `codec`.
    #[must_use]
    pub fn new(tail: Arc<dyn PolicyLogTail>, codec: Arc<dyn StateRecordCodec>) -> Self {
        Self { tail, codec }
    }

    /// The highest version among the newest heads of the topic, read backwards in windows; `None`
    /// when the topic holds no head that can be read. The connection of the reader is released
    /// afterwards.
    ///
    /// # Errors
    ///
    /// [`IamError::Storage`] when the cluster cannot be read.
    pub async fn highest_version(&self) -> Result<Option<PolicyVersion>, IamError> {
        let found = self.scan().await;
        self.tail.close().await;
        found.map_err(|error| IamError::Storage(Box::new(error)))
    }

    async fn scan(&self) -> Result<Option<PolicyVersion>, PolicyLogTailError> {
        let mut up_to = self.tail.watermark().await?;
        for _ in 0..WINDOWS {
            if up_to <= 0 {
                break;
            }
            let from = up_to.saturating_sub(WINDOW).max(0);
            let records = self.tail.read_range(from, up_to).await?;
            if let Some(version) = self.highest_in(&records) {
                return Ok(Some(version));
            }
            up_to = from;
        }
        Ok(None)
    }

    /// The highest head among `records`; a head that cannot be decoded does not count.
    fn highest_in(&self, records: &[TailRecord]) -> Option<PolicyVersion> {
        records
            .iter()
            .filter(|record| record.key == HEAD_KEY)
            .filter_map(|record| record.payload.as_deref())
            .filter_map(|payload| self.codec.decode(&StateKey::Head, payload).ok())
            .filter_map(|state| match state {
                PolicyState::Head(head) => Some(head.version),
                PolicyState::Role(_)
                | PolicyState::Subject(_)
                | PolicyState::Manifest(_)
                | PolicyState::Chunk(_)
                | PolicyState::Route(_)
                | PolicyState::Upstream(_)
                | PolicyState::RatePolicy(_) => None,
            })
            .max()
    }
}

#[cfg(test)]
mod tests;
