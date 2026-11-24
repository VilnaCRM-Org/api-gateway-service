//! The head check: the newest head of the topic against PostgreSQL, the offsets of the recent rows,
//! and the last record of every key that was written since the previous check.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use iam_domain::{
    PolicyHead, PolicyState, PolicyVersion, PublishedRecord, StateKey, StoredHead, TailRecord,
    WrittenKey,
};
use shared_domain::{BoxError, Uuid};

use super::{AntiEntropyAlert, AntiEntropyChecker, RECENT_WINDOW};

/// The records read to find the newest head of the topic: one window of this many offsets.
const HEAD_WINDOW: i64 = 500;

/// How many windows are read backwards before the newest head is declared absent.
const HEAD_WINDOWS: u32 = 20;

/// The most recently published rows whose offsets are verified in one check.
const RECENT_LIMIT: u32 = 20;

/// The most offsets that the scan of the written keys reads in one check.
const MAX_SCAN: i64 = 100_000;

/// The text of the key of the head.
const HEAD_KEY: &str = "__head";

/// The head check over the task that owns the ports.
pub(super) struct HeadCheck<'a>(pub(super) &'a AntiEntropyChecker);

impl HeadCheck<'_> {
    /// Runs the head check; `since` is the time from which the written rows are read.
    pub(super) async fn check_head(
        &self,
        now: SystemTime,
        since: SystemTime,
    ) -> Result<(), BoxError> {
        if self.topic_is_ahead().await? {
            return Ok(());
        }
        let mut repaired = HashSet::new();
        self.verify_recent(now, &mut repaired).await?;
        self.verify_written(since, &mut repaired).await
    }

    /// Whether the topic holds a version above PostgreSQL; the topic is read first, so a version
    /// that the relay published meanwhile is never taken for one that is ahead.
    async fn topic_is_ahead(&self) -> Result<bool, BoxError> {
        let watermark = self
            .0
            .ports
            .tail
            .watermark()
            .await
            .map_err(|error| self.0.tail_failure(error))?;
        let topic = self.newest_head(watermark).await?;
        let stored = self.0.ports.store.head().await?;
        let ahead = topic.filter(|head| head.version > stored.version);
        self.0.hold.set(ahead.is_some());
        if let Some(head) = ahead {
            self.0.raise(&topic_ahead(head, stored));
        }
        Ok(ahead.is_some())
    }

    /// The head of the highest version among the newest heads of the topic, read backwards in
    /// windows.
    async fn newest_head(&self, watermark: i64) -> Result<Option<PolicyHead>, BoxError> {
        let mut up_to = watermark;
        for _ in 0..HEAD_WINDOWS {
            if up_to <= 0 {
                break;
            }
            let from = up_to.saturating_sub(HEAD_WINDOW).max(0);
            let records = self.0.read(from, up_to).await?;
            if let Some(head) = self.highest_head(&records) {
                return Ok(Some(head));
            }
            up_to = from;
        }
        Ok(None)
    }

    fn highest_head(&self, records: &[TailRecord]) -> Option<PolicyHead> {
        records
            .iter()
            .filter(|record| record.key == HEAD_KEY)
            .filter_map(|record| self.head_of(record))
            .max_by_key(|head| head.version)
    }

    /// The head that `record` carries; a head that cannot be read is an alert.
    fn head_of(&self, record: &TailRecord) -> Option<PolicyHead> {
        let decoded = record
            .payload
            .as_deref()
            .and_then(|payload| self.0.ports.codec.decode(&StateKey::Head, payload).ok());
        if let Some(PolicyState::Head(head)) = decoded {
            return Some(head);
        }
        self.0.raise(&AntiEntropyAlert::UnreadableRecord {
            offset: record.offset,
            reason: "the head cannot be decoded".to_owned(),
        });
        None
    }

    /// Checks that the recent rows are stored at the offsets that were recorded for them.
    ///
    /// A recent row that is no longer the newest of its key is never repaired: publishing it again
    /// would put a superseded state back at the end of the topic. The newest PostgreSQL row of the
    /// key is checked instead, as [`Self::verify_written`] does, and repaired when it is lost.
    async fn verify_recent(
        &self,
        now: SystemTime,
        repaired: &mut HashSet<Uuid>,
    ) -> Result<(), BoxError> {
        let since = now.checked_sub(RECENT_WINDOW).unwrap_or(now);
        let recent = self
            .0
            .ports
            .store
            .recently_published(since, RECENT_LIMIT)
            .await?;
        let mut lost = Vec::new();
        for record in recent {
            if !self
                .holds_at(record.offset, &record.key, record.version)
                .await?
            {
                lost.push(record);
            }
        }
        if lost.is_empty() {
            return Ok(());
        }
        let keys: Vec<String> = lost.iter().map(|record| record.key.clone()).collect();
        let newest = self.0.ports.store.newest_rows(&keys).await?;
        for record in lost {
            let row = newest.iter().find(|row| row.key == record.key);
            self.repair_newest(&record, row, repaired).await?;
        }
        Ok(())
    }

    /// Whether the topic holds the record `key` at `version` at `offset`.
    async fn holds_at(
        &self,
        offset: i64,
        key: &str,
        version: PolicyVersion,
    ) -> Result<bool, BoxError> {
        let stored = self
            .0
            .ports
            .tail
            .read_at(offset)
            .await
            .map_err(|error| self.0.tail_failure(error))?;
        Ok(stored.is_some_and(|found| found.key == key && found.version == version))
    }

    /// Repairs the lost `record` through the newest row of its key: the record itself when it is
    /// the newest; a newer row only when that one is lost too (a row that is not published yet is
    /// the relay's to send); the record when the store knows no newer row of the key.
    async fn repair_newest(
        &self,
        record: &PublishedRecord,
        newest: Option<&WrittenKey>,
        repaired: &mut HashSet<Uuid>,
    ) -> Result<(), BoxError> {
        let Some(newest) = newest.filter(|row| row.id != record.id) else {
            return self.repair(record.id, &record.key, repaired).await;
        };
        let Some(offset) = newest.published_offset else {
            return Ok(());
        };
        if self.holds_at(offset, &newest.key, newest.version).await? {
            return Ok(());
        }
        self.repair(newest.id, &newest.key, repaired).await
    }

    /// Compares the last record by offset of every key written since `since` with the newest
    /// PostgreSQL version of the key.
    async fn verify_written(
        &self,
        since: SystemTime,
        repaired: &mut HashSet<Uuid>,
    ) -> Result<(), BoxError> {
        let written = self.0.ports.store.keys_written_since(since).await?;
        let published: Vec<_> = written
            .iter()
            .filter_map(|key| key.published_offset.map(|offset| (key, offset)))
            .collect();
        let Some(lowest) = published.iter().map(|(_, offset)| *offset).min() else {
            return Ok(());
        };
        let watermark = self
            .0
            .ports
            .tail
            .watermark()
            .await
            .map_err(|error| self.0.tail_failure(error))?;
        let from = lowest.max(watermark.saturating_sub(MAX_SCAN));
        let last = self.last_versions(from, watermark).await?;
        for (key, offset) in published {
            let lower = last.get(&key.key).is_none_or(|seen| *seen < key.version);
            if offset >= from && lower {
                self.repair(key.id, &key.key, repaired).await?;
            }
        }
        Ok(())
    }

    /// The version of the last record by offset of every key in `from..watermark`.
    async fn last_versions(
        &self,
        from: i64,
        watermark: i64,
    ) -> Result<HashMap<String, PolicyVersion>, BoxError> {
        let mut last = HashMap::new();
        let mut next = from;
        while next < watermark {
            let records = self.0.read(next, watermark).await?;
            let Some(end) = records.last().map(|record| record.offset) else {
                break;
            };
            next = end.saturating_add(1);
            for record in records {
                last.insert(record.key, record.version);
            }
        }
        Ok(last)
    }

    /// Clears the publication marks of the row `id`, so the relay sends it again; a row that the
    /// outbox no longer holds is a loss that only the resync repairs.
    async fn repair(
        &self,
        id: Uuid,
        key: &str,
        repaired: &mut HashSet<Uuid>,
    ) -> Result<(), BoxError> {
        if repaired.insert(id) {
            let republished = self.0.ports.store.republish(id).await?;
            self.account_for(republished, key);
        }
        Ok(())
    }

    /// Counts a repair, or raises the alert for a loss that cannot be repaired.
    fn account_for(&self, republished: bool, key: &str) {
        if republished {
            self.0.counters.record();
            log_republished(key);
        } else {
            self.0.raise(&AntiEntropyAlert::LossBeyondRetention {
                key: key.to_owned(),
            });
        }
    }
}

fn log_republished(key: &str) {
    tracing::warn!(
        key,
        metric = "anti_entropy_repairs_total",
        "a lost or stale record is published again"
    );
}

/// The alert for a topic whose newest head is above the PostgreSQL head.
pub(super) const fn topic_ahead(topic: PolicyHead, store: StoredHead) -> AntiEntropyAlert {
    AntiEntropyAlert::TopicAhead {
        topic: topic.version.value(),
        store: store.version.value(),
    }
}
