//! Doubles of the anti-entropy task of the IAM context: the PostgreSQL reads, the state topic, and a
//! codec and a digest that read the plain-text heads the tests write.

use std::hash::{DefaultHasher, Hash as _, Hasher as _};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use async_trait::async_trait;
use iam_domain::{
    AntiEntropyStore, ChunkId, InvalidStateRecord, PolicyDigest, PolicyDigestValue, PolicyHead,
    PolicyLogTail, PolicyLogTailError, PolicyState, PolicyVersion, PublishedRecord, RelayEpoch,
    RepositoryError, StateKey, StateRecordCodec, StoredHead, TAIL_READ_LIMIT, TailRecord,
    WrittenKey,
};
use shared_domain::{BoxError, Uuid};

/// # Panics
///
/// Panics when `number` is negative.
#[expect(
    clippy::expect_used,
    reason = "a negative version in a test double is a defect of the test"
)]
fn version_of(number: i64) -> PolicyVersion {
    PolicyVersion::new(number).expect("a version of a test is not negative")
}

/// # Panics
///
/// Panics when `number` is negative.
#[expect(
    clippy::expect_used,
    reason = "a negative epoch in a test double is a defect of the test"
)]
fn epoch_of(number: i64) -> RelayEpoch {
    RelayEpoch::new(number).expect("an epoch of a test is not negative")
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug)]
struct StoreBook {
    head: StoredHead,
    published: Vec<PublishedRecord>,
    written: Vec<WrittenKey>,
    newest: Vec<WrittenKey>,
    unpublished: u64,
    existing: Vec<Uuid>,
    republished: Vec<Uuid>,
    unavailable: bool,
}

/// PostgreSQL as the anti-entropy task reads it, answering from memory and recording the repairs.
#[derive(Debug)]
pub struct FakeAntiEntropyStore {
    book: Mutex<StoreBook>,
}

impl FakeAntiEntropyStore {
    /// A store at policy version `version` with digest `digest`, holding no rows.
    ///
    /// # Panics
    ///
    /// Panics when `version` is negative.
    #[must_use]
    pub fn at(version: i64, digest: PolicyDigestValue) -> Self {
        Self {
            book: Mutex::new(StoreBook {
                head: StoredHead {
                    version: version_of(version),
                    digest,
                },
                published: Vec::new(),
                written: Vec::new(),
                newest: Vec::new(),
                unpublished: 0,
                existing: Vec::new(),
                republished: Vec::new(),
                unavailable: false,
            }),
        }
    }

    /// The same store whose recently published rows are `rows`; each can be republished.
    #[must_use]
    pub fn with_published(self, rows: Vec<PublishedRecord>) -> Self {
        {
            let mut book = locked(&self.book);
            book.existing.extend(rows.iter().map(|row| row.id));
            book.published = rows;
        }
        self
    }

    /// The same store whose keys written since the last check are `keys`; each can be republished
    /// when `existing` is true.
    #[must_use]
    pub fn with_written(self, keys: Vec<WrittenKey>, existing: bool) -> Self {
        {
            let mut book = locked(&self.book);
            if existing {
                book.existing.extend(keys.iter().map(|key| key.id));
            }
            book.written = keys;
        }
        self
    }

    /// The same store whose newest rows of keys, whenever they were written, are `rows`; each can
    /// be republished.
    #[must_use]
    pub fn with_newest(self, rows: Vec<WrittenKey>) -> Self {
        {
            let mut book = locked(&self.book);
            book.existing.extend(rows.iter().map(|row| row.id));
            book.newest = rows;
        }
        self
    }

    /// The same store with `count` unpublished rows.
    #[must_use]
    pub fn with_unpublished(self, count: u64) -> Self {
        locked(&self.book).unpublished = count;
        self
    }

    /// The same store whose every read fails.
    #[must_use]
    pub fn unavailable(self) -> Self {
        locked(&self.book).unavailable = true;
        self
    }

    /// The rows that were republished, in order.
    #[must_use]
    pub fn republished(&self) -> Vec<Uuid> {
        locked(&self.book).republished.clone()
    }

    fn check(&self) -> Result<MutexGuard<'_, StoreBook>, RepositoryError> {
        let book = locked(&self.book);
        if book.unavailable {
            let cause: BoxError = "the store is down".into();
            return Err(RepositoryError::Unavailable(cause));
        }
        Ok(book)
    }
}

#[async_trait]
impl AntiEntropyStore for FakeAntiEntropyStore {
    async fn head(&self) -> Result<StoredHead, RepositoryError> {
        Ok(self.check()?.head)
    }

    async fn recently_published(
        &self,
        _since: SystemTime,
        limit: u32,
    ) -> Result<Vec<PublishedRecord>, RepositoryError> {
        let book = self.check()?;
        let take = usize::try_from(limit).unwrap_or(usize::MAX);
        Ok(book.published.iter().take(take).cloned().collect())
    }

    async fn keys_written_since(
        &self,
        _since: SystemTime,
    ) -> Result<Vec<WrittenKey>, RepositoryError> {
        Ok(self.check()?.written.clone())
    }

    async fn newest_rows(&self, keys: &[String]) -> Result<Vec<WrittenKey>, RepositoryError> {
        let book = self.check()?;
        Ok(book
            .newest
            .iter()
            .filter(|row| keys.contains(&row.key))
            .cloned()
            .collect())
    }

    async fn unpublished_count(&self) -> Result<u64, RepositoryError> {
        Ok(self.check()?.unpublished)
    }

    async fn republish(&self, id: Uuid) -> Result<bool, RepositoryError> {
        let exists = {
            let mut book = self.check()?;
            let exists = book.existing.contains(&id);
            if exists {
                book.republished.push(id);
            }
            exists
        };
        Ok(exists)
    }
}

#[derive(Debug)]
struct TailBook {
    records: Vec<TailRecord>,
    watermark: Option<i64>,
    unavailable: bool,
    unreadable_offsets: bool,
    watermark_calls: usize,
    watermark_fails_from: Option<usize>,
    malformed_at: Option<i64>,
}

/// The state topic as a list of records, read with the bounds of the port.
#[derive(Debug)]
pub struct FakePolicyLogTail {
    book: Mutex<TailBook>,
    closes: AtomicUsize,
}

impl FakePolicyLogTail {
    /// A topic with `records`, whose offsets the records carry.
    #[must_use]
    pub const fn with(records: Vec<TailRecord>) -> Self {
        Self {
            book: Mutex::new(TailBook {
                records,
                watermark: None,
                unavailable: false,
                unreadable_offsets: false,
                watermark_calls: 0,
                watermark_fails_from: None,
                malformed_at: None,
            }),
            closes: AtomicUsize::new(0),
        }
    }

    /// How often the reader was closed.
    #[must_use]
    pub fn closes(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }

    /// The same topic whose reads fail.
    #[must_use]
    pub fn unavailable(self) -> Self {
        locked(&self.book).unavailable = true;
        self
    }

    /// The same topic whose watermark is `watermark`, past its last record, as when the newest
    /// offsets hold transaction markers or compacted records.
    #[must_use]
    pub fn with_watermark(self, watermark: i64) -> Self {
        locked(&self.book).watermark = Some(watermark);
        self
    }

    /// The same topic whose reads of a single offset fail while every other read succeeds.
    #[must_use]
    pub fn unreadable_offsets(self) -> Self {
        locked(&self.book).unreadable_offsets = true;
        self
    }

    /// The same topic whose watermark answers `answered` times and then fails.
    #[must_use]
    pub fn watermark_fails_after(self, answered: usize) -> Self {
        locked(&self.book).watermark_fails_from = Some(answered);
        self
    }

    /// The same topic whose record at `offset` is malformed.
    #[must_use]
    pub fn malformed_at(self, offset: i64) -> Self {
        locked(&self.book).malformed_at = Some(offset);
        self
    }

    /// Appends `record` to the topic.
    pub fn append(&self, record: TailRecord) {
        locked(&self.book).records.push(record);
    }

    fn check(&self) -> Result<MutexGuard<'_, TailBook>, PolicyLogTailError> {
        let book = locked(&self.book);
        if book.unavailable {
            let cause: BoxError = "the broker is down".into();
            return Err(PolicyLogTailError::Unavailable(cause));
        }
        Ok(book)
    }
}

fn end_of(book: &TailBook) -> i64 {
    book.watermark.unwrap_or_else(|| {
        book.records
            .iter()
            .map(|record| record.offset.saturating_add(1))
            .max()
            .unwrap_or(0)
    })
}

#[async_trait]
impl PolicyLogTail for FakePolicyLogTail {
    async fn watermark(&self) -> Result<i64, PolicyLogTailError> {
        let mut book = self.check()?;
        let call = book.watermark_calls;
        book.watermark_calls = call.saturating_add(1);
        let fails = book.watermark_fails_from.is_some_and(|from| call >= from);
        let end = end_of(&book);
        drop(book);
        if fails {
            return Err(PolicyLogTailError::Unavailable(
                "the watermark failed".into(),
            ));
        }
        Ok(end)
    }

    async fn read_range(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<TailRecord>, PolicyLogTailError> {
        let (mut found, malformed) = {
            let book = self.check()?;
            let end = up_to.min(end_of(&book));
            let found: Vec<TailRecord> = book
                .records
                .iter()
                .filter(|record| record.offset >= from && record.offset < end)
                .cloned()
                .collect();
            (found, book.malformed_at)
        };
        found.sort_by_key(|record| record.offset);
        found.truncate(TAIL_READ_LIMIT);
        if let Some(offset) = malformed
            && found.iter().any(|record| record.offset == offset)
        {
            return Err(PolicyLogTailError::Malformed { offset });
        }
        Ok(found)
    }

    async fn read_at(&self, offset: i64) -> Result<Option<TailRecord>, PolicyLogTailError> {
        let (unreadable, found) = {
            let book = self.check()?;
            let found = book
                .records
                .iter()
                .find(|record| record.offset == offset)
                .cloned();
            (book.unreadable_offsets, found)
        };
        if unreadable {
            return Err(PolicyLogTailError::Unavailable(
                "the offset read failed".into(),
            ));
        }
        Ok(found)
    }

    async fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}

/// A topic record of `key` at `offset`, with the framing of the test: version and relay epoch.
///
/// # Panics
///
/// Panics when `version` or `epoch` is negative.
#[must_use]
pub fn tail_record(
    offset: i64,
    key: &str,
    payload: Option<&str>,
    version: i64,
    epoch: i64,
) -> TailRecord {
    TailRecord {
        offset,
        key: key.to_owned(),
        payload: payload.map(str::to_owned),
        version: version_of(version),
        relay_epoch: epoch_of(epoch),
    }
}

/// The record of the head of `version` with `digest`, in the plain-text form of [`TextHeadCodec`].
///
/// # Panics
///
/// Panics when `version` or `epoch` is negative.
#[must_use]
pub fn head_record(offset: i64, version: i64, digest: PolicyDigestValue, epoch: i64) -> TailRecord {
    let payload = format!("head {version} {}", digest.to_hex());
    tail_record(offset, "__head", Some(&payload), version, epoch)
}

/// Reads `head <version> <digest hex>` and nothing else.
#[derive(Debug, Default)]
pub struct TextHeadCodec;

impl StateRecordCodec for TextHeadCodec {
    fn encode(&self, _state: &PolicyState) -> Result<String, InvalidStateRecord> {
        Err(InvalidStateRecord::Encoding)
    }

    fn decode(&self, _key: &StateKey, payload: &str) -> Result<PolicyState, InvalidStateRecord> {
        let mut parts = payload.split(' ');
        let (Some("head"), Some(version), Some(digest)) =
            (parts.next(), parts.next(), parts.next())
        else {
            return Err(InvalidStateRecord::Encoding);
        };
        let version = version
            .parse()
            .ok()
            .and_then(|number| PolicyVersion::new(number).ok())
            .ok_or(InvalidStateRecord::Encoding)?;
        let digest =
            PolicyDigestValue::from_hex(digest).map_err(|_error| InvalidStateRecord::Encoding)?;
        Ok(PolicyState::Head(PolicyHead { version, digest }))
    }

    fn entry_size(&self, _entry: &iam_domain::CatalogueEntryState) -> usize {
        0
    }
}

/// Hashes with the standard hasher, which is deterministic for a fixed key.
#[derive(Debug, Default)]
pub struct HashDigest;

impl HashDigest {
    fn bytes(text: &str) -> [u8; 16] {
        let mut low = DefaultHasher::new();
        text.hash(&mut low);
        let mut high = DefaultHasher::new();
        (text, 1_u8).hash(&mut high);
        let mut bytes = [0; 16];
        let (first, second) = bytes.split_at_mut(8);
        first.copy_from_slice(&low.finish().to_be_bytes());
        second.copy_from_slice(&high.finish().to_be_bytes());
        bytes
    }

    /// The hash of the entity `key` whose canonical state is `canonical`.
    #[must_use]
    pub fn of(key: &str, canonical: &str) -> PolicyDigestValue {
        PolicyDigestValue::from_bytes(Self::bytes(&format!("{key}|{canonical}")))
    }
}

impl PolicyDigest for HashDigest {
    fn entity_hash(&self, key: &StateKey, canonical: &str) -> PolicyDigestValue {
        Self::of(&key.to_string(), canonical)
    }

    fn content_id(&self, canonical: &str) -> ChunkId {
        ChunkId::from_digest(PolicyDigestValue::from_bytes(Self::bytes(canonical)))
    }
}
