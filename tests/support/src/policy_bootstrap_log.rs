//! A double of the state topic as the bootstrap of a gateway pod reads it: a list of framed records
//! and a script of the last stable offsets.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{
    FramedRecord, LogEpoch, PolicyBootstrapLog, PolicyDigestValue, PolicyLogTailError,
    PolicyVersion, RelayEpoch, StateKey, TAIL_READ_LIMIT, VersionedRecord,
};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// # Panics
///
/// Panics when `text` is not a state key.
#[expect(
    clippy::expect_used,
    reason = "a malformed key in a test double is a defect of the test"
)]
fn key_of(text: &str) -> StateKey {
    StateKey::parse(text).expect("a key of a test is a state key")
}

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

/// The framed record of an entity row of `version`: row `seq` of `count`, with the digest after
/// it, at `offset`, from the relay of epoch 1 and the log epoch 0.
#[must_use]
pub fn framed_row(
    offset: i64,
    key: &str,
    payload: Option<&str>,
    version: i64,
    framing: (u32, u32, PolicyDigestValue),
) -> FramedRecord {
    let (seq, count, digest_after) = framing;
    FramedRecord {
        offset,
        record: VersionedRecord {
            key: key_of(key),
            payload: payload.map(str::to_owned),
            version: version_of(version),
            seq,
            count,
            digest_after,
            log_epoch: LogEpoch::ZERO,
            relay_epoch: epoch(1),
        },
    }
}

/// The framed record of the head of `version`: the last row, number `count`, in the plain-text
/// form of the `TextHeadCodec` of the anti-entropy double.
#[must_use]
pub fn framed_head(
    offset: i64,
    version: i64,
    count: u32,
    digest: PolicyDigestValue,
) -> FramedRecord {
    let payload = format!("head {version} {}", digest.to_hex());
    framed_row(
        offset,
        "__head",
        Some(&payload),
        version,
        (count, count, digest),
    )
}

/// The same record under another relay epoch.
///
/// # Panics
///
/// Panics when `number` is negative.
#[must_use]
pub fn by_relay(mut framed: FramedRecord, number: i64) -> FramedRecord {
    framed.record.relay_epoch = epoch(number);
    framed
}

#[expect(
    clippy::expect_used,
    reason = "a negative epoch in a test double is a defect of the test"
)]
fn epoch(number: i64) -> RelayEpoch {
    RelayEpoch::new(number).expect("an epoch of a test is not negative")
}

#[derive(Debug)]
struct Script {
    records: Vec<FramedRecord>,
    ends: VecDeque<i64>,
    last_end: i64,
    failing: bool,
}

/// The state topic of a bootstrap.
#[derive(Debug)]
pub struct FakePolicyBootstrapLog {
    script: Mutex<Script>,
    captures: AtomicUsize,
    reads: AtomicUsize,
    closes: AtomicUsize,
}

impl FakePolicyBootstrapLog {
    /// A topic of `records` whose stable end is one past the last offset.
    #[must_use]
    pub fn with(records: Vec<FramedRecord>) -> Self {
        let end = records
            .iter()
            .map(|framed| framed.offset.saturating_add(1))
            .max()
            .unwrap_or(0);
        Self::scripted(records, &[end])
    }

    /// A topic of `records` whose successive captures of the stable end answer `ends`; the last
    /// answer repeats.
    #[must_use]
    pub fn scripted(records: Vec<FramedRecord>, ends: &[i64]) -> Self {
        Self {
            script: Mutex::new(Script {
                records,
                ends: ends.iter().copied().collect(),
                last_end: ends.first().copied().unwrap_or(0),
                failing: false,
            }),
            captures: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        }
    }

    /// The same topic whose reads and captures fail.
    #[must_use]
    pub fn unavailable(self) -> Self {
        locked(&self.script).failing = true;
        self
    }

    /// How often the stable end was captured.
    #[must_use]
    pub fn captures(&self) -> usize {
        self.captures.load(Ordering::SeqCst)
    }

    /// How often records were read.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// How often the connection was closed.
    #[must_use]
    pub fn closes(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
}

fn unavailable() -> PolicyLogTailError {
    PolicyLogTailError::Unavailable(Box::new(std::io::Error::other(
        "the fake topic is unavailable",
    )))
}

#[async_trait]
impl PolicyBootstrapLog for FakePolicyBootstrapLog {
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        let mut script = locked(&self.script);
        if script.failing {
            return Err(unavailable());
        }
        if let Some(end) = script.ends.pop_front() {
            script.last_end = end;
        }
        Ok(script.last_end)
    }

    async fn read_framed(
        &self,
        from: i64,
        up_to: i64,
    ) -> Result<Vec<FramedRecord>, PolicyLogTailError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let script = locked(&self.script);
        if script.failing {
            return Err(unavailable());
        }
        let end = up_to.min(script.last_end);
        Ok(script
            .records
            .iter()
            .filter(|framed| framed.offset >= from && framed.offset < end)
            .take(TAIL_READ_LIMIT)
            .cloned()
            .collect())
    }

    async fn close(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}
