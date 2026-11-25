//! What a query of the access decisions asks for and what it returns (FR-51, FR-54, NFR-44).
//!
//! The decisions live in the log store, which honours bounds and not arbitrary scans: a query
//! names a time range of at most the configured length, filters on the structured fields that the
//! audit lane keeps, and pages newest first through a cursor made of the timestamp of the last
//! entry and the number of entries already returned at that timestamp.

use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use crate::access_log::{AccessDecision, AccessRecord};
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::subject::SubjectKind;

/// The most entries of one page.
pub const MAX_PAGE_SIZE: u32 = 500;

/// The most entries at one timestamp that a cursor may say earlier pages returned.
///
/// Entries share a nanosecond timestamp only in a handful, so a larger count is not a cursor this
/// service issued and is refused instead of being sent to the log store as a larger read.
pub const MAX_CURSOR_RETURNED: u32 = MAX_PAGE_SIZE;

/// The most entries one read of the log store may ask for.
///
/// It is a page, the entry that tells whether another page follows, and the entries that a cursor
/// skips.
pub const MAX_LOG_READ: u32 = MAX_PAGE_SIZE + 1 + MAX_CURSOR_RETURNED;

/// How far from the timestamp of a UUID v7 a read by id looks, in nanoseconds: two seconds.
pub const ID_WINDOW_NANOS: u64 = 2_000_000_000;

/// The nanoseconds of one millisecond, the precision of a UUID v7 timestamp.
const NANOS_PER_MILLI: u64 = 1_000_000;

/// The version number of a UUID v7.
const UUID_V7: usize = 7;

/// The time range of a query: from `from_nanos` on, until `until_nanos` not included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessLogRange {
    from_nanos: u64,
    until_nanos: u64,
}

/// The time range of a query cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAccessLogRange {
    /// A bound lies before 1970 or past the largest number of nanoseconds in 64 bits.
    #[error("The time range must lie between 1970 and the year 2554.")]
    OutOfBounds,
    /// The range ends at or before its start.
    #[error("The range must end after it starts.")]
    Inverted,
    /// The range is longer than the longest the log store may be asked to scan.
    #[error("The range is longer than the longest range that may be queried.")]
    TooLong,
}

impl InvalidAccessLogRange {
    /// The property of the request that carries the offending value.
    #[must_use]
    pub const fn property_path(self) -> &'static str {
        match self {
            Self::OutOfBounds => "from",
            Self::Inverted | Self::TooLong => "until",
        }
    }

    /// The machine-readable code of the violation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OutOfBounds => "range_bounds",
            Self::Inverted => "range_inverted",
            Self::TooLong => "range_too_long",
        }
    }
}

impl AccessLogRange {
    /// The range from `from` until `until`, which may span at most `max`.
    ///
    /// # Errors
    ///
    /// [`InvalidAccessLogRange::OutOfBounds`], [`InvalidAccessLogRange::Inverted`] or
    /// [`InvalidAccessLogRange::TooLong`].
    pub fn new(
        from: SystemTime,
        until: SystemTime,
        max: Duration,
    ) -> Result<Self, InvalidAccessLogRange> {
        let from_nanos = nanos(from).ok_or(InvalidAccessLogRange::OutOfBounds)?;
        let until_nanos = nanos(until).ok_or(InvalidAccessLogRange::OutOfBounds)?;
        if until_nanos <= from_nanos {
            return Err(InvalidAccessLogRange::Inverted);
        }
        let span = Duration::from_nanos(until_nanos.saturating_sub(from_nanos));
        if span > max {
            return Err(InvalidAccessLogRange::TooLong);
        }
        Ok(Self {
            from_nanos,
            until_nanos,
        })
    }

    /// The window around the timestamp of the UUID v7 `id`: two seconds before it and two seconds
    /// after the millisecond it names. `None` when `id` is not a UUID v7, which no decision has.
    #[must_use]
    pub fn around(id: Uuid) -> Option<Self> {
        let uuid = id.as_uuid();
        if uuid.get_version_num() != UUID_V7 {
            return None;
        }
        let millis = u64::try_from(uuid.as_u128() >> 80).ok()?;
        let at = millis.checked_mul(NANOS_PER_MILLI)?;
        Some(Self {
            from_nanos: at.saturating_sub(ID_WINDOW_NANOS),
            until_nanos: at
                .saturating_add(NANOS_PER_MILLI)
                .saturating_add(ID_WINDOW_NANOS),
        })
    }

    /// The first nanosecond kept, since 1970.
    #[must_use]
    pub const fn start_nanos(self) -> u64 {
        self.from_nanos
    }

    /// The first nanosecond not kept, since 1970.
    #[must_use]
    pub const fn until_nanos(self) -> u64 {
        self.until_nanos
    }

    /// The range that ends after `last_nanos`, the timestamp of the last entry of a page: the
    /// entries at that timestamp are still to be read, so it ends one nanosecond later.
    #[must_use]
    pub const fn ending_at(self, last_nanos: u64) -> Self {
        let until = last_nanos.saturating_add(1);
        Self {
            from_nanos: self.from_nanos,
            until_nanos: if until < self.until_nanos {
                until
            } else {
                self.until_nanos
            },
        }
    }
}

/// Nanoseconds since 1970, or nothing before it or past the largest 64-bit count.
fn nanos(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
}

/// The conditions on the structured fields of a decision; an entry must meet every one given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessLogFilter {
    /// The id of the subject: a user id or a service name.
    pub subject_id: Option<String>,
    /// The kind of the subject.
    pub subject_kind: Option<SubjectKind>,
    /// The kind of the decision.
    pub decision: Option<AccessDecision>,
    /// The reason code of the decision.
    pub reason: Option<DecisionReason>,
    /// The registered name of the upstream.
    pub upstream: Option<String>,
    /// The matched route.
    pub route_id: Option<Uuid>,
    /// The status of the answer.
    pub status: Option<u16>,
}

/// Where the next page of a query starts: the entries at `timestamp_nanos` that earlier pages
/// already returned are skipped, and older entries follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessLogCursor {
    /// The timestamp of the last entry of the previous page.
    pub timestamp_nanos: u64,
    /// How many entries at that timestamp earlier pages returned.
    pub returned: u32,
}

impl AccessLogCursor {
    /// The opaque text of the cursor.
    #[must_use]
    pub fn encode(self) -> String {
        format!("{:x}.{:x}", self.timestamp_nanos, self.returned)
    }

    /// The cursor that `text` names; `None` for any other text, one whose count of returned
    /// entries exceeds [`MAX_CURSOR_RETURNED`] included.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (timestamp, returned) = text.split_once('.')?;
        let digits =
            |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !digits(timestamp) || !digits(returned) {
            return None;
        }
        let returned = u32::from_str_radix(returned, 16)
            .ok()
            .filter(|returned| *returned <= MAX_CURSOR_RETURNED)?;
        Some(Self {
            timestamp_nanos: u64::from_str_radix(timestamp, 16).ok()?,
            returned,
        })
    }

    /// The cursor after a page whose last entry is at `last_nanos` and that holds `in_page`
    /// entries at that timestamp, when the page started at `previous`.
    #[must_use]
    pub fn after(last_nanos: u64, in_page: u32, previous: Option<Self>) -> Self {
        let earlier = previous
            .filter(|cursor| cursor.timestamp_nanos == last_nanos)
            .map_or(0, |cursor| cursor.returned);
        Self {
            timestamp_nanos: last_nanos,
            returned: earlier.saturating_add(in_page),
        }
    }

    /// The token of the cursor under `seal`.
    #[must_use]
    pub fn sealed(self, seal: &dyn CursorSeal) -> String {
        seal.seal(&self.encode())
    }

    /// The cursor that `token` carries; `None` when `seal` did not issue it or its payload is not
    /// a cursor.
    #[must_use]
    pub fn opened(token: &str, seal: &dyn CursorSeal) -> Option<Self> {
        Self::parse(&seal.open(token)?)
    }
}

/// The integrity protection of the cursors this service issues.
///
/// A cursor is a position in the log store that the client hands back; sealing it makes every
/// cursor one that this service issued, so that a forged position is refused (Story 14.3, NFR-44).
pub trait CursorSeal: std::fmt::Debug + Send + Sync {
    /// The opaque token that carries `payload` and proves where it came from.
    fn seal(&self, payload: &str) -> String;

    /// The payload that `token` carries; `None` for a token this seal did not issue, one that
    /// was altered included.
    fn open(&self, token: &str) -> Option<String>;
}

/// One page of a query: the entries newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogSearch {
    /// The time range.
    pub range: AccessLogRange,
    /// The conditions the entries must meet.
    pub filter: AccessLogFilter,
    /// Where the page starts; none for the first page.
    pub cursor: Option<AccessLogCursor>,
    /// The most entries to return.
    pub limit: u32,
}

/// One access decision as the log store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogEntry {
    /// The timestamp of the entry in the log store, in nanoseconds since 1970.
    pub timestamp_nanos: u64,
    /// The decision.
    pub record: AccessRecord,
}

/// A query of the log store failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccessLogQueryError {
    /// The log store did not answer within the time a query may take; no partial page is made.
    #[error("the access log store did not answer in time")]
    Timeout,
    /// The log store refused the connection, answered with an error or sent an unusable answer.
    #[error("the access log store is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests;
