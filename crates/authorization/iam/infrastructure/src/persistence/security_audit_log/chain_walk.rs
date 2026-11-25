//! The walk over the stored chain that decides whether it verifies.
//!
//! The walk is pure: the adapter reads the rows and computes their digests in SQL, and the walk
//! compares them link by link, so the rules are tested without a database.

use iam_domain::{
    AuditChainHead, AuditHash, ChainBreak, ChainBreakCause, ChainVerification, SecurityAuditEventId,
};

/// One stored record, as the walk sees it.
pub(super) struct Link<'a> {
    /// The stored sequence number.
    pub seq: i64,
    /// The stored identifier.
    pub id: SecurityAuditEventId,
    /// The stored hash of the previous record.
    pub prev_hash: &'a [u8],
    /// The stored hash of the record.
    pub hash: &'a [u8],
    /// `SHA-256(prev_hash || canonical form)` of the stored values; none when they cannot be read
    /// back as a valid record.
    pub digest: Option<&'a [u8]>,
}

/// The state of a walk from the first record.
pub(super) struct ChainWalk<'a> {
    anchors: &'a [AuditChainHead],
    checked: i64,
    last_seq: i64,
    last_hash: Vec<u8>,
}

impl<'a> ChainWalk<'a> {
    /// A walk that starts before the first record and checks `anchors` on the way.
    pub(super) fn new(anchors: &'a [AuditChainHead]) -> Self {
        Self {
            anchors,
            checked: 0,
            last_seq: 0,
            last_hash: AuditHash::GENESIS.as_bytes().to_vec(),
        }
    }

    /// The sequence number of the last record that verified, 0 before the first.
    pub(super) const fn last_seq(&self) -> i64 {
        self.last_seq
    }

    /// Checks the next record; returns where the chain breaks when it does.
    pub(super) fn step(&mut self, link: &Link<'_>) -> Option<ChainBreak> {
        self.checked = self.checked.saturating_add(1);
        if let Some(cause) = self.cause_of(link) {
            return Some(ChainBreak::new(link.seq, Some(link.id), cause));
        }
        self.last_seq = link.seq;
        self.last_hash = link.hash.to_vec();
        None
    }

    /// The verdict of a walk that reached the end of the chain: valid unless an anchor names a
    /// record beyond it.
    pub(super) fn finish(self) -> ChainVerification {
        let missing = self
            .anchors
            .iter()
            .map(AuditChainHead::seq)
            .filter(|seq| *seq > self.last_seq)
            .min();
        match missing {
            Some(seq) => ChainVerification::invalid(
                self.checked,
                ChainBreak::new(seq, None, ChainBreakCause::AnchorMissing),
            ),
            None => ChainVerification::valid(self.checked),
        }
    }

    /// The verdict of a walk that stopped at `broken`.
    pub(super) fn broken(self, broken: ChainBreak) -> ChainVerification {
        ChainVerification::invalid(self.checked, broken)
    }

    /// Why the record does not extend the chain, in the order gap, unreadable, link, digest,
    /// anchor; none when it does.
    fn cause_of(&self, link: &Link<'_>) -> Option<ChainBreakCause> {
        if link.seq != self.last_seq.saturating_add(1) {
            Some(ChainBreakCause::Gap)
        } else if link.digest.is_none() {
            Some(ChainBreakCause::Unreadable)
        } else if link.prev_hash != self.last_hash.as_slice() {
            Some(ChainBreakCause::Link)
        } else if link.digest != Some(link.hash) {
            Some(ChainBreakCause::Digest)
        } else {
            self.disagrees_with_anchor(link)
                .then_some(ChainBreakCause::Anchor)
        }
    }

    /// Whether an anchor of the record's sequence number carries another hash.
    fn disagrees_with_anchor(&self, link: &Link<'_>) -> bool {
        self.anchors
            .iter()
            .any(|anchor| anchor.seq() == link.seq && anchor.hash().as_bytes() != link.hash)
    }
}

#[cfg(test)]
mod tests;
