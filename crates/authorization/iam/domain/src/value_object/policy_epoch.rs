//! The policy epoch: what the single row of the system of record says about the policy.

use crate::error::InvalidIamValue;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;

/// The policy version with the digest of its state and the log, relay and catalogue epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEpoch {
    version: PolicyVersion,
    digest: PolicyDigestValue,
    log_epoch: LogEpoch,
    relay_epoch: RelayEpoch,
    catalog_epoch: i64,
}

impl PolicyEpoch {
    /// Builds the epoch from valid parts and validates the catalogue epoch.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::CatalogEpochNegative`] when the catalogue epoch is negative.
    pub const fn new(
        version: PolicyVersion,
        digest: PolicyDigestValue,
        log_epoch: LogEpoch,
        relay_epoch: RelayEpoch,
        catalog_epoch: i64,
    ) -> Result<Self, InvalidIamValue> {
        if catalog_epoch < 0 {
            return Err(InvalidIamValue::CatalogEpochNegative);
        }
        Ok(Self {
            version,
            digest,
            log_epoch,
            relay_epoch,
            catalog_epoch,
        })
    }

    /// The policy version.
    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// The digest of the policy state at this version.
    #[must_use]
    pub const fn digest(&self) -> PolicyDigestValue {
        self.digest
    }

    /// The epoch of the policy log.
    #[must_use]
    pub const fn log_epoch(&self) -> LogEpoch {
        self.log_epoch
    }

    /// The epoch of the outbox relay.
    #[must_use]
    pub const fn relay_epoch(&self) -> RelayEpoch {
        self.relay_epoch
    }

    /// The epoch of the permission catalogue, 0 or greater.
    #[must_use]
    pub const fn catalog_epoch(&self) -> i64 {
        self.catalog_epoch
    }
}

#[cfg(test)]
mod tests;
