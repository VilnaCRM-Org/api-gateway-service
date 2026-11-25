//! The settings that bound the access log: the sample rate of allows, the per-class budgets and the
//! capacity of the channel to the writer (FR-50, FR-55).

use super::kinds::AccessClass;

/// The channel capacity of FR-50 when `LOG_CHANNEL_CAPACITY` is not set.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 65_536;

/// The largest channel capacity: a bounded channel stays bounded.
const MAX_CHANNEL_CAPACITY: usize = 16_777_216;

/// What the fraction of a sample rate is counted in: billionths, so nothing is lost for a rate
/// written with up to nine decimals and no floating-point number is needed.
const SCALE: u64 = 1_000_000_000;

/// The digits of the fraction of a sample rate.
const FRACTION_DIGITS: usize = 9;

/// The default budget of the `error` class, per second and pod.
const DEFAULT_ERROR_BUDGET: u32 = 1_000;

/// The default budget of the `audit` class, per second and pod.
const DEFAULT_AUDIT_BUDGET: u32 = 2_000;

/// A setting of the access log that is out of range or cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAccessLogSetting {
    /// `LOG_ALLOW_SAMPLE_RATE` is not a decimal number from 0 to 1.
    #[error("must be a decimal number from 0 to 1 with at most 9 decimals")]
    SampleRate,
    /// `LOG_CLASS_BUDGETS` is not a list of `error=<n>` and `audit=<n>` with n of at least 1.
    #[error("must be a comma-separated list of error=<n> and audit=<n>, each n at least 1")]
    ClassBudgets,
    /// `LOG_CHANNEL_CAPACITY` is not an integer from 1 to 16777216.
    #[error("must be an integer from 1 to 16777216")]
    ChannelCapacity,
}

/// The share of allowed requests that is written to the ordinary lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleRate {
    billionths: u64,
}

impl SampleRate {
    /// Every allow is written.
    pub const ALL: Self = Self { billionths: SCALE };

    /// No allow is written.
    pub const NONE: Self = Self { billionths: 0 };

    /// Parses a decimal number from 0 to 1, such as `0`, `0.01`, `.5` or `1`.
    ///
    /// # Errors
    ///
    /// [`InvalidAccessLogSetting::SampleRate`] for any other text, a number above 1 or one with
    /// more than nine decimals.
    pub fn parse(text: &str) -> Result<Self, InvalidAccessLogSetting> {
        let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
        let fraction_value = Self::fraction(fraction)?;
        let billionths = match whole {
            "0" | "" if !(whole.is_empty() && fraction.is_empty()) => fraction_value,
            "1" if fraction_value == 0 => SCALE,
            _ => return Err(InvalidAccessLogSetting::SampleRate),
        };
        Ok(Self { billionths })
    }

    /// The fraction digits as billionths.
    fn fraction(digits: &str) -> Result<u64, InvalidAccessLogSetting> {
        let invalid = InvalidAccessLogSetting::SampleRate;
        if digits.len() > FRACTION_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid);
        }
        format!("{digits:0<FRACTION_DIGITS$}")
            .parse::<u64>()
            .map_err(|_error| invalid)
    }

    /// Whether a draw of the `Rng` port admits the request: `true` for the share of draws that the
    /// rate names.
    #[must_use]
    pub fn admits(self, draw: u64) -> bool {
        draw.checked_rem(SCALE)
            .is_some_and(|share| share < self.billionths)
    }
}

/// The records per second and per pod that the `error` and `audit` classes may write; beyond them
/// the writer emits one aggregate per second and route, status and reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassBudgets {
    error: u32,
    audit: u32,
}

impl Default for ClassBudgets {
    fn default() -> Self {
        Self {
            error: DEFAULT_ERROR_BUDGET,
            audit: DEFAULT_AUDIT_BUDGET,
        }
    }
}

impl ClassBudgets {
    /// Budgets of `error` and `audit` records per second.
    #[must_use]
    pub const fn new(error: u32, audit: u32) -> Self {
        Self { error, audit }
    }

    /// Parses `error=<n>,audit=<n>`; a class that the text does not name keeps its default.
    ///
    /// # Errors
    ///
    /// [`InvalidAccessLogSetting::ClassBudgets`] for an unknown class, a class named twice, a
    /// number that is not an integer of at least 1 or an empty entry.
    pub fn parse(text: &str) -> Result<Self, InvalidAccessLogSetting> {
        let mut error = None;
        let mut audit = None;
        for entry in text.split(',') {
            let (name, value) = entry
                .split_once('=')
                .ok_or(InvalidAccessLogSetting::ClassBudgets)?;
            let slot = match name.trim() {
                "error" => &mut error,
                "audit" => &mut audit,
                _ => return Err(InvalidAccessLogSetting::ClassBudgets),
            };
            Self::set_once(slot, value)?;
        }
        let defaults = Self::default();
        Ok(Self {
            error: error.unwrap_or(defaults.error),
            audit: audit.unwrap_or(defaults.audit),
        })
    }

    /// Reads `value` into `slot`, which a class may fill only once.
    fn set_once(slot: &mut Option<u32>, value: &str) -> Result<(), InvalidAccessLogSetting> {
        let budget = Self::budget(value)?;
        if slot.replace(budget).is_some() {
            return Err(InvalidAccessLogSetting::ClassBudgets);
        }
        Ok(())
    }

    fn budget(value: &str) -> Result<u32, InvalidAccessLogSetting> {
        value
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|budget| *budget >= 1)
            .ok_or(InvalidAccessLogSetting::ClassBudgets)
    }

    /// The budget of `class` per second; `None` for the `allow` class, which the sample rate
    /// bounds.
    #[must_use]
    pub const fn of(self, class: AccessClass) -> Option<u32> {
        match class {
            AccessClass::Allow => None,
            AccessClass::Error => Some(self.error),
            AccessClass::Audit => Some(self.audit),
        }
    }
}

/// Parses `LOG_CHANNEL_CAPACITY`.
///
/// # Errors
///
/// [`InvalidAccessLogSetting::ChannelCapacity`] for text that is not an integer from 1 to
/// 16777216.
pub fn parse_channel_capacity(text: &str) -> Result<usize, InvalidAccessLogSetting> {
    text.trim()
        .parse::<usize>()
        .ok()
        .filter(|capacity| (1..=MAX_CHANNEL_CAPACITY).contains(capacity))
        .ok_or(InvalidAccessLogSetting::ChannelCapacity)
}

#[cfg(test)]
mod tests;
