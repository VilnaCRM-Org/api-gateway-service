use iam_domain::{
    FramedRecord, PolicyBootstrapLog, PolicyDigestValue, PolicyLogTailError, TAIL_READ_LIMIT,
};
use test_support::policy_bootstrap_log::framed_row;

use super::{BootstrapFailure, BootstrapInput, Settled, failure_version, read, settle};

/// A topic whose reads either return one record more than a read may, or fail.
#[derive(Debug)]
struct MisbehavingLog {
    oversized: bool,
}

#[async_trait::async_trait]
impl PolicyBootstrapLog for MisbehavingLog {
    async fn stable_end(&self) -> Result<i64, PolicyLogTailError> {
        Ok(0)
    }

    async fn read_framed(
        &self,
        from: i64,
        _up_to: i64,
    ) -> Result<Vec<FramedRecord>, PolicyLogTailError> {
        if !self.oversized {
            return Err(PolicyLogTailError::Unavailable(Box::new(
                std::io::Error::other("the topic is gone"),
            )));
        }
        Ok((from..)
            .take(TAIL_READ_LIMIT + 1)
            .map(|offset| framed_row(offset, "__head", None, 1, (1, 1, PolicyDigestValue::ZERO)))
            .collect())
    }

    async fn close(&self) {}
}

fn reason(input: BootstrapInput) -> String {
    let BootstrapInput::ReadFailed(reason) = input else {
        panic!("not a failed read: {input:?}");
    };
    reason
}

#[tokio::test]
async fn a_read_with_more_records_than_a_read_may_return_is_a_failed_read() {
    let log = MisbehavingLog { oversized: true };

    let input = read(&log, 0, 10).await;

    assert_eq!(reason(input), "a read returned too many records");
}

#[tokio::test]
async fn a_read_that_fails_is_a_failed_read_with_its_error() {
    let log = MisbehavingLog { oversized: false };

    let input = read(&log, 0, 10).await;

    assert_eq!(reason(input), "the state topic cannot be read");
}

#[tokio::test]
async fn a_step_that_asks_for_nothing_is_a_failed_read_instead_of_a_loop() {
    let log = MisbehavingLog { oversized: true };

    let settled = settle(Vec::new(), &log).await;

    let Settled::Next(input) = settled else {
        panic!("an empty step must not end the bootstrap");
    };
    assert_eq!(reason(input), "the bootstrap made no progress");
}

#[test]
fn a_failure_names_its_version_only_when_it_has_one() {
    let digest = BootstrapFailure::DigestMismatch {
        version: 7,
        expected: "a".to_owned(),
        computed: "b".to_owned(),
    };

    assert_eq!(
        failure_version(&BootstrapFailure::VersionAboveHead { version: 4 }),
        Some(4)
    );
    assert_eq!(failure_version(&digest), Some(7));
    assert_eq!(
        failure_version(&BootstrapFailure::UnreadableHead("x".to_owned())),
        None
    );
    assert_eq!(
        failure_version(&BootstrapFailure::ReadFailed("x".to_owned())),
        None
    );
}
