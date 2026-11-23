//! Policy log producer double of the IAM context.

use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use iam_domain::{PolicyLogError, PolicyLogProducer, PolicyLogRecord};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the double answers a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Every record is acknowledged with consecutive offsets.
    Acknowledge,
    /// The cluster is unavailable.
    Unavailable,
    /// A newer producer fenced this one.
    Fenced,
    /// The answer names one offset fewer than there are records.
    Short,
}

#[derive(Debug)]
struct Book {
    batches: Vec<Vec<PolicyLogRecord>>,
    next_offset: i64,
}

/// A producer that records the batches it was given and answers as told, one answer per call and
/// then its default.
#[derive(Debug)]
pub struct FakePolicyLogProducer {
    script: Mutex<Vec<Answer>>,
    default: Answer,
    book: Mutex<Book>,
}

impl FakePolicyLogProducer {
    /// A producer that follows `script` and then gives `default` to every call.
    #[must_use]
    pub fn new(script: &[Answer], default: Answer) -> Self {
        let mut script = script.to_vec();
        script.reverse();
        Self {
            script: Mutex::new(script),
            default,
            book: Mutex::new(Book {
                batches: Vec::new(),
                next_offset: 0,
            }),
        }
    }

    /// A producer that acknowledges every record.
    #[must_use]
    pub fn acknowledging() -> Self {
        Self::new(&[], Answer::Acknowledge)
    }

    /// The batches the producer was given, in order, the failed ones included.
    #[must_use]
    pub fn batches(&self) -> Vec<Vec<PolicyLogRecord>> {
        locked(&self.book).batches.clone()
    }

    fn next_answer(&self) -> Answer {
        locked(&self.script).pop().unwrap_or(self.default)
    }

    fn record(&self, records: &[PolicyLogRecord]) {
        locked(&self.book).batches.push(records.to_vec());
    }

    /// The next `count` offsets of the partition.
    fn next_offsets(&self, count: usize) -> Vec<i64> {
        let mut book = locked(&self.book);
        (0..count)
            .map(|_index| {
                let offset = book.next_offset;
                book.next_offset = offset.saturating_add(1);
                offset
            })
            .collect()
    }
}

#[async_trait]
impl PolicyLogProducer for FakePolicyLogProducer {
    async fn publish(&self, records: &[PolicyLogRecord]) -> Result<Vec<i64>, PolicyLogError> {
        let answer = self.next_answer();
        self.record(records);
        match answer {
            Answer::Unavailable => Err(PolicyLogError::Unavailable("in-memory outage".into())),
            Answer::Fenced => Err(PolicyLogError::Fenced("in-memory fencing".into())),
            Answer::Acknowledge => Ok(self.next_offsets(records.len())),
            Answer::Short => Ok(self.next_offsets(records.len().saturating_sub(1))),
        }
    }
}

#[cfg(test)]
mod tests;
