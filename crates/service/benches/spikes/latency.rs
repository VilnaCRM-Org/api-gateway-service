//! Per-call latency: the median and the p99 of individually timed calls of one operation.

use std::fs;
use std::hint::black_box;
use std::io::{self, Write};
use std::time::Duration;

use criterion::measurement::{Measurement as _, WallTime};

/// Individually timed calls per operation.
const CALLS: usize = 10_000;
/// Index of the median in the sorted samples of [`CALLS`] calls.
const MEDIAN_INDEX: usize = 5_000;
/// Index of the 99th percentile in the sorted samples of [`CALLS`] calls, by nearest rank:
/// `ceil(0.99 * 10_000) - 1`.
const P99_INDEX: usize = 9_899;

/// The median and the p99 of one operation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Percentiles {
    median: Duration,
    p99: Duration,
}

/// Times [`CALLS`] calls of `operation` one by one, through criterion's wall-time measurement.
///
/// Returns `None` only when fewer samples than [`P99_INDEX`] needs were recorded.
pub(crate) fn measure<O, F: FnMut() -> O>(mut operation: F) -> Option<Percentiles> {
    let mut samples: Vec<Duration> = (0..CALLS)
        .map(|_| {
            let start = WallTime.start();
            drop(black_box(operation()));
            WallTime.end(start)
        })
        .collect();
    samples.sort_unstable();
    Some(Percentiles {
        median: *samples.get(MEDIAN_INDEX)?,
        p99: *samples.get(P99_INDEX)?,
    })
}

/// Writes one result line: `<group>/<case>: median <µs>, p99 <µs> per operation`.
pub(crate) fn write<W: Write>(
    out: &mut W,
    group: &str,
    case: &str,
    percentiles: Percentiles,
) -> io::Result<()> {
    writeln!(
        out,
        "{group}/{case}: median {:.1} us, p99 {:.1} us per operation ({CALLS} calls)",
        micros(percentiles.median),
        micros(percentiles.p99),
    )
}

/// The CPU model of the host, from `/proc/cpuinfo`, or `unknown` where that file is missing.
pub(crate) fn cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|rest| rest.split_once(':'))
                    .map(|(_, model)| model.trim().to_owned())
            })
        })
        .unwrap_or_else(|| String::from("unknown"))
}

const fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}
