//! Phase-0 spike benches of Story 1.6: the RS256 verify cost with one and with three trusted keys
//! tried newest first, and the `async-graphql-parser` cost on generated documents of 1, 5, 8 and
//! 64 KiB.
//!
//! `make bench-spikes` runs them; `make ci` never does. Every RSA key pair is generated through
//! `aws-lc-rs` when the bench starts and every token is signed then, so no private key and no token
//! is committed. Criterion reports its own estimates; after it, a latency pass times every operation
//! call by call and prints the median and the p99 per operation, with the CPU model of the host.
//! The figures are measurements of that host, never gate values.

mod graphql_parse;
mod latency;
mod token_verify;

use std::env;
use std::io::{self, Write as _};

use criterion::Criterion;

/// Why a spike bench could not run.
#[derive(Debug, thiserror::Error)]
enum SpikeError {
    /// `aws-lc-rs` could not generate or export an RSA key pair.
    #[error("RSA key generation or export failed: {0}")]
    Crypto(#[from] aws_lc_rs::error::Unspecified),
    /// `jsonwebtoken` rejected a generated key or could not sign a token.
    #[error("JWT key loading or signing failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    /// None of the trusted keys verified a token that one of them signed.
    #[error("no trusted key verified the token of case {0}")]
    NoKeyVerified(&'static str),
    /// A generated corpus document did not parse.
    #[error("a corpus document did not parse: {0}")]
    Parse(#[from] async_graphql_parser::Error),
    /// A latency pass recorded fewer samples than its percentiles need.
    #[error("the latency pass of {0} recorded too few samples")]
    TooFewSamples(&'static str),
    /// The report could not be written to standard output.
    #[error("writing the report failed: {0}")]
    Report(#[from] io::Error),
}

fn main() -> Result<(), SpikeError> {
    let tokens = token_verify::Fixture::generate()?;
    let corpus = graphql_parse::Corpus::generate();
    tokens.check()?;
    corpus.check()?;

    run_criterion(&tokens, &corpus);

    // `cargo bench` passes `--bench`; `cargo test --benches` and `--list` do not, and only check.
    if env::args().any(|argument| argument == "--bench") {
        let mut out = io::stdout().lock();
        writeln!(out, "host CPU model: {}", latency::cpu_model())?;
        writeln!(
            out,
            "figures measured on this host only; they are not gate values"
        )?;
        tokens.report(&mut out)?;
        corpus.report(&mut out)?;
    }
    Ok(())
}

/// Criterion's benchmarks of every case, configured from the command line.
fn run_criterion(tokens: &token_verify::Fixture, corpus: &graphql_parse::Corpus) {
    let mut criterion = Criterion::default().configure_from_args();
    tokens.bench(&mut criterion);
    corpus.bench(&mut criterion);
    criterion.final_summary();
}
