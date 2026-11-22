//! `async-graphql-parser` on a corpus of representative query documents of 1, 5, 8 and 64 KiB,
//! generated when the bench starts.

use std::hint::black_box;
use std::io::Write;

use async_graphql_parser::parse_query;
use criterion::Criterion;

use crate::{SpikeError, latency};

/// The criterion group and the prefix of every result line.
const GROUP: &str = "graphql_parse";
/// The documents of the corpus: name and exact size in bytes.
const SIZES: [(&str, usize); 4] = [
    ("1KiB", 1_024),
    ("5KiB", 5_120),
    ("8KiB", 8_192),
    ("64KiB", 65_536),
];
/// The operation header: one named query with variables and defaults.
const HEADER: &str = "query Corpus($id: ID!, $first: Int = 10, $after: String) {\n";
/// The named fragments the selections spread, in turn.
const FRAGMENT_NAMES: [&str; 4] = ["UserFields", "ServiceFields", "RoleFields", "GroupFields"];
/// The end of the operation and the fragment definitions.
const FOOTER: &str = "}\n\
fragment UserFields on User { id email roles profile { firstName lastName } }\n\
fragment ServiceFields on Service { id name scopes }\n\
fragment RoleFields on Role { id name permissions { resource action } }\n\
fragment GroupFields on Group { id name members(first: 5) { totalCount } }\n";

/// One corpus document.
struct Document {
    name: &'static str,
    source: String,
}

/// The documents of [`SIZES`].
pub(crate) struct Corpus {
    documents: Vec<Document>,
}

impl Corpus {
    /// Generates one document per entry of [`SIZES`].
    pub(crate) fn generate() -> Self {
        Self {
            documents: SIZES
                .iter()
                .map(|&(name, bytes)| Document {
                    name,
                    source: document(bytes),
                })
                .collect(),
        }
    }

    /// Fails unless every document parses, so that no figure measures a syntax error.
    pub(crate) fn check(&self) -> Result<(), SpikeError> {
        self.documents.iter().try_for_each(|document| {
            parse_query(&document.source)
                .map(drop)
                .map_err(SpikeError::from)
        })
    }

    /// Registers one criterion benchmark per document.
    pub(crate) fn bench(&self, criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group(GROUP);
        for document in &self.documents {
            group.bench_function(document.name, |bencher| {
                bencher.iter(|| parse_query(black_box(&document.source)));
            });
        }
        group.finish();
    }

    /// Writes the median and the p99 per parse of every document.
    pub(crate) fn report<W: Write>(&self, out: &mut W) -> Result<(), SpikeError> {
        for document in &self.documents {
            let percentiles = latency::measure(|| parse_query(black_box(&document.source)))
                .ok_or(SpikeError::TooFewSamples(document.name))?;
            latency::write(out, GROUP, document.name, percentiles)?;
        }
        Ok(())
    }
}

/// A query document of exactly `bytes` bytes: aliased selections with object arguments, nested
/// connections, inline fragments and fragment spreads, as many as fit, then whitespace up to the
/// size, then the fragment definitions.
fn document(bytes: usize) -> String {
    let budget = bytes.saturating_sub(FOOTER.len());
    let mut source = String::with_capacity(bytes);
    source.push_str(HEADER);
    for (index, fragment) in (0..bytes).zip(FRAGMENT_NAMES.iter().cycle()) {
        let block = selection(index, fragment);
        if source.len().saturating_add(block.len()) > budget {
            break;
        }
        source.push_str(&block);
    }
    source.push_str(&" ".repeat(budget.saturating_sub(source.len())));
    source.push_str(FOOTER);
    source
}

/// One aliased top-level selection that spreads `fragment`.
fn selection(index: usize, fragment: &str) -> String {
    format!(
        "  a{index}: account(id: $id) {{ id name createdAt \
members(first: $first, after: $after, filter: {{ role: ADMIN, active: true }}) {{ totalCount \
edges {{ cursor node {{ ...{fragment} ... on Service {{ owner {{ id }} }} }} }} \
pageInfo {{ hasNextPage endCursor }} }} }}\n"
    )
}
