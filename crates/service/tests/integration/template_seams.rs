//! The seam check: the files this service changed away from the template are covered by `.templatesyncignore`,
//! and the workflow jobs start the compose services their tests need before they call the test targets.
//!
//! `scripts/check-invariants.sh` checks neither, so every story that adds a seam file or a workflow step
//! extends [`SEAM_FILES`] or [`KAFKA_JOBS`]. The coverage probe is the documented one,
//! `sed 's/#.*//' .templatesyncignore | xargs -r git ls-files -- | grep -Fx <path>`, reimplemented here: an
//! entry covers the file of that path and every file below the directory of that path, and the file must
//! exist.

use std::fs;
use std::path::{Path, PathBuf};

/// Seam files: changed away from the template, so the template sync must not overwrite them.
const SEAM_FILES: [&str; 6] = [
    ".github/workflows/tests.yml",
    ".github/workflows/scheduled.yml",
    "docker-compose.yml",
    "docker-compose.override.yml",
    "crates/service/Cargo.toml",
    "crates/service/tests/integration/main.rs",
];

/// Jobs that run the integration tests against the compose `kafka` broker (Story 1.2), with the make targets
/// that run those tests. Mutation testing reruns the integration tests for every infrastructure mutant, so
/// every mutation shard needs the broker.
const KAFKA_JOBS: [(&str, &str, &[&str]); 3] = [
    (
        ".github/workflows/tests.yml",
        "tests",
        &["tests-with-coverage"],
    ),
    (
        ".github/workflows/tests.yml",
        "mutation-shard",
        &["mutation-tests-diff", "mutation-tests"],
    ),
    (
        ".github/workflows/scheduled.yml",
        "mutation-shard",
        &["mutation-tests"],
    ),
];

/// The compose service the spike tests read.
const KAFKA_SERVICE: &str = "kafka";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(repository_root().join(path)).unwrap()
}

/// The entries of `.templatesyncignore`: comments removed, one entry per word.
fn ignore_entries(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split('#').next())
        .flat_map(str::split_whitespace)
        .map(str::to_owned)
        .collect()
}

/// Whether an entry names `path` or a directory above it.
fn entry_covers(entry: &str, path: &str) -> bool {
    let entry = entry.trim_end_matches('/');
    path == entry
        || path
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The probe: some entry covers `path`, and `path` is a file of the repository.
fn covered(root: &Path, entries: &[String], path: &str) -> bool {
    root.join(path).is_file() && entries.iter().any(|entry| entry_covers(entry, path))
}

/// One `make` call of a workflow step: its targets and its `NAME=value` variables.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MakeCall {
    targets: Vec<String>,
    variables: Vec<(String, String)>,
}

impl MakeCall {
    /// Parses a command line that starts with `make `; other lines (an `echo` that names a target, for
    /// example) are no call.
    fn parse(line: &str) -> Option<Self> {
        let words = line.strip_prefix("make ")?.split_whitespace();
        let mut call = Self {
            targets: Vec::new(),
            variables: Vec::new(),
        };
        for word in words {
            if let Some((name, value)) = word.split_once('=') {
                call.variables
                    .push((name.to_owned(), value.trim_matches(['"', '\'']).to_owned()));
            } else if word
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                call.targets.push(word.to_owned());
            } else {
                break;
            }
        }
        Some(call)
    }

    /// Whether the call starts the compose service `service` (`make start-deps DEPS=<service>`).
    fn starts(&self, service: &str) -> bool {
        self.targets.iter().any(|target| target == "start-deps")
            && self.variables.iter().any(|(name, value)| {
                name == "DEPS" && value.split_whitespace().any(|dep| dep == service)
            })
    }
}

/// The jobs of a workflow in file order, each with its `make` calls in step order.
fn jobs(workflow: &str) -> Vec<(String, Vec<MakeCall>)> {
    let mut jobs: Vec<(String, Vec<MakeCall>)> = Vec::new();
    let mut inside = false;
    for line in workflow.lines() {
        if !line.starts_with(' ') && !line.trim_start().starts_with('#') && !line.is_empty() {
            inside = line.trim_end() == "jobs:";
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '))
            .and_then(|rest| rest.trim_end().strip_suffix(':'))
        {
            jobs.push((name.to_owned(), Vec::new()));
            continue;
        }
        let command = line.trim_start();
        let command = command.strip_prefix("- ").unwrap_or(command);
        let command = command.strip_prefix("run:").unwrap_or(command).trim_start();
        if let (Some(call), Some((_, calls))) = (MakeCall::parse(command), jobs.last_mut()) {
            calls.push(call);
        }
    }
    jobs
}

/// The problem with `job` of `workflow`, if the job does not start `service` before every call of a target of
/// `targets`, or calls none of them.
fn missing_start(workflow: &str, job: &str, targets: &[&str], service: &str) -> Option<String> {
    let all = jobs(workflow);
    let Some((_, calls)) = all.iter().find(|(name, _)| name == job) else {
        return Some(format!("no job {job}"));
    };
    let calls_target = |call: &MakeCall| {
        call.targets
            .iter()
            .any(|target| targets.contains(&target.as_str()))
    };
    let Some(first_test) = calls.iter().position(calls_target) else {
        return Some(format!("job {job} calls none of {targets:?}: {calls:?}"));
    };
    let started = calls
        .iter()
        .take(first_test)
        .any(|call| call.starts(service));
    (!started).then(|| format!("job {job} does not start {service} before {targets:?}: {calls:?}"))
}

#[test]
fn every_seam_file_is_covered_by_templatesyncignore() {
    let root = repository_root();
    let entries = ignore_entries(&read(".templatesyncignore"));

    let uncovered: Vec<&str> = SEAM_FILES
        .into_iter()
        .filter(|path| !covered(&root, &entries, path))
        .collect();

    assert!(
        uncovered.is_empty(),
        "not in .templatesyncignore: {uncovered:?}"
    );
}

#[test]
fn the_probe_rejects_a_file_no_entry_covers_and_a_missing_file() {
    let root = repository_root();
    let entries = ignore_entries("docs/adr/ # decisions\n# Makefile\nREADME.md\n");

    assert!(covered(&root, &entries, "README.md"));
    assert!(covered(&root, &entries, "docs/adr/README.md"));
    assert!(!covered(&root, &entries, "Makefile"));
    assert!(!covered(&root, &entries, "docs/adr-elsewhere.md"));
    assert!(!covered(&root, &entries, "docs/adr/no-such-file.md"));
}

#[test]
fn every_job_that_runs_the_integration_tests_starts_the_compose_kafka_broker_first() {
    let problems: Vec<String> = KAFKA_JOBS
        .into_iter()
        .filter_map(|(file, job, targets)| {
            missing_start(&read(file), job, targets, KAFKA_SERVICE)
                .map(|problem| format!("{file}: {problem}"))
        })
        .collect();

    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn the_workflow_reader_lists_the_make_calls_of_each_job_and_ignores_messages() {
    let workflow = "\
on:
  push:
jobs:
  late:
    steps:
      - run: make mutation-tests MUTANTS_SHARD=\"$SHARD\"
      - run: make start-deps DEPS=kafka
  early:
    steps:
      - name: Start
        run: make start-deps DEPS=kafka
      - run: |
          make mutation-tests-diff base_ref=\"origin/$BASE_REF\" 2>&1 | tee log
          echo \"make mutation-tests failed\"
  none:
    steps:
      - run: make start-deps DEPS=database
      - run: make mutation-tests
";

    let listed = jobs(workflow);
    let targets: Vec<(String, Vec<Vec<String>>)> = listed
        .iter()
        .map(|(name, calls)| {
            let targets = calls.iter().map(|call| call.targets.clone()).collect();
            (name.clone(), targets)
        })
        .collect();

    assert_eq!(
        targets,
        [
            (
                "late".to_owned(),
                vec![
                    vec!["mutation-tests".to_owned()],
                    vec!["start-deps".to_owned()]
                ]
            ),
            (
                "early".to_owned(),
                vec![
                    vec!["start-deps".to_owned()],
                    vec!["mutation-tests-diff".to_owned()]
                ]
            ),
            (
                "none".to_owned(),
                vec![
                    vec!["start-deps".to_owned()],
                    vec!["mutation-tests".to_owned()]
                ]
            ),
        ]
    );
    let mutation = ["mutation-tests", "mutation-tests-diff"];
    assert!(missing_start(workflow, "late", &mutation, KAFKA_SERVICE).is_some());
    assert_eq!(
        missing_start(workflow, "early", &mutation, KAFKA_SERVICE),
        None
    );
    assert!(missing_start(workflow, "none", &mutation, KAFKA_SERVICE).is_some());
    assert!(missing_start(workflow, "absent", &mutation, KAFKA_SERVICE).is_some());
    assert!(missing_start(workflow, "early", &["e2e-tests"], KAFKA_SERVICE).is_some());
}
