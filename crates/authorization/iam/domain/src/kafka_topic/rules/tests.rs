use rstest::rstest;

use super::{CONTROL_PRINCIPAL, ConfigurationRules};
use crate::kafka_topic::{
    AllowEveryoneEvidence, CheckSource, ConfigGates, TopicObservation, Violation,
};

fn compliant() -> TopicObservation {
    TopicObservation {
        cleanup_policy: Some("compact".to_owned()),
        unclean_leader_election: Some("false".to_owned()),
        min_insync_replicas: Some("2".to_owned()),
        message_timestamp_type: Some("LogAppendTime".to_owned()),
        partition_count: 1,
        replication_factor: 3,
        writers: vec![CONTROL_PRINCIPAL.to_owned()],
        allow_everyone: Some(AllowEveryoneEvidence::Read("false".to_owned())),
    }
}

fn settings_of(gates: ConfigGates, observation: &TopicObservation) -> Vec<String> {
    ConfigurationRules::new(gates)
        .evaluate(observation)
        .violations()
        .iter()
        .map(|violation| violation.setting.clone())
        .collect()
}

#[test]
fn a_compliant_topic_passes_under_enforce_and_reports_the_broker_as_the_source() {
    let verdict = ConfigurationRules::new(ConfigGates::Enforce).evaluate(&compliant());

    assert!(verdict.passed(), "{}", verdict.describe());
    assert_eq!(verdict.allow_everyone_source(), Some(CheckSource::Broker));
}

#[rstest]
#[case::cleanup_policy_delete(
    TopicObservation { cleanup_policy: Some("delete".to_owned()), ..compliant() },
    "cleanup.policy"
)]
#[case::cleanup_policy_missing(
    TopicObservation { cleanup_policy: None, ..compliant() },
    "cleanup.policy"
)]
#[case::unclean_election_on(
    TopicObservation { unclean_leader_election: Some("true".to_owned()), ..compliant() },
    "unclean.leader.election.enable"
)]
#[case::min_insync_one(
    TopicObservation { min_insync_replicas: Some("1".to_owned()), ..compliant() },
    "min.insync.replicas"
)]
#[case::min_insync_not_a_number(
    TopicObservation { min_insync_replicas: Some("two".to_owned()), ..compliant() },
    "min.insync.replicas"
)]
#[case::min_insync_missing(
    TopicObservation { min_insync_replicas: None, ..compliant() },
    "min.insync.replicas"
)]
#[case::create_time(
    TopicObservation { message_timestamp_type: Some("CreateTime".to_owned()), ..compliant() },
    "message.timestamp.type"
)]
#[case::two_partitions(
    TopicObservation { partition_count: 2, ..compliant() },
    "partitions"
)]
#[case::no_partition(
    TopicObservation { partition_count: 0, ..compliant() },
    "partitions"
)]
#[case::replication_factor_one(
    TopicObservation { replication_factor: 1, ..compliant() },
    "replication.factor"
)]
#[case::another_writer(
    TopicObservation {
        writers: vec![CONTROL_PRINCIPAL.to_owned(), "User:other".to_owned()],
        ..compliant()
    },
    "acl.write"
)]
#[case::everyone_may_write(
    TopicObservation { writers: vec!["User:*".to_owned()], ..compliant() },
    "acl.write"
)]
#[case::allow_everyone_true(
    TopicObservation {
        allow_everyone: Some(AllowEveryoneEvidence::Read("true".to_owned())),
        ..compliant()
    },
    "allow.everyone.if.no.acl.found"
)]
#[case::allow_everyone_not_checked(
    TopicObservation { allow_everyone: None, ..compliant() },
    "allow.everyone.if.no.acl.found"
)]
fn a_rule_that_is_broken_under_enforce_is_named(
    #[case] observation: TopicObservation,
    #[case] setting: &str,
) {
    assert_eq!(settings_of(ConfigGates::Enforce, &observation), [setting]);
}

#[test]
fn the_fallback_probe_decides_when_the_broker_does_not_return_the_setting() {
    let refused = TopicObservation {
        allow_everyone: Some(AllowEveryoneEvidence::ProbeRefused),
        ..compliant()
    };
    let answered = TopicObservation {
        allow_everyone: Some(AllowEveryoneEvidence::ProbeAnswered),
        ..compliant()
    };

    let passed = ConfigurationRules::new(ConfigGates::Enforce).evaluate(&refused);
    let failed = ConfigurationRules::new(ConfigGates::Enforce).evaluate(&answered);

    assert!(passed.passed());
    assert_eq!(passed.allow_everyone_source(), Some(CheckSource::Fallback));
    assert_eq!(failed.allow_everyone_source(), Some(CheckSource::Fallback));
    assert_eq!(
        failed
            .violations()
            .first()
            .map(|violation| violation.source),
        Some(CheckSource::Fallback)
    );
    assert_eq!(
        failed
            .violations()
            .iter()
            .map(|violation| violation.setting.as_str())
            .collect::<Vec<_>>(),
        ["allow.everyone.if.no.acl.found"]
    );
}

#[test]
fn relaxed_gates_accept_a_single_node_topic_and_skip_the_acl_rules() {
    let single_node = TopicObservation {
        replication_factor: 1,
        min_insync_replicas: Some("1".to_owned()),
        writers: vec!["User:other".to_owned()],
        allow_everyone: None,
        ..compliant()
    };

    let verdict = ConfigurationRules::new(ConfigGates::Relaxed).evaluate(&single_node);

    assert!(verdict.passed(), "{}", verdict.describe());
    assert_eq!(verdict.gates(), ConfigGates::Relaxed);
    assert_eq!(verdict.allow_everyone_source(), None);
}

#[rstest]
#[case::no_replica(TopicObservation { replication_factor: 0, ..compliant() }, "replication.factor")]
#[case::min_insync_zero(
    TopicObservation { min_insync_replicas: Some("0".to_owned()), ..compliant() },
    "min.insync.replicas"
)]
#[case::two_partitions(TopicObservation { partition_count: 2, ..compliant() }, "partitions")]
#[case::delete(
    TopicObservation { cleanup_policy: Some("delete".to_owned()), ..compliant() },
    "cleanup.policy"
)]
fn relaxed_gates_still_refuse_the_rules_a_single_node_can_meet(
    #[case] observation: TopicObservation,
    #[case] setting: &str,
) {
    assert_eq!(settings_of(ConfigGates::Relaxed, &observation), [setting]);
}

#[test]
fn every_violation_names_the_value_that_was_found() {
    let observation = TopicObservation {
        cleanup_policy: None,
        partition_count: 2,
        ..compliant()
    };

    let verdict = ConfigurationRules::new(ConfigGates::Enforce).evaluate(&observation);

    assert_eq!(
        verdict.violations(),
        [
            Violation::new("cleanup.policy", "compact", "not reported"),
            Violation::new("partitions", "1", "2"),
        ]
    );
}
