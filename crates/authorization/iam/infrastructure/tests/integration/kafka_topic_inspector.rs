//! `KrafkaTopicInspector` against the compose broker `kafka` (Story 7.3): the verdicts of the
//! configuration gates (FR-72), the ACL checks, the fallback for `allow.everyone.if.no.acl.found`
//! and the secrecy of the SASL password.
//!
//! krafka's `test-broker` answers neither `DescribeConfigs` nor `DescribeAcls`, so the answers that
//! the compose broker cannot give (an allow-everyone setting, a refused probe) are injected through
//! the cluster seam in the unit tests of the inspector; the tests here run the real client.

use std::time::Duration;

use iam_domain::{
    CheckSource, ConfigGates, ConfigurationVerdict, KafkaInspectionError, KafkaTopicInspector as _,
};
use iam_infrastructure::{
    KafkaSecret, KafkaSecurity, KafkaSettings, KrafkaTopicInspector, SaslMechanism,
};
use krafka::Kafka;
use krafka::admin::{
    AclBinding, AclFilter, AclResourceType, CreateAclsOptions, CreateTopicsOptions,
    DeleteAclsOptions, NewTopic,
};
use rstest::rstest;
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;
use test_support::log::LogRecorder;
use tracing::Level;

/// How long a test waits for the cluster to show what it just created.
const DEADLINE: Duration = Duration::from_secs(30);

/// The pause between two reads while a test waits for the cluster.
const POLL: Duration = Duration::from_millis(300);

/// The settings the gates require of the state topic.
const REQUIRED: [(&str, &str); 4] = [
    ("cleanup.policy", "compact"),
    ("min.insync.replicas", "2"),
    ("unclean.leader.election.enable", "false"),
    ("message.timestamp.type", "LogAppendTime"),
];

#[expect(
    clippy::disallowed_methods,
    reason = "the test stack is described by the environment"
)]
fn stack_variable(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run the tests through `make`"))
}

fn settings(topic: &str, gates: ConfigGates) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: stack_variable("KAFKA_BOOTSTRAP_SERVERS"),
        security: KafkaSecurity::Plaintext,
        client_id: "iam-integration-test".to_owned(),
        connect_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
        retry_delay: Duration::from_millis(100),
        gates,
        policy_topic: topic.to_owned(),
        events_topic: "unused-events-topic".to_owned(),
    }
}

async fn admin_client() -> Kafka {
    Kafka::builder(stack_variable("KAFKA_BOOTSTRAP_SERVERS"))
        .client_id("iam-integration-test-admin")
        .connect()
        .await
        .unwrap()
}

/// A topic name no earlier run used: the compose broker keeps its topics between runs.
fn unique_topic(label: &str) -> String {
    format!("iam-it-{label}-{}", UuidV7Generator.generate())
}

/// Creates a topic of `partitions` partitions and one replica with `config`.
async fn create_topic(topic: &str, partitions: i32, config: &[(&str, &str)]) {
    let kafka = admin_client().await;
    let new_topic = config.iter().fold(
        NewTopic::new(topic, partitions, 1).unwrap(),
        |new_topic, (name, value)| new_topic.with_config(*name, *value),
    );
    let results = kafka
        .admin()
        .create_topics([new_topic], CreateTopicsOptions::default())
        .await
        .unwrap();
    drop(kafka);
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

/// The configuration of `REQUIRED` with `name` set to `value`.
fn required_except(name: &str, value: &str) -> Vec<(String, String)> {
    REQUIRED
        .iter()
        .map(|(setting, required)| {
            let chosen = if *setting == name { value } else { required };
            ((*setting).to_owned(), chosen.to_owned())
        })
        .collect()
}

async fn create_with(topic: &str, partitions: i32, config: &[(String, String)]) {
    let pairs: Vec<(&str, &str)> = config
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    create_topic(topic, partitions, &pairs).await;
}

/// Inspects until `done` accepts the verdict or [`DEADLINE`] elapsed: a topic that was created a
/// moment ago can still be unknown to the broker that answers, and a read of it can fail with
/// `UnknownTopicOrPartition` until the metadata has spread, so an error is retried as well and only
/// the last one, at the deadline, fails the test.
async fn inspect_until<F>(inspector: &KrafkaTopicInspector, done: F) -> ConfigurationVerdict
where
    F: Fn(&ConfigurationVerdict) -> bool,
{
    let started = tokio::time::Instant::now();
    loop {
        let expired = started.elapsed() >= DEADLINE;
        match inspector.inspect().await {
            Ok(verdict) if expired || done(&verdict) => return verdict,
            Err(error) if expired => panic!("the inspection kept failing: {error}"),
            Ok(_) | Err(_) => tokio::time::sleep(POLL).await,
        }
    }
}

fn names(verdict: &ConfigurationVerdict, setting: &str) -> bool {
    verdict
        .violations()
        .iter()
        .any(|violation| violation.setting == setting)
}

#[tokio::test]
async fn compose_topics_pass_with_relaxed_gates_and_every_check_warns() {
    let (recorder, _guard) = LogRecorder::install();
    let topic = unique_topic("relaxed");
    create_topic(&topic, 1, &REQUIRED).await;
    let inspector = KrafkaTopicInspector::new(&settings(&topic, ConfigGates::Relaxed));

    let verdict = inspect_until(&inspector, ConfigurationVerdict::passed).await;
    let again = inspector.inspect().await.unwrap();

    assert!(verdict.passed(), "{}", verdict.describe());
    assert!(again.passed(), "{}", again.describe());
    let warnings: Vec<_> = recorder
        .lines()
        .into_iter()
        .filter(|line| line.level == Level::WARN && line.field("gates") == Some("relaxed"))
        .collect();
    assert!(warnings.len() >= 2, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .all(|line| line.message.contains("KAFKA_CONFIG_GATES"))
    );
}

#[tokio::test]
async fn a_topic_that_breaks_one_rule_fails_the_verdict_and_names_the_setting() {
    // `min.insync.replicas` is enforced as 2 under the enforced gates only: the relaxed gates of a
    // single-node broker accept any value of at least 1, the only values Kafka allows.
    let cases = [
        (
            "cleanup.policy",
            required_except("cleanup.policy", "delete"),
            1,
            ConfigGates::Relaxed,
        ),
        (
            "unclean.leader.election.enable",
            required_except("unclean.leader.election.enable", "true"),
            1,
            ConfigGates::Relaxed,
        ),
        (
            "min.insync.replicas",
            required_except("min.insync.replicas", "1"),
            1,
            ConfigGates::Enforce,
        ),
        (
            "partitions",
            required_except("", ""),
            2,
            ConfigGates::Relaxed,
        ),
        (
            "message.timestamp.type",
            required_except("message.timestamp.type", "CreateTime"),
            1,
            ConfigGates::Relaxed,
        ),
    ];

    for (setting, config, partitions, gates) in cases {
        let topic = unique_topic("broken");
        create_with(&topic, partitions, &config).await;
        let inspector = KrafkaTopicInspector::new(&settings(&topic, gates));

        let verdict = inspect_until(&inspector, |verdict| names(verdict, setting)).await;

        assert!(!verdict.passed(), "{setting}");
        assert!(
            names(&verdict, setting),
            "{setting}: {}",
            verdict.describe()
        );
    }
}

#[tokio::test]
async fn enforced_gates_name_the_replication_factor_of_a_single_node_topic() {
    let topic = unique_topic("enforce");
    create_topic(&topic, 1, &REQUIRED).await;
    let inspector = KrafkaTopicInspector::new(&settings(&topic, ConfigGates::Enforce));

    let verdict = inspect_until(&inspector, |verdict| names(verdict, "replication.factor")).await;

    assert!(!verdict.passed());
    assert_eq!(verdict.gates(), ConfigGates::Enforce);
    assert!(
        names(&verdict, "replication.factor"),
        "{}",
        verdict.describe()
    );
}

#[tokio::test]
async fn a_principal_other_than_iam_control_that_may_write_fails_the_enforced_verdict() {
    let topic = unique_topic("acl");
    create_topic(&topic, 1, &REQUIRED).await;
    let kafka = admin_client().await;
    let created = kafka
        .admin()
        .create_acls(
            vec![AclBinding::allow_write_topic(topic.as_str(), "User:other")],
            CreateAclsOptions::default(),
        )
        .await
        .unwrap();
    assert!(
        created.iter().all(|(_, result)| result.is_ok()),
        "{created:?}"
    );
    let inspector = KrafkaTopicInspector::new(&settings(&topic, ConfigGates::Enforce));

    let verdict = inspect_until(&inspector, |verdict| names(verdict, "acl.write")).await;
    let removed = kafka
        .admin()
        .delete_acls(
            vec![AclFilter::for_resource(
                AclResourceType::Topic,
                topic.as_str(),
            )],
            DeleteAclsOptions::default(),
        )
        .await
        .unwrap();
    drop(kafka);

    assert!(names(&verdict, "acl.write"), "{}", verdict.describe());
    assert!(
        verdict.describe().contains("acl.write is User:other"),
        "{}",
        verdict.describe()
    );
    assert!(
        removed.iter().all(|(_, result)| result.is_ok()),
        "{removed:?}"
    );
}

#[tokio::test]
async fn a_broker_that_omits_allow_everyone_is_checked_through_the_fallback_probe() {
    let topic = unique_topic("fallback");
    create_topic(&topic, 1, &REQUIRED).await;
    let inspector = KrafkaTopicInspector::new(&settings(&topic, ConfigGates::Enforce));

    let verdict = inspect_until(&inspector, |verdict| {
        names(verdict, "allow.everyone.if.no.acl.found")
    })
    .await;

    // The compose broker never returns the setting, and its PLAINTEXT principal is a super user, so
    // the principal without an ACL is answered: the allow-everyone answer fails the verdict.
    assert_eq!(verdict.allow_everyone_source(), Some(CheckSource::Fallback));
    assert!(
        names(&verdict, "allow.everyone.if.no.acl.found"),
        "{}",
        verdict.describe()
    );
    assert!(
        verdict.describe().contains("(fallback)"),
        "{}",
        verdict.describe()
    );
}

#[tokio::test]
async fn a_cluster_that_cannot_be_reached_is_unavailable() {
    let mut unreachable = settings("any-topic", ConfigGates::Relaxed);
    unreachable.bootstrap_servers = "127.0.0.1:1".to_owned();
    unreachable.connect_timeout = Duration::from_millis(500);
    unreachable.request_timeout = Duration::from_secs(1);

    let error = KrafkaTopicInspector::new(&unreachable)
        .inspect()
        .await
        .unwrap_err();

    assert!(matches!(error, KafkaInspectionError::Unavailable(_)));
}

#[rstest]
#[case::scram_sha_256(SaslMechanism::ScramSha256)]
#[case::scram_sha_512(SaslMechanism::ScramSha512)]
#[tokio::test]
async fn the_sasl_password_never_appears_in_a_log_line_or_an_error(
    #[case] mechanism: SaslMechanism,
) {
    let (recorder, _guard) = LogRecorder::install();
    let password = format!("pw-{}", UuidV7Generator.generate());
    let mut secured = settings("any-topic", ConfigGates::Enforce);
    secured.bootstrap_servers = stack_variable("KAFKA_SASL_SSL_BOOTSTRAP_SERVERS");
    secured.security = KafkaSecurity::SaslSsl {
        mechanism,
        username: "nobody".to_owned(),
        password: KafkaSecret::new(password.clone()),
        ca_file: Some(format!("{}/ca.pem", stack_variable("KAFKA_TLS_DIR"))),
        probe: None,
    };

    let error = KrafkaTopicInspector::new(&secured)
        .inspect()
        .await
        .unwrap_err();

    assert!(matches!(error, KafkaInspectionError::Unavailable(_)));
    assert!(!format!("{error:?} {error}").contains(&password));
    assert!(!format!("{secured:?}").contains(&password));
    let lines = recorder.lines();
    assert_ne!(lines.len(), 0);
    for line in lines {
        assert!(!line.message.contains(&password), "{line:?}");
        assert!(
            line.fields
                .iter()
                .all(|(_, value)| !value.contains(&password)),
            "{line:?}"
        );
    }
}
