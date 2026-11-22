//! Capability 5: `DescribeConfigs` on a topic and on the broker, and `DescribeAcls`, return every value the
//! Kafka configuration gates of FR-72 read.
//!
//! The compose broker runs the `KRaft` ACL authorizer (`StandardAuthorizer`, the successor of the `simple`
//! authorizer) with `allow.everyone.if.no.acl.found=false`; the anonymous PLAINTEXT principal is its super user,
//! so the spike tests keep full access. `allow.everyone.if.no.acl.found` is an authorizer property outside the
//! broker's configuration definition, and a broker reports such a key as sensitive without a value, or not at
//! all: the broker test accepts either, never a readable `true`, and `docs/spikes/phase-0.md` records the
//! fallback the gates use instead.

use std::time::Duration;

use krafka::admin::{
    AclBinding, AclFilter, AclOperation, AclPatternType, AclPermissionType, AclResourceType,
    ConfigEntry, ConfigResource, ConfigValue, CreateAclsOptions, CreateTopicsOptions,
    DeleteAclsOptions, DescribeAclsOptions, DescribeConfigsOptions, DescribeTopicsOptions,
    NewTopic,
};
use krafka::error::ErrorCode;
use krafka::{Kafka, KrafkaError};

use super::{DEADLINE, POLL, compose_broker, create_topic, unique_topic};

/// The node id of the compose broker (`KAFKA_NODE_ID` in `docker-compose.yml`).
const COMPOSE_BROKER: i32 = 1;

/// The topic settings the configuration gates of FR-72 refuse to run without; `min.insync.replicas` is the
/// production value 2 (the one-broker compose topic accepts it because nothing produces with `acks=all`).
const GATED_TOPIC_CONFIG: [(&str, &str); 4] = [
    ("cleanup.policy", "compact"),
    ("min.insync.replicas", "2"),
    ("unclean.leader.election.enable", "false"),
    ("message.timestamp.type", "LogAppendTime"),
];

/// The broker setting FR-72 wants `false`.
const ALLOW_EVERYONE: &str = "allow.everyone.if.no.acl.found";

/// The authorizer the compose broker runs.
const AUTHORIZER: &str = "org.apache.kafka.metadata.authorizer.StandardAuthorizer";

/// The one principal allowed to write the state topic.
const CONTROL_PRINCIPAL: &str = "User:iam-control";

/// Creates a one-partition topic with one replica and the [`GATED_TOPIC_CONFIG`] settings.
async fn create_gated_topic(kafka: &Kafka, topic: &str) {
    let new_topic = GATED_TOPIC_CONFIG.iter().fold(
        NewTopic::new(topic, 1, 1).unwrap(),
        |new_topic, (name, value)| new_topic.with_config(*name, *value),
    );
    let results = kafka
        .admin()
        .create_topics([new_topic], CreateTopicsOptions::default())
        .await
        .unwrap();
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

/// The entries `DescribeConfigs` returns for `resource`, asked again while the broker answers
/// `UNKNOWN_TOPIC_OR_PARTITION` and [`DEADLINE`] has not elapsed: `CreateTopics` returns before the controller's
/// metadata record reaches the broker that serves `DescribeConfigs`, so a topic created a moment ago can still be
/// unknown there.
async fn describe(kafka: &Kafka, resource: &ConfigResource) -> Vec<ConfigEntry> {
    let started = tokio::time::Instant::now();
    loop {
        let described = kafka
            .admin()
            .describe_configs([resource.clone()], DescribeConfigsOptions::default())
            .await
            .unwrap();
        let entries = described[resource].clone();
        let unknown = matches!(
            &entries,
            Err(KrafkaError::Broker {
                code: ErrorCode::UnknownTopicOrPartition,
                ..
            })
        );
        if !unknown || started.elapsed() >= DEADLINE {
            return entries.unwrap();
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The value of the entry `name`, or `None` when the broker did not return the key.
fn value_of(entries: &[ConfigEntry], name: &str) -> Option<ConfigValue> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .map(ConfigEntry::config_value)
}

/// The ACLs of `topic`, asked until at least one is listed or [`DEADLINE`] elapsed: the controller applies a
/// new ACL through the metadata log, a moment after `CreateAcls` returns.
async fn listed_acls(kafka: &Kafka, topic: &str) -> Vec<AclBinding> {
    let started = tokio::time::Instant::now();
    loop {
        let listed = kafka
            .admin()
            .describe_acls(
                AclFilter::for_resource(AclResourceType::Topic, topic),
                DescribeAclsOptions::default().timeout(Duration::from_secs(10)),
            )
            .await
            .unwrap();
        if !listed.is_empty() || started.elapsed() >= DEADLINE {
            return listed;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn describe_configs_returns_every_topic_value_the_configuration_gates_need() {
    let kafka = compose_broker().await;
    let topic = unique_topic("config");
    create_gated_topic(&kafka, &topic).await;

    let entries = describe(&kafka, &ConfigResource::topic(topic.as_str())).await;
    let described = kafka
        .admin()
        .describe_topics([topic.as_str()], DescribeTopicsOptions::default())
        .await
        .unwrap();
    drop(kafka);
    let description = described[&topic].as_ref().unwrap();

    for (name, value) in GATED_TOPIC_CONFIG {
        assert_eq!(
            value_of(&entries, name),
            Some(ConfigValue::Value(value.to_owned())),
            "{name}"
        );
    }
    assert_eq!(description.partitions.len(), 1);
    assert_eq!(
        description
            .partitions
            .first()
            .map(|partition| partition.replicas.len()),
        Some(1)
    );
}

#[tokio::test]
async fn describe_configs_on_the_broker_names_the_authorizer_and_never_a_readable_allow_everyone() {
    let kafka = compose_broker().await;

    let entries = describe(&kafka, &ConfigResource::broker(COMPOSE_BROKER)).await;
    drop(kafka);
    let allow_everyone = value_of(&entries, ALLOW_EVERYONE);

    assert_eq!(
        value_of(&entries, "authorizer.class.name"),
        Some(ConfigValue::Value(AUTHORIZER.to_owned()))
    );
    assert!(
        matches!(
            &allow_everyone,
            None | Some(ConfigValue::Sensitive | ConfigValue::Unavailable)
        ) || allow_everyone == Some(ConfigValue::Value("false".to_owned())),
        "{allow_everyone:?}"
    );
}

#[tokio::test]
async fn describe_acls_lists_the_write_acl_of_the_control_principal() {
    let kafka = compose_broker().await;
    let topic = unique_topic("acl");
    create_topic(&kafka, &topic).await;
    let created = kafka
        .admin()
        .create_acls(
            vec![AclBinding::allow_write_topic(
                topic.as_str(),
                CONTROL_PRINCIPAL,
            )],
            CreateAclsOptions::default(),
        )
        .await
        .unwrap();

    let listed = listed_acls(&kafka, &topic).await;
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

    assert!(
        created.iter().all(|(_, result)| result.is_ok()),
        "{created:?}"
    );
    assert_eq!(
        listed
            .iter()
            .map(|acl| (
                acl.resource_name.as_str(),
                acl.principal.as_str(),
                acl.operation,
                acl.permission_type,
                acl.pattern_type
            ))
            .collect::<Vec<_>>(),
        [(
            topic.as_str(),
            CONTROL_PRINCIPAL,
            AclOperation::Write,
            AclPermissionType::Allow,
            AclPatternType::Literal
        )]
    );
    assert!(
        removed.iter().all(|(_, result)| result.is_ok()),
        "{removed:?}"
    );
}
