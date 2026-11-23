#!/bin/sh
# Creates the two topics of IAM on the compose broker `kafka` (Story 7.3): the state topic and the events
# topic, with the settings that the Kafka configuration gates of FR-72 require, except the replication factor,
# which is 1 because the compose broker is a single node; `KAFKA_CONFIG_GATES=relaxed` accepts that in `dev`
# and `test`. `min.insync.replicas` is 1 here for the same reason: with a single replica, `acks=all` could
# never be acknowledged under 2.
#
# The compose one-shot service `kafka-topics` runs it once the broker is healthy. It is idempotent: a topic
# that exists keeps its settings, and the settings are applied again so that a topic created by an earlier
# version of this script is corrected.
#
# Usage: scripts/kafka-topics-fixture.sh <bootstrap-server> <state-topic> <events-topic>
# Needs: the Kafka command-line tools (the `apache/kafka` image ships them under /opt/kafka/bin).
set -eu

bootstrap="${1:?usage: kafka-topics-fixture.sh <bootstrap-server> <state-topic> <events-topic>}"
state="${2:?usage: kafka-topics-fixture.sh <bootstrap-server> <state-topic> <events-topic>}"
events="${3:?usage: kafka-topics-fixture.sh <bootstrap-server> <state-topic> <events-topic>}"
bin=/opt/kafka/bin

# create <topic> <cleanup.policy>
create() {
    "$bin/kafka-topics.sh" --bootstrap-server "$bootstrap" --create --if-not-exists \
        --topic "$1" --partitions 1 --replication-factor 1 \
        --config "cleanup.policy=$2" \
        --config min.insync.replicas=1 \
        --config unclean.leader.election.enable=false \
        --config message.timestamp.type=LogAppendTime
    "$bin/kafka-configs.sh" --bootstrap-server "$bootstrap" --alter --entity-type topics --entity-name "$1" \
        --add-config "cleanup.policy=$2,min.insync.replicas=1,unclean.leader.election.enable=false,message.timestamp.type=LogAppendTime"
}

create "$state" compact
create "$events" delete
