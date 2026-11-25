//! A rig that writes versioned transactions as the outbox does and offers their records to a
//! builder.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    AssignmentScope, AssignmentState, CatalogueChunk, CatalogueEntryState, CatalogueManifest,
    ChunkId, EnforcementMode, EntityVersion, GrantState, HttpMethod, LogEpoch, PolicyDigestValue,
    PolicySnapshot, PolicyState, PolicyVersion, PolicyView as _, RateFallback, RateKeyKind,
    RatePolicyDraft, RatePolicyFields, RatePolicyId, RatePolicyState, RelayEpoch, RetryPolicy,
    RoleId, RoleKind, RoleState, RouteDraft, RouteFields, RouteFlags, RouteId, RouteState,
    ServiceName, StateBatch, StateChange, StateKey, StateRecordCodec as _, SubjectRef,
    SubjectState, UpstreamFields, UpstreamId, UpstreamProtocol, UpstreamSettingsDraft,
    UpstreamState, VersionedRecord,
};
use shared_domain::Uuid;
use test_support::boot_clock::FakeBootClock;

use super::super::{ApplyOutcome, PolicySnapshotBuilder, SnapshotPorts};
use crate::policy_snapshot::{ArcSwapPolicySnapshot, MatchitRouteTableCompiler};
use crate::policy_state::json_state_record_codec::JsonStateRecordCodec;
use crate::policy_state::sha256_policy_digest::Sha256PolicyDigest;

/// `number` past `base`, for the identifiers of one kind of entry.
fn offset(base: u32, number: u32) -> u32 {
    base.checked_add(number).unwrap()
}

pub(super) fn uuid(number: u32) -> Uuid {
    Uuid::parse(&format!("0192f6a0-0000-7000-8000-{number:012x}")).unwrap()
}

pub(super) fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

/// The change of one key: its new state, or `None` to delete it.
pub(super) type Edit = (StateKey, Option<PolicyState>);

pub(super) fn role_key(number: u32) -> StateKey {
    StateKey::Role(RoleId::from_uuid(uuid(number)))
}

pub(super) fn role(number: u32, grants: &[&str]) -> Edit {
    let state = PolicyState::Role(RoleState {
        id: RoleId::from_uuid(uuid(number)),
        name: format!("role-{number}"),
        description: None,
        kind: RoleKind::Custom,
        version: EntityVersion::INITIAL,
        grants: grants
            .iter()
            .map(|key| GrantState {
                key: (*key).to_owned(),
                active: true,
            })
            .collect(),
    });
    (role_key(number), Some(state))
}

pub(super) fn subject_ref(number: u32) -> SubjectRef {
    SubjectRef::user(uuid(offset(1_000, number)))
}

pub(super) fn subject_key(number: u32) -> StateKey {
    StateKey::Subject(subject_ref(number))
}

/// A subject that holds `roles`, or a tombstone when there are none.
pub(super) fn subject(number: u32, roles: &[u32]) -> Edit {
    let subject = subject_ref(number);
    let assignments: Vec<AssignmentState> = roles
        .iter()
        .map(|role| AssignmentState {
            role: RoleId::from_uuid(uuid(*role)),
            scope: AssignmentScope::Global,
            expires_at_micros: None,
        })
        .collect();
    let state = (!assignments.is_empty()).then(|| {
        PolicyState::Subject(
            SubjectState {
                subject: subject.clone(),
                assignments,
            }
            .canonical(),
        )
    });
    (StateKey::Subject(subject), state)
}

pub(super) fn upstream_id(number: u32) -> UpstreamId {
    UpstreamId::from_uuid(uuid(offset(2_000, number)))
}

pub(super) fn upstream(number: u32, port: i64) -> Edit {
    let name = format!("svc-{number}");
    let (name, settings) = UpstreamFields::new(
        &name,
        &UpstreamSettingsDraft {
            namespace: "platform".to_owned(),
            service_name: format!("service-{number}"),
            catalog_service: format!("cat-{}", number % 2),
            port,
            protocol: UpstreamProtocol::H2c,
            forward_credentials: false,
            connect_timeout_ms: 1_000,
            response_timeout_ms: 30_000,
            concurrency_limit: 256,
            retry_budget_percent: 20,
            outlier_threshold: 5,
        },
    )
    .unwrap()
    .into_parts();
    let state = UpstreamState {
        id: upstream_id(number),
        name: name.clone(),
        settings,
        system: false,
        version: EntityVersion::INITIAL,
    };
    (StateKey::Upstream(name), Some(PolicyState::Upstream(state)))
}

pub(super) fn upstream_key(number: u32) -> StateKey {
    StateKey::Upstream(iam_domain::UpstreamName::new(&format!("svc-{number}")).unwrap())
}

pub(super) fn route_id(number: u32) -> RouteId {
    RouteId::from_uuid(uuid(offset(3_000, number)))
}

/// A route of `host` for `/r<number>/{id}`.
pub(super) fn route(number: u32, host: &str) -> Edit {
    route_with_pattern(number, host, &format!("/r{number}/{{id}}"))
}

/// A route of `host` for `pattern`.
pub(super) fn route_with_pattern(number: u32, host: &str, pattern: &str) -> Edit {
    let draft = RouteDraft {
        host: host.to_owned(),
        methods: vec![HttpMethod::Get, HttpMethod::Post],
        path_pattern: pattern.to_owned(),
        service: "cat-0".to_owned(),
        upstream_id: upstream_id(0),
        flags: RouteFlags::default(),
        enforcement: EnforcementMode::Enforce,
        body_limit: 1_048_576,
        request_timeout_ms: 30_000,
        idle_timeout_ms: 60_000,
        retry: RetryPolicy::None,
        rate_policies: Vec::new(),
        cors: None,
    };
    let state = RouteState {
        id: route_id(number),
        fields: RouteFields::new(&draft).unwrap(),
        system: false,
        version: EntityVersion::INITIAL,
    };
    (
        StateKey::Route(route_id(number)),
        Some(PolicyState::Route(state)),
    )
}

pub(super) fn route_key(number: u32) -> StateKey {
    StateKey::Route(route_id(number))
}

pub(super) fn rate_policy_id(number: u32) -> RatePolicyId {
    RatePolicyId::from_uuid(uuid(offset(4_000, number)))
}

pub(super) fn rate_policy(number: u32, limit: i64) -> Edit {
    let id = rate_policy_id(number);
    let state = RatePolicyState {
        id,
        fields: RatePolicyFields::new(RatePolicyDraft {
            name: format!("policy-{number}"),
            key_kind: RateKeyKind::SubjectRoute,
            limit,
            period_seconds: 60,
            burst: 1,
            fallback: RateFallback::Full,
        })
        .unwrap(),
        version: EntityVersion::INITIAL,
    };
    (
        StateKey::RatePolicy(id),
        Some(PolicyState::RatePolicy(state)),
    )
}

pub(super) fn service(number: u32) -> ServiceName {
    ServiceName::new(&format!("cat-{number}")).unwrap()
}

/// The manifest of the catalogue of service `number` with one chunk `chunk`, and that chunk.
pub(super) fn catalogue(number: u32, chunk: &str, keys: &[&str]) -> (Edit, Edit) {
    let id = ChunkId::new(chunk).unwrap();
    let manifest = PolicyState::Manifest(CatalogueManifest {
        service: service(number),
        catalog_epoch: 1,
        chunks: vec![id.clone()],
    });
    let chunk_state = PolicyState::Chunk(CatalogueChunk {
        service: service(number),
        entries: keys
            .iter()
            .map(|key| CatalogueEntryState::untyped((*key).to_owned(), [false, false]))
            .collect(),
    });
    (
        (StateKey::CatalogueManifest(service(number)), Some(manifest)),
        (StateKey::chunk(service(number), id), Some(chunk_state)),
    )
}

/// The key of the manifest of service `number`.
pub(super) fn manifest_key(number: u32) -> StateKey {
    StateKey::CatalogueManifest(service(number))
}

/// A builder, the cell it publishes into and the log it reads, as the outbox writes it.
pub(super) struct Rig {
    pub(super) builder: PolicySnapshotBuilder,
    pub(super) cell: Arc<ArcSwapPolicySnapshot>,
    pub(super) clock: Arc<FakeBootClock>,
    pub(super) codec: JsonStateRecordCodec,
    pub(super) hasher: Sha256PolicyDigest,
    /// The live state after the last transaction written.
    pub(super) model: BTreeMap<StateKey, (PolicyVersion, PolicyState)>,
    pub(super) version: i64,
    pub(super) digest: PolicyDigestValue,
    pub(super) relay_epoch: i64,
}

impl Rig {
    pub(super) fn new() -> Self {
        Self::with_interval(crate::policy_snapshot::PUBLISH_INTERVAL)
    }

    pub(super) fn with_interval(interval: Duration) -> Self {
        let clock = Arc::new(FakeBootClock::new());
        let cell = Arc::new(ArcSwapPolicySnapshot::new());
        let builder = PolicySnapshotBuilder::new(ports(&clock), Arc::clone(&cell), interval);
        Self {
            builder,
            cell,
            clock,
            codec: JsonStateRecordCodec,
            hasher: Sha256PolicyDigest,
            model: BTreeMap::new(),
            version: 0,
            digest: PolicyDigestValue::ZERO,
            relay_epoch: 1,
        }
    }

    /// Writes the next versioned transaction of `edits` and returns its records, without offering
    /// them to the builder.
    pub(super) fn write(&mut self, edits: Vec<Edit>) -> Vec<VersionedRecord> {
        self.write_after(edits, self.digest)
    }

    /// Like [`Self::write`], but the batch starts from `before` instead of the true digest.
    pub(super) fn write_after(
        &mut self,
        edits: Vec<Edit>,
        before: PolicyDigestValue,
    ) -> Vec<VersionedRecord> {
        let next = self.version.checked_add(1).unwrap();
        let changes: Vec<StateChange> = edits
            .iter()
            .map(|(key, after)| StateChange {
                key: key.clone(),
                before: self.model.get(key).map(|(_, state)| state.clone()),
                after: after.clone(),
            })
            .collect();
        let batch =
            StateBatch::assemble(version(next), before, changes, (&self.codec, &self.hasher))
                .unwrap();
        let by_key: BTreeMap<StateKey, Option<PolicyState>> = edits.into_iter().collect();
        for (key, after) in by_key {
            // The batch writes no record for an edit that leaves the state as it was, so the
            // entry keeps the version it last changed in.
            let unchanged = self.model.get(&key).map(|(_, state)| state) == after.as_ref();
            if unchanged {
                continue;
            }
            match after {
                Some(state) => self.model.insert(key, (version(next), state)),
                None => self.model.remove(&key),
            };
        }
        self.version = next;
        self.digest = batch.digest();
        self.records_of(&batch)
    }

    pub(super) fn records_of(&self, batch: &StateBatch) -> Vec<VersionedRecord> {
        batch
            .rows()
            .iter()
            .map(|row| VersionedRecord {
                key: row.key().clone(),
                payload: row.payload().map(str::to_owned),
                version: batch.version(),
                seq: row.seq(),
                count: row.count(),
                digest_after: row.digest_after(),
                log_epoch: LogEpoch::new(1).unwrap(),
                relay_epoch: RelayEpoch::new(self.relay_epoch).unwrap(),
            })
            .collect()
    }

    /// Writes a transaction and offers every record in order; the outcome of the last one.
    pub(super) fn apply(&mut self, edits: Vec<Edit>) -> ApplyOutcome {
        let records = self.write(edits);
        self.offer_all(records)
    }

    pub(super) fn offer_all(&mut self, records: Vec<VersionedRecord>) -> ApplyOutcome {
        let mut outcome = ApplyOutcome::Malformed;
        for record in records {
            outcome = self.builder.offer(record);
        }
        outcome
    }

    pub(super) fn snapshot(&self) -> Arc<dyn PolicySnapshot> {
        self.cell.current().expect("a published snapshot")
    }

    /// The canonical text of a state.
    pub(super) fn encode(&self, state: &PolicyState) -> String {
        self.codec.encode(state).unwrap()
    }
}

pub(super) fn ports(clock: &Arc<FakeBootClock>) -> SnapshotPorts {
    let boot_clock: Arc<dyn iam_domain::BootClock> = Arc::<FakeBootClock>::clone(clock);
    SnapshotPorts {
        codec: Arc::new(JsonStateRecordCodec),
        digest: Arc::new(Sha256PolicyDigest),
        compiler: Arc::new(MatchitRouteTableCompiler),
        boot_clock,
    }
}
