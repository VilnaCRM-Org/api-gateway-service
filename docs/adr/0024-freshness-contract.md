# 0024. Freshness contract: watermark proof, replica-quorum epoch check, `T_hard` and Sync-Fence

Status: proposed. The bound it declares stays conditional until the results of Story 1.3 (the replica-quorum observation on the three-broker profile) and test T15 (Story 16.8, one zone isolated with the old partition leader) confirm the replica-quorum argument below. Story 9.5 builds the proof, the attachment, the staleness rule and the endpoint; Sync-Fence (Story 13.x) builds on it.

Planning decisions: sections 9.5 to 9.8 of `specs/8-iam-scaffolding-and-spikes/architecture.md` (freshness proof, guarantees, choosing `T_hard`, write modes and Sync-Fence) and requirements FR-73 and NFR-36 of its `prd.md`.

## Context

A gateway pod decides from an in-process snapshot of the policy (ADR 0014) that it follows from the state topic (ADR 0017). Nothing makes an update atomic across PostgreSQL and every pod, and the high watermark alone proves nothing, because an isolated partition leader keeps answering with its frozen watermark. The gateway therefore needs a per-pod proof that its snapshot contains every acknowledged change, taken against a quorum, and a rule that stops it from allowing when the proof is missing or old.

## Decision

Each pod proves its own freshness and enforces a bound `T_hard` (`FRESHNESS_HARD_BOUND`, 15 s by default, 3 to 30 s) on the age of the proof.

1. **Clock.** Every elapsed-time rule reads `CLOCK_BOOTTIME` through the `BootClock` port (`LinuxBootClock`, `rustix`). A watchdog ticks every second; a gap between two ticks above `T_ready` (`FRESHNESS_READY_BOUND`) invalidates the proof it spans, so a frozen or suspended process cannot keep allowing on an old proof.
2. **Probe.** `KrafkaPolicyLogProbe` runs every `FRESHNESS_PROBE_INTERVAL` (500 ms by default). It records `t_s` on the boot clock before it sends anything. It asks the replica brokers of the state partition for their metadata, each through a client seeded with that broker only (krafka cannot address a Metadata request to a chosen broker, ADR 0026), and needs a majority of the replicas to answer with the same leader and leader epoch, an epoch at least the highest seen and exactly one partition. It then sends `ListOffsets` with the isolation `READ_COMMITTED` for every partition through the consumer path, which carries the leader epoch of its freshly refreshed metadata. The answer for the state partition is `HW(t_s)`, the last stable offset. `OFFSET_NOT_AVAILABLE`, `FENCED_LEADER_EPOCH`, `UNKNOWN_LEADER_EPOCH`, a watermark lower than one seen before and a nonzero watermark on another partition each yield no proof.
3. **Attachment.** The apply thread attaches a proof to the published snapshot only once the snapshot holds every complete version whose last record lies below `HW(t_s)`. It learns the reach of the applied versions from the records it handles and, for the commit markers behind the last record, from the idle polls of the tail, which report the last stable offset. With the transactional relay an open transaction holds `HW(t_s)` at its first record, so no proof requires a version before its commit. The proof never claims more than the snapshot that serves requests contains.
4. **Rule.** `FreshnessRule` allows only while `now_boot - last_proof <= T_hard` and the watchdog saw no gap above `T_ready` since that proof. The snapshot step of the public listener evaluates it with the published snapshot and answers 503 `iam_stale` with `Retry-After: 1` otherwise (the decision API answers `deny` with reason `unavailable`).
5. **Peer cross-check.** When a peer reports an applied version above this pod's published version for more than 1 s while this pod's proof says fresh, the pod treats its proof as invalid and alerts. Until Story 15.1 wires the peer client, the composition root passes an empty peer set and the check is inactive; this state never leaves the feature branch.
6. **Observability.** `/internal/freshness` on the internal listener reports the published version, the age of the proof, the digest and the configured `T_hard` as `hardBoundMs`; the metric events `policy_proof_age_seconds` and `policy_fresh` are emitted on every watchdog tick.
7. **Sync-Fence.** The coordinator of `iam-control` (Story 13.x) answers `complete` when every polled pod applied the version and `bounded` after `max(own T_hard, the highest hardBoundMs reported) + SYNC_FENCE_MARGIN`; a pod that did not answer cannot allow on older state by then, because an allow needs a proof whose probe was sent after the acknowledgement, so its snapshot contains the version.

The default mode counts the bound from the Kafka acknowledgement. Committed but unacknowledged changes are not enforced until published. The strict mode with heartbeats, which counts from the commit at an availability cost, is built only if Story 1.3 or T15 fails.

| Option | Outcome | Reason |
| --- | --- | --- |
| Watermark proof with a replica-quorum epoch check | Chosen | Needs no record written to Kafka and closes the zombie-leader case if a broker's Metadata answer is never older than the epoch its replica fetcher uses |
| High watermark alone | Rejected | An isolated leader keeps answering with a frozen watermark |
| Sequenced liveness record from `iam-control` | Fallback | Needs an owner ruling (D17) if the quorum check cannot be built |
| Strict mode with heartbeats | Later phase | Counts from the commit, at an availability cost |

## Consequences

The bound is conditional: it rests on one point no client API shows, that a broker's Metadata answer is never older than the leader epoch its own replica fetcher uses. Story 1.3 recorded that the point is not observable through krafka and Story 16.8 tests it (T15); until then the guarantees G4 and G8 are declared conditional. A Kafka outage longer than `T_hard` blocks every request, anonymous routes included, because a stale pod must not keep serving a route that has become protected. `FRESHNESS_HARD_BOUND` must stay above `KAFKA_TRANSACTION_TIMEOUT`, so a hanging zombie transaction cannot pin the last stable offset past the bound. The probe opens one short-lived client per replica broker per probe; its cost is measured by the load stories.
