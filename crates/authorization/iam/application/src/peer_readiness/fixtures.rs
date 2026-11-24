//! A small cluster of gateway pods for the tests of the peer comparison: the pods share one
//! endpoint directory, one boot clock and one reader that answers for every peer.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AzFloor, BootClock as _, Condition, EndpointConditions, EndpointParts, EndpointSlice,
    FreshnessRule, PeerObservation, PolicyVersion, UpstreamEndpoint, WatchTarget, Zone,
};
use test_support::boot_clock::FakeBootClock;
use test_support::peer_freshness_reader::FakePeerFreshnessReader;
use test_support::rng::FakeRng;

use super::{PeerReadinessChecker, PeerSet, PeerSetPorts, ReadinessGate};
use crate::endpoint_directory::{EndpointDirectory, ZoneSource};
use crate::freshness::FreshnessState;

pub(super) const HARD: Duration = Duration::from_secs(15);
pub(super) const READY: Duration = Duration::from_secs(2);

pub(super) fn zone(name: &str) -> Zone {
    Zone::new(name).unwrap()
}

pub(super) fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

/// A peer endpoint whose address is its pod name.
pub(super) fn endpoint(pod: &str, zone_name: &str, ready: bool) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: pod.to_owned(),
        port: 9090,
        zone: Some(zone(zone_name)),
        pod: Some(pod.to_owned()),
        conditions: EndpointConditions::healthy().with(Condition::Ready, ready),
    })
}

/// What a fresh peer reports.
pub(super) fn current(version_number: i64) -> PeerObservation {
    PeerObservation {
        version: Some(version(version_number)),
        fresh: true,
        proof_age: Some(Duration::from_millis(100)),
    }
}

/// What a stale peer reports.
pub(super) fn stale(version_number: i64) -> PeerObservation {
    PeerObservation {
        version: Some(version(version_number)),
        fresh: false,
        proof_age: Some(Duration::from_secs(20)),
    }
}

/// The pods that share the directory, the clock and the reader.
pub(super) struct Cluster {
    directories: Mutex<Vec<Arc<EndpointDirectory>>>,
    pub(super) target: WatchTarget,
    pub(super) reader: Arc<FakePeerFreshnessReader>,
    pub(super) clock: Arc<FakeBootClock>,
    pods: Vec<(String, String)>,
}

/// One pod of the cluster.
pub(super) struct Member {
    pub(super) peers: Arc<PeerSet>,
    pub(super) state: Arc<FreshnessState>,
    pub(super) gate: Arc<ReadinessGate>,
    pub(super) checker: PeerReadinessChecker,
}

impl Cluster {
    /// A cluster of `pods`, each a name and a zone, all listed ready in the peers slices.
    pub(super) fn of(pods: &[(&str, &str)]) -> Self {
        let target = WatchTarget {
            namespace: "iam".to_owned(),
            service: "iam-gateway-peers".to_owned(),
        };
        Self {
            directories: Mutex::new(Vec::new()),
            target,
            reader: Arc::new(FakePeerFreshnessReader::new()),
            clock: Arc::new(FakeBootClock::new()),
            pods: pods
                .iter()
                .map(|(pod, zone_name)| ((*pod).to_owned(), (*zone_name).to_owned()))
                .collect(),
        }
    }

    /// Lists every pod ready in the peers slices of every member except the `unready` ones.
    pub(super) fn publish(&self, unready: &[&str]) {
        let directories = self
            .directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for directory in directories.iter() {
            directory.replace(&self.target, self.slices(unready));
        }
    }

    /// The pod `name` of the cluster with a zone `floor`.
    pub(super) fn member(&self, name: &str, floor: usize) -> Member {
        let directory = Arc::new(EndpointDirectory::new(ZoneSource {
            peers: self.target.clone(),
            pod: Some(name.to_owned()),
            explicit: None,
        }));
        directory.replace(&self.target, self.slices(&[]));
        self.directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&directory));
        let rule = FreshnessRule::new(HARD, READY);
        let peers = Arc::new(PeerSet::new(PeerSetPorts {
            view: directory.view(),
            target: self.target.clone(),
            pod: Some(name.to_owned()),
            reader: Arc::<FakePeerFreshnessReader>::clone(&self.reader),
            rng: Arc::new(FakeRng::seeded(1)),
            rule,
        }));
        let state = Arc::new(FreshnessState::new(
            rule,
            Arc::<FakeBootClock>::clone(&self.clock),
        ));
        let gate = Arc::new(ReadinessGate::new());
        let checker = PeerReadinessChecker::new(
            Arc::clone(&peers),
            Arc::clone(&state),
            Arc::clone(&gate),
            AzFloor::new(floor),
        );
        Member {
            peers,
            state,
            gate,
            checker,
        }
    }

    fn slices(&self, unready: &[&str]) -> Vec<EndpointSlice> {
        vec![EndpointSlice {
            name: "slice".to_owned(),
            endpoints: self
                .pods
                .iter()
                .map(|(pod, zone_name)| endpoint(pod, zone_name, !unready.contains(&pod.as_str())))
                .collect(),
        }]
    }
}

impl Member {
    /// The pod holds a proof taken now.
    pub(super) fn prove(&self, clock: &FakeBootClock) {
        assert!(self.state.attach(
            FreshnessProof {
                taken_at: clock.now(),
                watermark: 5,
            },
            version(5),
        ));
    }
}
