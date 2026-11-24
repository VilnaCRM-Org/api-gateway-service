//! AZ-aware peer-relative readiness in process (Story 15.1, FR-85): gateway pods with fake peers
//! compare their freshness every check, fail readiness and shed their connections, keep the last
//! pod of a zone and stay ready when staleness is fleet-wide.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::routing::get;
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper::{Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use iam_application::{
    EndpointDirectory, FreshnessProber, FreshnessState, NotReady, PeerReadinessChecker, PeerSet,
    PeerSetPorts, PodProbes, PodStatus, ProberPorts, ProberSettings, ProofSink, ReadinessGate,
    ZoneSource,
};
use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{
    AzFloor, BootClock as _, EndpointConditions, EndpointParts, EndpointSlice, FreshnessRule,
    PeerObservation, PolicyVersion, UpstreamEndpoint, WatchTarget, Zone,
};
use service::bootstrap::gateway::shedding::{ConnectionSignals, serve};
use test_support::boot_clock::FakeBootClock;
use test_support::peer_freshness_reader::FakePeerFreshnessReader;
use test_support::policy_log_probe::FakePolicyLogProbe;
use test_support::policy_view::{EmptySnapshot, FakePolicyView};
use test_support::rng::FakeRng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;

const HARD: Duration = Duration::from_secs(15);
const READY: Duration = Duration::from_secs(2);
const LIMIT: Duration = Duration::from_secs(5);

const SIX: [(&str, &str); 6] = [
    ("gw-a1", "a"),
    ("gw-a2", "a"),
    ("gw-b1", "b"),
    ("gw-b2", "b"),
    ("gw-c1", "c"),
    ("gw-c2", "c"),
];

fn version(value: i64) -> PolicyVersion {
    PolicyVersion::new(value).unwrap()
}

fn current() -> PeerObservation {
    PeerObservation {
        version: Some(version(5)),
        fresh: true,
        proof_age: Some(Duration::from_millis(100)),
    }
}

fn stale() -> PeerObservation {
    PeerObservation {
        version: Some(version(5)),
        fresh: false,
        proof_age: Some(Duration::from_secs(20)),
    }
}

fn peers_target() -> WatchTarget {
    WatchTarget {
        namespace: "iam".to_owned(),
        service: "iam-gateway-peers".to_owned(),
    }
}

/// One gateway pod: its freshness, its readiness and the task that compares it with its peers.
struct Pod {
    state: Arc<FreshnessState>,
    gate: Arc<ReadinessGate>,
    peers: Arc<PeerSet>,
    checker: PeerReadinessChecker,
}

/// Pods that share one boot clock and one fake reader of the peers.
struct Fleet {
    reader: Arc<FakePeerFreshnessReader>,
    clock: Arc<FakeBootClock>,
    names: Vec<String>,
    pods: Vec<Pod>,
}

fn endpoint(name: &str, zone: &str) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: name.to_owned(),
        port: 9090,
        zone: Some(Zone::new(zone).unwrap()),
        pod: Some(name.to_owned()),
        conditions: EndpointConditions::healthy(),
    })
}

fn fleet(spec: &[(String, String)], floor: usize) -> Fleet {
    let reader = Arc::new(FakePeerFreshnessReader::new());
    let clock = Arc::new(FakeBootClock::new());
    let rule = FreshnessRule::new(HARD, READY);
    let slices = vec![EndpointSlice {
        name: "slice".to_owned(),
        endpoints: spec
            .iter()
            .map(|(name, zone)| endpoint(name, zone))
            .collect(),
    }];
    let pods = spec
        .iter()
        .map(|(name, _zone)| {
            let directory = EndpointDirectory::new(ZoneSource {
                peers: peers_target(),
                pod: Some(name.clone()),
                explicit: None,
            });
            directory.replace(&peers_target(), slices.clone());
            let peers = Arc::new(PeerSet::new(PeerSetPorts {
                view: directory.view(),
                target: peers_target(),
                pod: Some(name.clone()),
                reader: Arc::<FakePeerFreshnessReader>::clone(&reader),
                rng: Arc::new(FakeRng::seeded(7)),
                rule,
            }));
            let state = Arc::new(FreshnessState::new(
                rule,
                Arc::<FakeBootClock>::clone(&clock),
            ));
            let gate = Arc::new(ReadinessGate::new());
            let checker = PeerReadinessChecker::new(
                Arc::clone(&peers),
                Arc::clone(&state),
                Arc::clone(&gate),
                AzFloor::new(floor),
            );
            Pod {
                state,
                gate,
                peers,
                checker,
            }
        })
        .collect();
    Fleet {
        reader,
        clock,
        names: spec.iter().map(|(name, _zone)| name.clone()).collect(),
        pods,
    }
}

fn spec(pods: &[(&str, &str)]) -> Vec<(String, String)> {
    pods.iter()
        .map(|(name, zone)| ((*name).to_owned(), (*zone).to_owned()))
        .collect()
}

impl Fleet {
    fn pod(&self, name: &str) -> &Pod {
        let index = self.names.iter().position(|pod| pod == name).unwrap();
        &self.pods[index]
    }

    fn prove(&self, name: &str) {
        assert!(self.pod(name).state.attach(
            FreshnessProof {
                taken_at: self.clock.now(),
                watermark: 5,
            },
            version(5),
        ));
    }

    /// Every pod holds a proof; then the clock passes the hard bound, and only `fresh` pods prove
    /// again. The others are stale.
    fn age_all_but(&self, fresh: &[&str]) {
        for name in &self.names {
            self.prove(name);
        }
        self.clock
            .advance(HARD.saturating_add(Duration::from_secs(1)));
        for name in fresh {
            self.prove(name);
        }
    }
}

async fn ok() -> &'static str {
    "ok"
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves the gateway on a free loopback port"
)]
async fn serve_public(
    gate: &ReadinessGate,
) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = watch::channel(false);
    let router = Router::new().route("/", get(ok));
    let signals = ConnectionSignals::new(stopping, Some(gate.shedding()));
    let server = tokio::spawn(async move {
        serve(listener, router, signals).await.unwrap();
    });
    (address, stop, server)
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test connects to its own gateway on loopback"
)]
async fn connect(address: SocketAddr) -> TcpStream {
    TcpStream::connect(address).await.unwrap()
}

fn request() -> Request<Empty<Bytes>> {
    Request::get("/")
        .header("host", "gateway")
        .body(Empty::new())
        .unwrap()
}

/// One request on a new HTTP/1.1 connection; whether the response says `Connection: close`.
async fn closes_after_the_response(address: SocketAddr) -> bool {
    let (mut sender, connection) = http1::handshake(TokioIo::new(connect(address).await))
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap_or_default();
    });
    sender.ready().await.unwrap();
    let response = sender.send_request(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let closes = response
        .headers()
        .get("connection")
        .is_some_and(|value| value == "close");
    response.into_body().collect().await.unwrap();
    closes
}

#[tokio::test]
async fn a_stale_pod_among_fresh_peers_fails_readiness_sheds_its_connections_and_returns_after_three_fresh_verdicts()
 {
    let fleet = fleet(&spec(&SIX), 1);
    fleet.reader.report_all(current());
    fleet.reader.report("gw-a1", stale());
    let pod = fleet.pod("gw-a1");
    let (address, stop, server) = serve_public(&pod.gate).await;
    let (mut sender, connection) =
        http2::handshake(TokioExecutor::new(), TokioIo::new(connect(address).await))
            .await
            .unwrap();
    let goaway = tokio::spawn(async move { connection.await.unwrap_or_default() });
    sender.ready().await.unwrap();
    sender
        .send_request(request())
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    pod.checker.check_once().await;
    assert!(pod.gate.is_ready());
    assert!(!closes_after_the_response(address).await);
    pod.checker.check_once().await;

    assert!(!pod.gate.is_ready());
    timeout(LIMIT, goaway).await.unwrap().unwrap();
    assert!(closes_after_the_response(address).await);

    fleet.prove("gw-a1");
    for _ in 0..2 {
        pod.checker.check_once().await;
    }
    assert!(!pod.gate.is_ready());
    pod.checker.check_once().await;
    assert!(pod.gate.is_ready());
    assert!(!closes_after_the_response(address).await);
    stop.send_replace(true);
    timeout(LIMIT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn of_two_stale_pods_of_a_zone_one_goes_unready_and_the_last_stays_ready_failing_closed() {
    let fleet = fleet(&spec(&SIX), 1);
    fleet.reader.report_all(current());
    fleet.reader.report("gw-a1", stale());
    fleet.reader.report("gw-a2", stale());
    fleet.age_all_but(&["gw-b1", "gw-b2", "gw-c1", "gw-c2"]);

    for _ in 0..3 {
        fleet.pod("gw-a1").checker.check_once().await;
        fleet.pod("gw-a2").checker.check_once().await;
    }

    let kept = fleet.pod("gw-a1");
    let shed = fleet.pod("gw-a2");
    assert!(kept.gate.is_ready());
    assert!(!shed.gate.is_ready());
    assert!(!kept.state.is_fresh(), "its requests get 503 iam_stale");
    let probes = |pod: &Pod| {
        let status = Arc::new(PodStatus::new());
        status.mark_keys_parsed();
        status.mark_config_gates_passed();
        status.mark_bootstrapped();
        let view = FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(version(5))));
        PodProbes::new(status, Arc::clone(&pod.state), Arc::new(view))
            .with_peer_readiness(Arc::clone(&pod.gate))
    };
    assert_eq!(probes(kept).ready(), Ok(()));
    assert_eq!(probes(shed).ready(), Err(NotReady::StaleAgainstPeers));
}

#[tokio::test]
async fn when_every_pod_is_stale_every_pod_stays_ready_and_fails_closed() {
    let fleet = fleet(&spec(&SIX), 1);
    fleet.reader.report_all(stale());
    fleet.age_all_but(&[]);

    for _ in 0..4 {
        for pod in &fleet.pods {
            pod.checker.check_once().await;
        }
    }

    for pod in &fleet.pods {
        assert!(pod.gate.is_ready());
        assert!(!pod.state.is_fresh(), "its requests get 503 iam_stale");
    }
}

fn zone_of(address: &str) -> char {
    address.chars().nth(3).unwrap()
}

#[tokio::test]
async fn a_fleet_of_twelve_peers_is_sampled_to_five_with_three_in_the_own_zone() {
    let names: Vec<(String, String)> = (0..13)
        .map(|index| {
            let zone = ["a", "b", "c"].get(index % 3).copied().unwrap();
            (format!("gw-{zone}{index:02}"), zone.to_owned())
        })
        .collect();
    let fleet = fleet(&names, 1);
    fleet.reader.report_all(current());
    let first = fleet.names.first().unwrap().clone();
    let pod = fleet.pod(&first);

    pod.checker.check_once().await;

    let asked = fleet.reader.asked();
    assert_eq!(asked.len(), 5);
    let own_zone = zone_of(&first);
    assert_eq!(
        asked
            .iter()
            .filter(|address| zone_of(address) == own_zone)
            .count(),
        3
    );
}

#[tokio::test]
async fn with_six_peers_every_peer_is_asked() {
    let names = spec(&[
        ("gw-a1", "a"),
        ("gw-a2", "a"),
        ("gw-b1", "b"),
        ("gw-b2", "b"),
        ("gw-c1", "c"),
        ("gw-c2", "c"),
        ("gw-c3", "c"),
    ]);
    let fleet = fleet(&names, 1);
    fleet.reader.report_all(current());

    fleet.pod("gw-a1").checker.check_once().await;

    let mut asked = fleet.reader.asked();
    asked.sort();
    assert_eq!(
        asked,
        ["gw-a2", "gw-b1", "gw-b2", "gw-c1", "gw-c2", "gw-c3"]
    );
}

#[derive(Debug, Default)]
struct NoSink(Mutex<Vec<FreshnessProof>>);

impl ProofSink for NoSink {
    fn offer(&self, proof: FreshnessProof) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(proof);
    }
}

#[tokio::test]
async fn a_peer_that_reports_a_newer_version_for_more_than_a_second_invalidates_the_proof() {
    let fleet = fleet(&spec(&SIX), 1);
    fleet.reader.report_all(current());
    fleet.reader.report(
        "gw-b1",
        PeerObservation {
            version: Some(version(9)),
            ..current()
        },
    );
    fleet.prove("gw-a1");
    let pod = fleet.pod("gw-a1");
    let prober = FreshnessProber::new(
        ProberPorts {
            probe: Arc::new(FakePolicyLogProbe::scripted(Vec::new())),
            peers: Arc::<PeerSet>::clone(&pod.peers),
            view: Arc::new(FakePolicyView::with_snapshot(Arc::new(EmptySnapshot::at(
                version(5),
            )))),
            clock: Arc::<FakeBootClock>::clone(&fleet.clock),
            sink: Arc::new(NoSink::default()),
            state: Arc::clone(&pod.state),
        },
        ProberSettings {
            probe_interval: Duration::from_millis(500),
        },
    );

    prober.check_peers().await;
    assert!(pod.state.is_fresh());
    fleet.clock.advance(Duration::from_millis(1_100));
    prober.check_peers().await;

    assert!(!pod.state.is_fresh());
}
