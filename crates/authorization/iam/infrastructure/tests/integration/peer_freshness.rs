//! `HyperPeerFreshnessClient` against a fake peer pod: it reads the report of
//! `GET /internal/freshness`, and a peer that fails, answers another status or sends something
//! else reads as no answer (FR-85).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use iam_domain::{
    EndpointConditions, EndpointParts, PeerFreshnessReader as _, PolicyVersion, UpstreamEndpoint,
};
use iam_infrastructure::HyperPeerFreshnessClient;
use tokio::net::TcpListener;

/// The paths a fake peer was asked for.
type Paths = Arc<Mutex<Vec<String>>>;

/// A fake peer on a free loopback port that answers every request with `status` and `body`.
#[expect(
    clippy::disallowed_methods,
    reason = "an integration test serves the fake peer on a free loopback port"
)]
async fn fake_peer(status: u16, body: &'static str) -> (SocketAddr, Paths) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let paths = Paths::default();
    let seen = Arc::clone(&paths);
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                seen.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(request.uri().path().to_owned());
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from_static(body.as_bytes())))
                            .unwrap(),
                    )
                }
            });
            tokio::spawn(http1::Builder::new().serve_connection(TokioIo::new(stream), service));
        }
    });
    (address, paths)
}

fn endpoint(address: SocketAddr) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.ip().to_string(),
        port: address.port(),
        zone: None,
        pod: Some("gateway-1".to_owned()),
        conditions: EndpointConditions::healthy(),
    })
}

#[tokio::test]
async fn the_report_of_a_peer_is_read_from_its_freshness_endpoint() {
    let (address, paths) = fake_peer(
        200,
        r#"{"version":7,"digest":"ab","proofAgeMs":120,"hardBoundMs":15000,"fresh":true}"#,
    )
    .await;

    let observation = HyperPeerFreshnessClient::new()
        .read(&endpoint(address))
        .await
        .unwrap();

    assert_eq!(observation.version, Some(PolicyVersion::new(7).unwrap()));
    assert!(observation.fresh);
    assert_eq!(observation.proof_age, Some(Duration::from_millis(120)));
    assert_eq!(
        *paths.lock().unwrap_or_else(PoisonError::into_inner),
        ["/internal/freshness"]
    );
}

#[tokio::test]
async fn a_peer_that_answers_another_status_reads_as_no_answer() {
    let (address, _paths) = fake_peer(503, r#"{"version":7,"fresh":true}"#).await;

    assert_eq!(
        HyperPeerFreshnessClient::new()
            .read(&endpoint(address))
            .await,
        None
    );
}

#[tokio::test]
async fn a_peer_that_sends_something_else_reads_as_no_answer() {
    let (address, _paths) = fake_peer(200, "not a report").await;

    assert_eq!(
        HyperPeerFreshnessClient::new()
            .read(&endpoint(address))
            .await,
        None
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "an integration test reserves a free loopback port and releases it"
)]
async fn unused_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn a_peer_that_refuses_the_connection_reads_as_no_answer() {
    let address = unused_address().await;

    assert_eq!(
        HyperPeerFreshnessClient::new()
            .read(&endpoint(address))
            .await,
        None
    );
}
