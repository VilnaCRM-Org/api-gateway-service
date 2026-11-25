use rstest::rstest;

use super::{InvalidValkeyUrl, ValkeyEndpoint};

#[rstest]
#[case("redis://valkey:6379")]
#[case("redis://127.0.0.1:6379/0")]
#[case("redis://user:secret@valkey:6379")]
fn a_redis_url_names_one_server(#[case] url: &str) {
    assert_eq!(
        ValkeyEndpoint::parse(url).unwrap(),
        ValkeyEndpoint::Direct(url.to_owned())
    );
}

#[rstest]
#[case("")]
#[case("valkey:6379")]
#[case("http://valkey:6379")]
#[case("rediss://valkey:6379")]
#[case("unix:///tmp/valkey.sock")]
fn another_scheme_is_refused(#[case] url: &str) {
    assert_eq!(ValkeyEndpoint::parse(url), Err(InvalidValkeyUrl::Scheme));
}

#[test]
fn a_redis_url_the_client_cannot_read_is_refused() {
    assert_eq!(
        ValkeyEndpoint::parse("redis://valkey:notaport"),
        Err(InvalidValkeyUrl::Server)
    );
}

#[test]
fn a_sentinel_url_names_its_nodes_and_the_monitored_service() {
    let endpoint = ValkeyEndpoint::parse("redis+sentinel://s1:26380,s2/mymaster").unwrap();

    assert_eq!(
        endpoint,
        ValkeyEndpoint::Sentinel {
            nodes: vec!["redis://s1:26380".to_owned(), "redis://s2:26379".to_owned()],
            service: "mymaster".to_owned(),
        }
    );
}

#[rstest]
#[case("redis+sentinel://s1:26379")]
#[case("redis+sentinel://s1:26379/")]
#[case("redis+sentinel://s1:26379/mymaster/0")]
fn a_sentinel_url_needs_exactly_one_service_name(#[case] url: &str) {
    assert_eq!(
        ValkeyEndpoint::parse(url),
        Err(InvalidValkeyUrl::SentinelService)
    );
}

#[rstest]
#[case("redis+sentinel:///mymaster")]
#[case("redis+sentinel://s1:26379,/mymaster")]
#[case("redis+sentinel://s1:port/mymaster")]
#[case("redis+sentinel://user@s1:26379/mymaster")]
fn a_sentinel_node_needs_a_host_and_a_valid_port(#[case] url: &str) {
    assert_eq!(
        ValkeyEndpoint::parse(url),
        Err(InvalidValkeyUrl::SentinelNodes)
    );
}

#[tokio::test]
async fn a_sentinel_group_that_nobody_answers_is_a_connection_error() {
    let endpoint = ValkeyEndpoint::parse("redis+sentinel://127.0.0.1:1/mymaster").unwrap();

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.connect())
        .await
        .unwrap();

    assert!(outcome.is_err());
}

#[tokio::test]
async fn a_server_url_the_client_cannot_read_is_a_connection_error() {
    let endpoint = ValkeyEndpoint::Direct("not a url".to_owned());

    assert!(endpoint.connect().await.is_err());
}

#[tokio::test]
async fn a_sentinel_node_the_client_cannot_read_is_a_connection_error() {
    let endpoint = ValkeyEndpoint::Sentinel {
        nodes: vec!["not a url".to_owned()],
        service: "mymaster".to_owned(),
    };

    assert!(endpoint.connect().await.is_err());
}
