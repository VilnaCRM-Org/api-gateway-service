use iam_domain::StateKey;

use super::*;

#[test]
fn a_key_always_lands_in_the_same_shard_inside_the_range() {
    let key = StateKey::parse("route/0192f6a0-0000-7000-8000-000000000001").unwrap();

    assert_eq!(shard_of(&key), shard_of(&key));
    assert!(shard_of(&key) < SHARD_COUNT);
    assert!(shard_of(&StateKey::Head) < SHARD_COUNT);
}

#[test]
fn keys_spread_over_many_shards() {
    let shards: std::collections::BTreeSet<_> = (0..512_u32)
        .filter_map(|number| {
            StateKey::parse(&format!("upstream/service-{number}"))
                .ok()
                .map(|key| shard_of(&key))
        })
        .collect();

    assert!(shards.len() > 256, "only {} shards used", shards.len());
}
