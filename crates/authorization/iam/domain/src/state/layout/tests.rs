use super::*;
use crate::state::fakes::{HashDigest, TextCodec};

const PORTS: (&dyn StateRecordCodec, &dyn PolicyDigest) = (&TextCodec, &HashDigest);

fn service() -> ServiceName {
    ServiceName::new("user-service").unwrap()
}

fn entry(number: u32) -> CatalogueEntryState {
    CatalogueEntryState {
        key: format!("gql:user-service:Query.f{number:04}"),
        sensitive: false,
        audit_always: false,
    }
}

fn entries(count: u32) -> Vec<CatalogueEntryState> {
    (1..=count).map(entry).collect()
}

/// A chunk limit that fits three entries of the test codec next to the empty chunk.
fn three_entries() -> usize {
    let empty = TextCodec
        .encode(&PolicyState::Chunk(CatalogueChunk {
            service: service(),
            entries: Vec::new(),
        }))
        .unwrap()
        .len();
    TextCodec
        .entry_size(&entry(1))
        .checked_mul(3)
        .and_then(|entries| entries.checked_add(empty))
        .unwrap()
}

fn bounded(epoch: i64, entries: Vec<CatalogueEntryState>) -> CatalogueLayout {
    CatalogueLayout::build_bounded(&service(), epoch, entries, PORTS, three_entries()).unwrap()
}

fn chunk_keys(layout: &CatalogueLayout) -> Vec<StateKey> {
    layout
        .states()
        .iter()
        .skip(1)
        .map(|(key, _state)| key.clone())
        .collect()
}

#[test]
fn a_service_without_entries_has_no_manifest_and_no_chunk() {
    let layout = CatalogueLayout::build(&service(), 3, Vec::new(), PORTS).unwrap();

    assert_eq!(layout.states().len(), 0);
}

#[test]
fn a_small_catalogue_is_one_chunk_and_a_manifest_that_names_it() {
    let layout = CatalogueLayout::build(&service(), 3, entries(2), PORTS).unwrap();

    let [(manifest_key, manifest), (chunk_key, _chunk)] = layout.states() else {
        panic!("expected a manifest and one chunk");
    };
    assert_eq!(manifest_key, &StateKey::CatalogueManifest(service()));
    let PolicyState::Manifest(manifest) = manifest else {
        panic!("expected a manifest");
    };
    assert_eq!(manifest.catalog_epoch, 3);
    assert_eq!(manifest.chunks.len(), 1);
    assert_eq!(
        chunk_key,
        &StateKey::chunk(service(), manifest.chunks[0].clone())
    );
}

#[test]
fn entries_fill_chunks_up_to_the_limit_and_each_one_lands_in_exactly_one_chunk() {
    let layout = bounded(1, entries(7));

    let sizes: Vec<_> = layout
        .states()
        .iter()
        .filter_map(|(_key, state)| match state {
            PolicyState::Chunk(chunk) => Some(chunk.entries.len()),
            PolicyState::Role(_)
            | PolicyState::Subject(_)
            | PolicyState::Manifest(_)
            | PolicyState::Upstream(_)
            | PolicyState::Route(_)
            | PolicyState::RatePolicy(_)
            | PolicyState::SessionRevocation(_)
            | PolicyState::UserRevocation(_)
            | PolicyState::GlobalRevocation(_)
            | PolicyState::Head(_) => None,
        })
        .collect();
    assert_eq!(sizes, [3, 3, 1]);
    let PolicyState::Manifest(manifest) = &layout.states()[0].1 else {
        panic!("expected a manifest");
    };
    assert_eq!(manifest.chunks.len(), 3);
}

#[test]
fn the_entries_are_laid_out_in_key_order_whatever_the_order_given() {
    let mut reversed = entries(5);
    reversed.reverse();

    assert_eq!(bounded(1, entries(5)), bounded(1, reversed));
}

#[test]
fn a_chunk_whose_entries_do_not_change_keeps_its_key_in_the_next_activation() {
    let first = bounded(1, entries(6));
    let mut changed = entries(6);
    changed.push(entry(9));

    let second = bounded(2, changed);

    let before = chunk_keys(&first);
    let after = chunk_keys(&second);
    assert_eq!(before.len(), 2);
    assert_eq!(after.len(), 3);
    assert_eq!(before, after[..2]);
    assert_ne!(first.states()[0], second.states()[0]);
}

#[test]
fn a_change_in_one_chunk_leaves_the_other_chunks_unchanged() {
    let first = bounded(1, entries(6));
    let mut changed = entries(6);
    if let Some(last) = changed.last_mut() {
        last.sensitive = true;
    }

    let second = bounded(1, changed);

    let before = chunk_keys(&first);
    let after = chunk_keys(&second);
    assert_eq!(before[0], after[0]);
    assert_ne!(before[1], after[1]);
}

#[test]
fn an_entry_larger_than_a_chunk_is_refused() {
    let result = CatalogueLayout::build_bounded(&service(), 1, entries(1), PORTS, 10);

    assert_eq!(result, Err(InvalidStateRecord::EntryTooLarge));
}

#[test]
fn the_test_codec_names_the_manifest_and_decodes_nothing() {
    let layout = bounded(1, entries(4));
    let PolicyState::Manifest(manifest) = &layout.states()[0].1 else {
        panic!("the first state is the manifest");
    };

    let text = TextCodec
        .encode(&PolicyState::Manifest(manifest.clone()))
        .unwrap();

    assert!(text.starts_with("manifest 1 "), "{text}");
    assert!(matches!(
        TextCodec.decode(&StateKey::Head, &text),
        Err(InvalidStateRecord::Encoding)
    ));
}
