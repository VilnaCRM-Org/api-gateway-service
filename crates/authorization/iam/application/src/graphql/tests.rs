use super::{IamMutation, IamQuery};

fn default_of<T: Default>() -> T {
    T::default()
}

#[test]
fn the_roots_are_default_and_debug_like_every_root_the_schema_merges() {
    assert_eq!(format!("{:?}", default_of::<IamQuery>()), "IamQuery");
    assert_eq!(format!("{:?}", default_of::<IamMutation>()), "IamMutation");
}
