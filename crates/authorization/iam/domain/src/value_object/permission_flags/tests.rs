use super::PermissionFlags;

#[test]
fn no_flags_are_set_by_default() {
    let flags = PermissionFlags::NONE;

    assert!(!flags.is_sensitive());
    assert!(!flags.is_audit_always());
    assert_eq!(flags, PermissionFlags::default());
}

#[test]
fn each_flag_is_set_on_its_own() {
    let sensitive = PermissionFlags::NONE.with_sensitive();
    let audited = PermissionFlags::NONE.with_audit_always();

    assert!(sensitive.is_sensitive());
    assert!(!sensitive.is_audit_always());
    assert!(audited.is_audit_always());
    assert!(!audited.is_sensitive());
}

#[test]
fn the_most_restrictive_value_keeps_every_flag_that_either_side_sets() {
    let sensitive = PermissionFlags::NONE.with_sensitive();
    let audited = PermissionFlags::NONE.with_audit_always();
    let both = sensitive.most_restrictive(audited);

    assert!(both.is_sensitive());
    assert!(both.is_audit_always());
    assert_eq!(
        PermissionFlags::NONE.most_restrictive(PermissionFlags::NONE),
        PermissionFlags::NONE
    );
    assert_eq!(sensitive.most_restrictive(PermissionFlags::NONE), sensitive);
    assert_eq!(PermissionFlags::NONE.most_restrictive(audited), audited);
}
