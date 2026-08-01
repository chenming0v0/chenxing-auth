//! Unit tests for the shared frontend-build decision logic.
//!
//! `build_logic.rs` is pulled into `build.rs` with `include!` and into this
//! test crate with `#[path]`, so `cargo test` exercises the exact same pure
//! rules that the build script runs, without a real `npm ci` / `npm run build`
//! chain.

#[path = "../build_logic.rs"]
mod logic;

#[test]
fn source_edit_with_stale_dist_never_keeps_the_old_bundle() {
    use logic::BuildAction;

    // A pre-existing `web/dist` used to short-circuit build.rs unconditionally.
    // With stale markers and mtimes it must be rebuilt whenever possible.
    assert_eq!(
        logic::decide_build_action(true, false, false, true),
        BuildAction::Rebuild
    );
}

#[test]
fn docker_prebuilt_dist_is_not_rebuilt_without_npm() {
    use logic::BuildAction;

    // The Docker builder stage receives a freshly built web/dist but has no
    // npm; the build script must keep the artifact instead of panicking.
    assert_eq!(
        logic::decide_build_action(true, false, false, false),
        BuildAction::KeepStaleWithWarning
    );
}
