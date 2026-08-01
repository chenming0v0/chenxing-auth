// Shared, pure decision logic for the embedded frontend build.
//
// `build.rs` includes this file so the build script and the integration test
// in `tests/build_logic.rs` compile the exact same rules. Keeping the logic
// free of `npm` and filesystem side effects lets us test the stale-bundle
// behaviour without running a real `npm ci` / `npm run build` chain.

/// What the build script should do with the embedded frontend bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildAction {
    /// `web/dist/index.html` does not exist; a full install + build is required.
    BuildMissing,
    /// The bundle is stale and `npm` is available; rebuild it.
    Rebuild,
    /// The bundle is stale but `npm` is unavailable (for example the Docker
    /// builder stage, which only receives a pre-built `web/dist`); keep the
    /// pre-built artifact and surface a warning.
    KeepStaleWithWarning,
    /// The bundle is up to date; nothing to do.
    Skip,
}

/// Decide the build action from the raw signals.
///
/// A pre-existing bundle is never blindly trusted: it must either match the
/// recorded source fingerprint or be at least as new as every build input.
/// Otherwise the bundle is rebuilt when possible, and only kept as a last
/// resort when no toolchain is available to rebuild it.
pub fn decide_build_action(
    dist_index_exists: bool,
    marker_fresh: bool,
    dist_newer_than_sources: bool,
    can_build: bool,
) -> BuildAction {
    if !dist_index_exists {
        return BuildAction::BuildMissing;
    }
    if marker_fresh || dist_newer_than_sources {
        return BuildAction::Skip;
    }
    if can_build {
        BuildAction::Rebuild
    } else {
        BuildAction::KeepStaleWithWarning
    }
}

/// Whether the bundle counts as fresh by mtime: the bundle must be at least
/// as new as the newest source input.
///
/// Ties count as fresh because coarse filesystems (and the Docker builder
/// stage, where sources and the freshly built bundle can share a timestamp)
/// would otherwise report a same-tick build as stale and try to run `npm`
/// where it is not installed.
pub fn fresh_by_mtime(
    dist_index_mtime: std::time::SystemTime,
    newest_input_mtime: std::time::SystemTime,
) -> bool {
    dist_index_mtime >= newest_input_mtime
}

/// Whether `npm ci` must run before `npm run build`.
///
/// A full reinstall is only needed when `node_modules` has no install marker
/// or the lockfile is newer than the last install.
pub fn requires_npm_ci(install_marker_exists: bool, lockfile_newer_than_install: bool) -> bool {
    !install_marker_exists || lockfile_newer_than_install
}

/// Deterministic fingerprint of the frontend inputs. The input list carries
/// `(relative_path, content)` pairs so the function stays pure and testable
/// without touching the filesystem. The leading `v1-` prefix invalidates
/// markers written by older formats, forcing a rebuild instead of trusting a
/// foreign marker.
pub fn source_fingerprint(inputs: &[(&str, &[u8])]) -> String {
    use sha2::{Digest, Sha256};

    // Sort by path so the fingerprint does not depend on the (unspecified)
    // iteration order of directory reads.
    let mut inputs: Vec<&(&str, &[u8])> = inputs.iter().collect();
    inputs.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    for (path, content) in inputs {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update(content);
        hasher.update([1u8]);
    }
    format!("v1-{}", hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn time(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn stale_dist_is_rebuilt_when_toolchain_available() {
        // Regression for the stale-bundle bug: a pre-existing bundle must not
        // short-circuit the build when the sources changed.
        assert_eq!(
            decide_build_action(true, false, false, true),
            BuildAction::Rebuild
        );
    }

    #[test]
    fn stale_dist_is_kept_with_warning_without_toolchain() {
        // Docker copies a pre-built web/dist into a builder stage without
        // npm; in that environment the stale artifact must be kept, not panic.
        assert_eq!(
            decide_build_action(true, false, false, false),
            BuildAction::KeepStaleWithWarning
        );
    }

    #[test]
    fn missing_dist_always_builds() {
        assert_eq!(
            decide_build_action(false, false, false, true),
            BuildAction::BuildMissing
        );
        assert_eq!(
            decide_build_action(false, true, true, false),
            BuildAction::BuildMissing
        );
    }

    #[test]
    fn fresh_marker_or_mtime_skips() {
        assert_eq!(
            decide_build_action(true, true, false, true),
            BuildAction::Skip
        );
        assert_eq!(
            decide_build_action(true, false, true, true),
            BuildAction::Skip
        );
        assert_eq!(
            decide_build_action(true, true, false, false),
            BuildAction::Skip
        );
    }

    #[test]
    fn bundle_as_new_as_sources_counts_as_fresh() {
        assert!(fresh_by_mtime(time(100), time(100)));
        assert!(!fresh_by_mtime(time(99), time(100)));
    }

    #[test]
    fn fingerprint_is_deterministic_and_content_sensitive() {
        let before = source_fingerprint(&[("src/App.tsx", b"hello")]);
        assert_eq!(before, source_fingerprint(&[("src/App.tsx", b"hello")]));
        assert_ne!(before, source_fingerprint(&[("src/App.tsx", b"hello!")]));
        assert_ne!(
            before,
            source_fingerprint(&[("src/App.tsx", b"hello"), ("src/api.ts", b"x")])
        );
    }

    #[test]
    fn fingerprint_is_independent_of_input_order() {
        let first = source_fingerprint(&[("src/App.tsx", b"hello"), ("src/api.ts", b"x")]);
        let second = source_fingerprint(&[("src/api.ts", b"x"), ("src/App.tsx", b"hello")]);
        assert_eq!(first, second);
    }

    #[test]
    fn fingerprint_is_version_prefixed() {
        assert!(source_fingerprint(&[("src/App.tsx", b"hello")]).starts_with("v1-"));
    }

    #[test]
    fn npm_ci_required_only_when_install_is_missing_or_outdated() {
        assert!(requires_npm_ci(false, false));
        assert!(requires_npm_ci(true, true));
        assert!(!requires_npm_ci(true, false));
    }
}
