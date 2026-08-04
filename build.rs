use std::{env, fs, path::Path, process::Command, time::SystemTime};

include!("build_logic.rs");

/// Frontend input files (relative to `web/`, outside `web/src` and
/// `web/public`) that influence the built bundle.
const INPUT_FILES: &[&str] = &[
    "index.html",
    "package.json",
    "package-lock.json",
    "vite.config.ts",
    "tsconfig.json",
];

/// Marker file written next to the bundle after a successful local build. It
/// records the fingerprint of the inputs that produced the bundle.
const FINGERPRINT_FILE: &str = ".build-fingerprint";

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
    let web_dir = Path::new(&manifest_dir).join("web");
    let dist_dir = web_dir.join("dist");
    let dist_entry = dist_dir.join("index.html");

    println!("cargo:rerun-if-changed=web/package.json");
    println!("cargo:rerun-if-changed=web/package-lock.json");
    println!("cargo:rerun-if-changed=web/src");
    println!("cargo:rerun-if-changed=web/index.html");
    println!("cargo:rerun-if-changed=web/vite.config.ts");
    println!("cargo:rerun-if-changed=web/tsconfig.json");
    // build.rs is rerun automatically, but Cargo does not track files pulled
    // in via include!().
    println!("cargo:rerun-if-changed=build_logic.rs");

    // CI can hand us a freshly built web/dist artifact while still checking out
    // the full frontend sources. Honour an explicit prebuilt marker so the
    // matrix jobs never re-enter npm just because artifact mtimes look stale.
    if env::var_os("CHENXING_USE_PREBUILT_WEB").is_some() {
        if dist_entry.exists() {
            println!("cargo:rerun-if-env-changed=CHENXING_USE_PREBUILT_WEB");
            println!(
                "cargo:warning=CHENXING_USE_PREBUILT_WEB set; embedding the provided web/dist"
            );
            return;
        }
        panic!("CHENXING_USE_PREBUILT_WEB is set but web/dist/index.html is missing");
    }

    // Docker's local source builder may only receive a pre-built web/dist and
    // not the frontend sources or npm. Embed the artifact as-is in that case.
    if !frontend_sources_present(&web_dir) {
        if dist_entry.exists() {
            println!(
                "cargo:warning=frontend sources not present; embedding the pre-built web/dist"
            );
            return;
        }
        panic!(
            "web/dist/index.html is missing and frontend sources are unavailable; \
             cannot embed the web console"
        );
    }

    let inputs = frontend_inputs(&web_dir);
    let input_refs: Vec<(&str, &[u8])> = inputs
        .entries
        .iter()
        .map(|(path, content)| (path.as_str(), content.as_slice()))
        .collect();
    let fingerprint = source_fingerprint(&input_refs);

    let marker_fresh = read_fingerprint(&dist_dir).is_some_and(|recorded| recorded == fingerprint);
    let dist_newer_than_sources = dist_entry
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok())
        .is_some_and(|dist_mtime| fresh_by_mtime(dist_mtime, inputs.newest_mtime));

    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };

    match decide_build_action(
        dist_entry.exists(),
        marker_fresh,
        dist_newer_than_sources,
        npm_available(npm),
    ) {
        BuildAction::BuildMissing => {
            run(npm, &["ci", "--prefix", "web"], &manifest_dir);
            run(npm, &["run", "build", "--prefix", "web"], &manifest_dir);
            write_fingerprint(&dist_dir, &fingerprint);
        }
        BuildAction::Rebuild => {
            let install_marker = web_dir.join("node_modules/.package-lock.json");
            let lockfile_newer_than_install = package_lock_newer_than(&web_dir, &install_marker);
            if requires_npm_ci(install_marker.exists(), lockfile_newer_than_install) {
                run(npm, &["ci", "--prefix", "web"], &manifest_dir);
            }
            run(npm, &["run", "build", "--prefix", "web"], &manifest_dir);
            write_fingerprint(&dist_dir, &fingerprint);
        }
        BuildAction::KeepStaleWithWarning => {
            println!(
                "cargo:warning=web/dist is stale or unverified and npm is unavailable; \
                 embedding the pre-built bundle as-is"
            );
        }
        BuildAction::Skip => {}
    }

    if !dist_entry.exists() {
        panic!("web build completed without producing web/dist/index.html");
    }
}

/// Collected frontend build inputs: `(relative_path, content)` pairs plus the
/// newest modification time across all of them.
struct FrontendInputs {
    entries: Vec<(String, Vec<u8>)>,
    newest_mtime: SystemTime,
}

impl FrontendInputs {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            newest_mtime: SystemTime::UNIX_EPOCH,
        }
    }

    fn push(&mut self, relative: String, content: Vec<u8>, mtime: SystemTime) {
        if mtime > self.newest_mtime {
            self.newest_mtime = mtime;
        }
        self.entries.push((relative, content));
    }
}

/// Whether the explicit frontend config inputs exist. Used to detect the
/// Docker builder stage, which only mounts a pre-built `web/dist`.
fn frontend_sources_present(web_dir: &Path) -> bool {
    INPUT_FILES
        .iter()
        .all(|relative| web_dir.join(relative).is_file())
}

/// Collect the files that determine the bundle: the explicit config files plus
/// everything under `web/src` and, when present, `web/public`.
fn frontend_inputs(web_dir: &Path) -> FrontendInputs {
    let mut inputs = FrontendInputs::new();

    for relative in INPUT_FILES {
        let path = web_dir.join(relative);
        let meta = fs::metadata(&path).unwrap_or_else(|error| {
            panic!("cannot stat frontend input {relative}: {error}");
        });
        let content = fs::read(&path).unwrap_or_else(|error| {
            panic!("cannot read frontend input {relative}: {error}");
        });
        let mtime = meta.modified().unwrap_or_else(|error| {
            panic!("cannot read mtime of frontend input {relative}: {error}");
        });
        inputs.push((*relative).to_string(), content, mtime);
    }

    for (relative_dir, prefix) in [("src", "web/src"), ("public", "web/public")] {
        let dir = web_dir.join(relative_dir);
        if dir.is_dir() {
            collect_dir(&dir, prefix, &mut inputs);
        }
    }

    inputs
}

fn collect_dir(dir: &Path, prefix: &str, inputs: &mut FrontendInputs) {
    for entry in fs::read_dir(dir).unwrap_or_else(|error| {
        panic!("cannot list frontend input directory {prefix}: {error}");
    }) {
        let entry = entry.unwrap_or_else(|error| {
            panic!("cannot read entry in frontend input directory {prefix}: {error}");
        });
        let path = entry.path();
        let relative = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        if path.is_dir() {
            collect_dir(&path, &relative, inputs);
        } else {
            let meta = fs::metadata(&path).unwrap_or_else(|error| {
                panic!("cannot stat frontend input {relative}: {error}");
            });
            let content = fs::read(&path).unwrap_or_else(|error| {
                panic!("cannot read frontend input {relative}: {error}");
            });
            let mtime = meta.modified().unwrap_or_else(|error| {
                panic!("cannot read mtime of frontend input {relative}: {error}");
            });
            inputs.push(relative, content, mtime);
        }
    }
}

fn read_fingerprint(dist_dir: &Path) -> Option<String> {
    let content = fs::read_to_string(dist_dir.join(FINGERPRINT_FILE)).ok()?;
    Some(content.trim().to_string())
}

fn write_fingerprint(dist_dir: &Path, fingerprint: &str) {
    fs::create_dir_all(dist_dir).expect("failed to create web/dist");
    fs::write(dist_dir.join(FINGERPRINT_FILE), format!("{fingerprint}\n"))
        .expect("failed to write web/dist/.build-fingerprint");
}

/// Whether `web/package-lock.json` is newer than the last `npm ci`/install,
/// which npm records in `node_modules/.package-lock.json`.
fn package_lock_newer_than(web_dir: &Path, install_marker: &Path) -> bool {
    let lock_mtime = web_dir
        .join("package-lock.json")
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok());
    let install_mtime = install_marker
        .metadata()
        .ok()
        .and_then(|meta| meta.modified().ok());
    matches!((lock_mtime, install_mtime), (Some(lock), Some(install)) if lock > install)
}

fn npm_available(npm: &str) -> bool {
    Command::new(npm)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(program: &str, args: &[&str], cwd: &str) {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|error| panic!("failed to run {program}: {error}"));
    if !status.success() {
        panic!("{program} {args:?} failed with status {status}");
    }
}
