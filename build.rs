use std::{env, path::Path, process::Command};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest directory");
    let web_dir = Path::new(&manifest_dir).join("web");
    let dist_entry = web_dir.join("dist/index.html");

    println!("cargo:rerun-if-changed=web/package.json");
    println!("cargo:rerun-if-changed=web/package-lock.json");
    println!("cargo:rerun-if-changed=web/src");

    if dist_entry.exists() {
        return;
    }

    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    run(npm, &["ci", "--prefix", "web"], &manifest_dir);
    run(npm, &["run", "build", "--prefix", "web"], &manifest_dir);

    if !dist_entry.exists() {
        panic!("web build completed without producing web/dist/index.html");
    }
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
