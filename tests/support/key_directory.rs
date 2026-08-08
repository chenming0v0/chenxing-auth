#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
use uuid::Uuid;

static TEMPLATE: OnceLock<PathBuf> = OnceLock::new();

/// Build the expensive RSA material once per test binary, then give each test
/// its own writable copy so rotation and cleanup remain isolated.
pub fn isolated_key_directory(label: &str) -> PathBuf {
    let template = TEMPLATE.get_or_init(|| {
        let path =
            std::env::temp_dir().join(format!("chenxing-key-template-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        chenxing_auth::keys::KeyManager::load_or_generate(&path).expect("test signing keys");
        chenxing_auth::oauth::providers::secrets::SecretManager::load_or_generate(&path)
            .expect("test provider secret");
        path
    });
    let destination = std::env::temp_dir().join(format!("chenxing-{label}-{}", Uuid::new_v4()));
    copy_files(template, &destination).expect("copy test key material");
    destination
}

fn copy_files(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_file() {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}
