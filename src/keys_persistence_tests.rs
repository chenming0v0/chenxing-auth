//! 单元测试：持久化加载的状态机分支。
//!
//! 核心安全断言是 fail-closed：`active-rs256.kid` 存在但它指向的私钥材料不在盘上时，
//! 加载必须失败，并且不得覆盖 kid、不得生成替代密钥。静默生成替代密钥会一次性作废
//! 所有已签发令牌、把 JWKS 换成全新公钥，还会抹掉唯一能指认材料丢失的证据。

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use time::OffsetDateTime;

use super::{
    ACTIVE_KEY_ID_FILE, KEY_FILE_PREFIX, KEY_FILE_SUFFIX, KeyManagerError, KeyMaterial,
    LEGACY_KEY_FILE, key_file_name, load_materials,
};

const RETENTION: Duration = Duration::from_secs(3600);

type LoadResult = Result<(String, BTreeMap<String, KeyMaterial>), KeyManagerError>;

/// 独占临时密钥目录，drop 时清理，避免测试之间看到对方的密钥文件。
struct TempKeyDir(PathBuf);

impl TempKeyDir {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        Self(std::env::temp_dir().join(format!("chenxing-keys-{name}-{unique}")))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn active_key_id_file(&self) -> PathBuf {
        self.0.join(ACTIVE_KEY_ID_FILE)
    }

    fn legacy_key_file(&self) -> PathBuf {
        self.0.join(LEGACY_KEY_FILE)
    }
}

impl Drop for TempKeyDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 保留窗口用真实时间：所有夹具文件都是刚写入的，稳定落在 `RETENTION` 之内。
/// 无跨实例时钟偏差（单实例测试语义），容忍值取 0。
fn load(directory: &TempKeyDir, generate_if_empty: bool) -> LoadResult {
    load_materials(
        directory.path(),
        RETENTION,
        Duration::ZERO,
        OffsetDateTime::now_utc(),
        generate_if_empty,
    )
}

fn write_key_file(directory: &TempKeyDir, key_id: &str, contents: &[u8]) {
    fs::create_dir_all(directory.path()).expect("key directory");
    fs::write(directory.path().join(key_file_name(key_id)), contents).expect("key material");
}

fn write_legacy_key_file(directory: &TempKeyDir, contents: &[u8]) {
    fs::create_dir_all(directory.path()).expect("key directory");
    fs::write(directory.legacy_key_file(), contents).expect("legacy key material");
}

fn write_active_key_id(directory: &TempKeyDir, key_id: &str) {
    fs::create_dir_all(directory.path()).expect("key directory");
    fs::write(directory.active_key_id_file(), key_id).expect("active key id");
}

fn read_active_key_id(directory: &TempKeyDir) -> String {
    fs::read_to_string(directory.active_key_id_file()).expect("active key id file")
}

/// 让"最新密钥"判断可复现：mtime 是创建时间的唯一来源。
fn age_key_file(directory: &TempKeyDir, key_id: &str, seconds: u64) {
    let path = directory.path().join(key_file_name(key_id));
    let file = fs::File::options()
        .write(true)
        .open(&path)
        .expect("open key file");
    file.set_modified(SystemTime::now() - Duration::from_secs(seconds))
        .expect("set key file mtime");
}

fn persisted_key_ids(directory: &TempKeyDir) -> Vec<String> {
    let mut key_ids = Vec::new();
    for entry in fs::read_dir(directory.path()).expect("key directory") {
        let file_name = entry.expect("directory entry").file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if let Some(key_id) = file_name
            .strip_prefix(KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(KEY_FILE_SUFFIX))
        {
            key_ids.push(key_id.to_owned());
        }
    }
    key_ids.sort();
    key_ids
}

fn der_of(materials: &BTreeMap<String, KeyMaterial>, key_id: &str) -> Option<Vec<u8>> {
    materials.get(key_id).map(|material| material.der.to_vec())
}

#[test]
fn truly_empty_directory_initializes_the_first_key() {
    let directory = TempKeyDir::new("empty-init");

    let (active_key_id, materials) = load(&directory, true).expect("first initialization");

    assert!(
        materials.contains_key(&active_key_id),
        "returned snapshot must contain the active material"
    );
    assert_eq!(read_active_key_id(&directory), active_key_id);
    assert_eq!(persisted_key_ids(&directory), vec![active_key_id]);
}

#[test]
fn empty_directory_is_not_initialized_when_generation_is_disabled() {
    // 刷新路径（refresh_from_disk / revoke）不允许凭空造密钥。
    let directory = TempKeyDir::new("empty-no-generate");

    let error = load(&directory, false).expect_err("refresh must not initialize keys");

    assert!(matches!(error, KeyManagerError::MissingActiveKeyMaterial));
    assert!(
        !directory.active_key_id_file().exists(),
        "failed load must not write an active key id"
    );
    assert!(persisted_key_ids(&directory).is_empty());
}

#[test]
fn active_key_id_without_any_material_fails_closed() {
    // Issue #264：kid 残留而私钥材料全丢时，旧行为是静默生成新密钥并覆盖 kid。
    let directory = TempKeyDir::new("kid-without-material");
    write_active_key_id(&directory, "cx-lost");

    let error = load(&directory, true).expect_err("missing active key material must fail closed");

    assert!(matches!(error, KeyManagerError::MissingActiveKeyMaterial));
    assert_eq!(
        read_active_key_id(&directory),
        "cx-lost",
        "the active key id is the only evidence of the lost material; it must survive"
    );
    assert!(
        persisted_key_ids(&directory).is_empty(),
        "no replacement key may be generated"
    );
}

#[test]
fn active_key_id_pointing_at_missing_material_fails_even_with_other_keys() {
    // 只丢了 active 材料、其他材料还在时同样失败：静默切到别的 key 会让 active kid
    // 与运维记录不一致，并掩盖材料丢失。
    let directory = TempKeyDir::new("kid-points-elsewhere");
    write_key_file(&directory, "cx-survivor", b"survivor-material");
    write_active_key_id(&directory, "cx-lost");

    let error = load(&directory, true).expect_err("stale active key id must fail closed");

    assert!(matches!(error, KeyManagerError::MissingActiveKeyMaterial));
    assert_eq!(read_active_key_id(&directory), "cx-lost");
    assert_eq!(
        persisted_key_ids(&directory),
        vec!["cx-survivor".to_owned()],
        "surviving material must not be replaced or removed"
    );
}

#[test]
fn active_key_id_with_its_material_loads_unchanged() {
    let directory = TempKeyDir::new("healthy");
    write_key_file(&directory, "cx-active", b"active-material");
    write_active_key_id(&directory, "cx-active");

    let (active_key_id, materials) = load(&directory, false).expect("healthy directory must load");

    assert_eq!(active_key_id, "cx-active");
    assert_eq!(
        der_of(&materials, "cx-active"),
        Some(b"active-material".to_vec())
    );
    assert_eq!(read_active_key_id(&directory), "cx-active");
}

#[test]
fn missing_active_key_id_file_adopts_the_newest_material() {
    // 反向情况：材料在盘上、只丢了 kid 文件。可以从材料自身恢复，不作废任何令牌。
    let directory = TempKeyDir::new("missing-kid-file");
    write_key_file(&directory, "cx-older", b"older-material");
    write_key_file(&directory, "cx-newer", b"newer-material");
    age_key_file(&directory, "cx-older", 600);
    age_key_file(&directory, "cx-newer", 1);

    let (active_key_id, materials) = load(&directory, false).expect("recover the active key id");

    assert_eq!(active_key_id, "cx-newer");
    assert_eq!(read_active_key_id(&directory), "cx-newer");
    assert!(
        materials.contains_key("cx-older"),
        "older material stays published for verification"
    );
}

#[test]
fn legacy_key_is_migrated_under_the_declared_active_key_id() {
    let directory = TempKeyDir::new("legacy-declared");
    write_legacy_key_file(&directory, b"legacy-material");
    write_active_key_id(&directory, "cx-legacy");

    // generate_if_empty=false：迁移不依赖生成许可，它补齐的是已声明 kid 的材料。
    let (active_key_id, materials) = load(&directory, false).expect("legacy migration");

    assert_eq!(active_key_id, "cx-legacy");
    assert_eq!(
        der_of(&materials, "cx-legacy"),
        Some(b"legacy-material".to_vec())
    );
    assert_eq!(read_active_key_id(&directory), "cx-legacy");
    assert_eq!(persisted_key_ids(&directory), vec!["cx-legacy".to_owned()]);
    assert!(
        !directory.legacy_key_file().exists(),
        "legacy file must be removed after migration"
    );
}

#[test]
fn legacy_key_without_active_key_id_gets_a_generated_key_id() {
    let directory = TempKeyDir::new("legacy-orphan");
    write_legacy_key_file(&directory, b"legacy-material");

    let (active_key_id, materials) = load(&directory, false).expect("legacy migration");

    assert!(active_key_id.starts_with("cx-"), "{active_key_id}");
    assert_eq!(
        der_of(&materials, &active_key_id),
        Some(b"legacy-material".to_vec())
    );
    assert_eq!(read_active_key_id(&directory), active_key_id);
    assert!(!directory.legacy_key_file().exists());
}
