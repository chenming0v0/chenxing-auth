//! 单元测试：吊销意图记录的崩溃恢复（Issue #284）。
//!
//! 覆盖的核心事实是"已提交的吊销不会复活"：无论崩溃发生在改写 active kid 之前
//! 还是之后，加载都必须收敛到"被吊销的材料不在盘上、active kid 指向替代密钥"。
//! 同时不能把恢复做成盲目回放：记录残留而 active kid 已经前进（吊销完成后又发生
//! 轮换）时，恢复不得把 active 退回更旧的 kid。

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use time::OffsetDateTime;

use super::{
    KeyManagerError, PENDING_REVOCATION_FILE, PendingRevocation,
    persistence::{ACTIVE_KEY_ID_FILE, key_file_name, load_materials},
    record,
};

const RETENTION: Duration = Duration::from_secs(3600);

/// 独占临时密钥目录，drop 时清理。
struct TempKeyDir(PathBuf);

impl TempKeyDir {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let path = std::env::temp_dir().join(format!("chenxing-journal-{name}-{unique}"));
        fs::create_dir_all(&path).expect("key directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn record_path(&self) -> PathBuf {
        self.0.join(PENDING_REVOCATION_FILE)
    }

    fn active_key_id_path(&self) -> PathBuf {
        self.0.join(ACTIVE_KEY_ID_FILE)
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.0.join(key_file_name(key_id))
    }
}

impl Drop for TempKeyDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 保留窗口用真实时间：夹具文件都是刚写入的，稳定落在 `RETENTION` 之内。
fn load(directory: &TempKeyDir) -> Result<String, KeyManagerError> {
    load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .map(|(active_key_id, _)| active_key_id)
}

fn write_key(directory: &TempKeyDir, key_id: &str) {
    fs::write(directory.key_path(key_id), format!("material-{key_id}")).expect("key material");
}

fn write_active_key_id(directory: &TempKeyDir, key_id: &str) {
    fs::write(directory.active_key_id_path(), key_id).expect("active key id");
}

fn read_active_key_id(directory: &TempKeyDir) -> String {
    fs::read_to_string(directory.active_key_id_path()).expect("active key id file")
}

fn write_record(directory: &TempKeyDir, revoked_key_id: &str, active_key_id: &str) {
    record(
        directory.path(),
        &PendingRevocation::new(revoked_key_id.to_owned(), active_key_id.to_owned()),
    )
    .expect("pending revocation record");
}

/// 崩溃在"记录已落盘、active kid 还没改写"之间。
#[test]
fn recovery_completes_a_revocation_interrupted_before_the_active_key_switch() {
    let directory = TempKeyDir::new("before-switch");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-replacement");
    write_active_key_id(&directory, "cx-revoked");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("load must complete the pending revocation");

    assert_eq!(active_key_id, "cx-replacement");
    assert_eq!(read_active_key_id(&directory), "cx-replacement");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists(), "记录做完后必须清除");
}

/// 崩溃在"active kid 已改写、旧材料还没删"之间——正是 Issue #284 的复活窗口。
#[test]
fn recovery_removes_material_left_by_a_revocation_interrupted_after_the_switch() {
    let directory = TempKeyDir::new("after-switch");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-replacement");
    write_active_key_id(&directory, "cx-replacement");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("load must complete the pending revocation");

    assert_eq!(active_key_id, "cx-replacement");
    assert!(
        !materials.contains_key("cx-revoked"),
        "被吊销的密钥不得复活进 JWKS"
    );
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// 吊销非 active key 时记录里的 active 就是当前 active，恢复只删材料。
#[test]
fn recovery_of_a_non_active_revocation_keeps_the_active_key_id() {
    let directory = TempKeyDir::new("non-active");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-active");
    write_active_key_id(&directory, "cx-active");
    write_record(&directory, "cx-revoked", "cx-active");

    let active_key_id = load(&directory).expect("load must complete the pending revocation");

    assert_eq!(active_key_id, "cx-active");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// 记录残留而 active kid 已经前进：恢复不得把 active 退回记录里的旧 kid。
#[test]
fn recovery_never_rolls_the_active_key_back_to_a_stale_record() {
    let directory = TempKeyDir::new("stale-record");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-replacement");
    write_key(&directory, "cx-rotated");
    write_active_key_id(&directory, "cx-rotated");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("stale record must not break the load");

    assert_eq!(
        active_key_id, "cx-rotated",
        "轮换后的 active key 不得被记录回退"
    );
    assert_eq!(read_active_key_id(&directory), "cx-rotated");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(directory.key_path("cx-replacement").exists());
}

/// 记录已被完整执行、只差清除时再跑一次：必须幂等，而不是报"材料不存在"。
#[test]
fn recovery_is_idempotent_when_only_the_record_is_left() {
    let directory = TempKeyDir::new("idempotent");
    write_key(&directory, "cx-replacement");
    write_active_key_id(&directory, "cx-replacement");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("already-applied record must load cleanly");

    assert_eq!(active_key_id, "cx-replacement");
    assert!(!directory.record_path().exists());
}

/// 记录指向的替代材料不在盘上：改写 kid 会造出 fail-closed 目录，必须先拒绝。
#[test]
fn recovery_fails_closed_when_the_replacement_material_is_missing() {
    let directory = TempKeyDir::new("missing-replacement");
    write_key(&directory, "cx-revoked");
    write_active_key_id(&directory, "cx-revoked");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let error = load(&directory).expect_err("missing replacement must fail closed");

    assert!(matches!(error, KeyManagerError::MissingActiveKeyMaterial));
    assert_eq!(
        read_active_key_id(&directory),
        "cx-revoked",
        "证据必须留在盘上，不得改写 kid"
    );
    assert!(
        directory.key_path("cx-revoked").exists(),
        "恢复失败时不得先删掉唯一还在的材料"
    );
    assert!(directory.record_path().exists(), "未完成的记录必须保留");
}

/// 记录被篡改成"吊销的就是替代密钥"：执行它等于自己删自己，一律 fail-closed。
#[test]
fn recovery_rejects_a_record_naming_the_same_key_twice() {
    let directory = TempKeyDir::new("self-referential");
    write_key(&directory, "cx-active");
    write_active_key_id(&directory, "cx-active");
    fs::write(directory.record_path(), "cx-active\ncx-active\n").expect("corrupt record");

    let error = load(&directory).expect_err("self-referential record must fail closed");

    assert!(matches!(error, KeyManagerError::InvalidKeyId));
    assert!(directory.key_path("cx-active").exists());
    assert!(directory.record_path().exists());
}

/// 记录内容非法（空行、越界字符）同样 fail-closed，不猜测意图。
#[test]
fn recovery_rejects_a_malformed_record() {
    let directory = TempKeyDir::new("malformed");
    write_key(&directory, "cx-active");
    write_active_key_id(&directory, "cx-active");
    fs::write(directory.record_path(), "../escape\n").expect("corrupt record");

    let error = load(&directory).expect_err("malformed record must fail closed");

    assert!(matches!(error, KeyManagerError::InvalidKeyId));
    assert!(directory.key_path("cx-active").exists());
}

/// 没有记录时加载路径完全不受影响。
#[test]
fn load_without_a_record_is_unaffected() {
    let directory = TempKeyDir::new("no-record");
    write_key(&directory, "cx-active");
    write_active_key_id(&directory, "cx-active");

    let active_key_id = load(&directory).expect("healthy directory must load");

    assert_eq!(active_key_id, "cx-active");
    assert!(!directory.record_path().exists());
}

/// 记录文件不能被误当成密钥材料或中断的原子写临时文件。
#[test]
fn the_record_file_is_outside_the_key_and_temporary_namespaces() {
    let directory = TempKeyDir::new("namespace");
    write_key(&directory, "cx-active");
    write_key(&directory, "cx-replacement");
    write_active_key_id(&directory, "cx-active");
    // active kid 与记录里的吊销目标不同，因此这条记录本轮不改 kid，只删材料。
    write_record(&directory, "cx-gone", "cx-active");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("record must not be read as key material");

    assert_eq!(active_key_id, "cx-active");
    assert!(
        !materials.keys().any(|key_id| key_id.contains("revocation")),
        "记录文件不得被 discover_key_files 收进材料集合"
    );
    assert!(materials.contains_key("cx-replacement"));
}
