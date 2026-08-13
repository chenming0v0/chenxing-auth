//! 单元测试：吊销意图记录的崩溃恢复（Issue #284、#311）。
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
    KeyManagerError, PENDING_REVOCATION_FILE, PENDING_ROTATION_FILE, PendingRevocation,
    PendingRotation,
    persistence::{ACTIVE_KEY_ID_FILE, key_file_name, load_materials},
    record, record_rotation,
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

    fn rotation_record_path(&self) -> PathBuf {
        self.0.join(PENDING_ROTATION_FILE)
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

fn write_rotation_record(directory: &TempKeyDir, new_key_id: &str, previous_key_id: &str) {
    record_rotation(
        directory.path(),
        &PendingRotation::new(new_key_id.to_owned(), previous_key_id.to_owned()),
    )
    .expect("pending rotation record");
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

/// 记录指向的替代材料已被裁剪时，从剩余材料选择安全 active，不能继续使用 revoked。
#[test]
fn recovery_adopts_a_surviving_key_when_the_recorded_replacement_is_missing() {
    let directory = TempKeyDir::new("missing-replacement");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-survivor");
    write_active_key_id(&directory, "cx-revoked");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("missing replacement must converge");

    assert_eq!(active_key_id, "cx-survivor");
    assert_eq!(read_active_key_id(&directory), "cx-survivor");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// 没有任何安全候选时生成全新 active；revoked 即使是唯一材料也绝不能复活。
#[test]
fn recovery_generates_a_fresh_key_when_replacement_and_other_materials_are_missing() {
    let directory = TempKeyDir::new("missing-all-replacements");
    write_key(&directory, "cx-revoked");
    write_active_key_id(&directory, "cx-revoked");
    write_record(&directory, "cx-revoked", "cx-pruned");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("committed revocation permits a fresh safe key");

    assert_ne!(active_key_id, "cx-revoked");
    assert_ne!(active_key_id, "cx-pruned");
    assert!(materials.contains_key(&active_key_id));
    assert!(!materials.contains_key("cx-revoked"));
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// replacement 已消失但 active 已前进到另一把现存 key：保留 current，不回退也不重置。
#[test]
fn recovery_keeps_a_usable_current_active_when_the_stale_replacement_is_missing() {
    let directory = TempKeyDir::new("missing-stale-replacement");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-current");
    write_active_key_id(&directory, "cx-current");
    write_record(&directory, "cx-revoked", "cx-pruned");

    let active_key_id = load(&directory).expect("usable current active must win");

    assert_eq!(active_key_id, "cx-current");
    assert_eq!(read_active_key_id(&directory), "cx-current");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// active 指针自身已失配时，仍存在的 journal replacement 是唯一明确的恢复目标。
#[test]
fn recovery_repairs_a_missing_current_active_from_the_pending_replacement() {
    let directory = TempKeyDir::new("missing-current-active");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-replacement");
    write_active_key_id(&directory, "cx-missing");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("journal replacement must repair active");

    assert_eq!(active_key_id, "cx-replacement");
    assert_eq!(read_active_key_id(&directory), "cx-replacement");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// active kid 内容损坏时不能盖过仍完整的 pending journal；丢弃指针并采用 replacement。
#[test]
fn recovery_repairs_an_invalid_active_key_id_from_the_pending_replacement() {
    let directory = TempKeyDir::new("invalid-current-active");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-replacement");
    fs::write(directory.active_key_id_path(), [0xff, 0xfe]).expect("invalid active key id");
    write_record(&directory, "cx-revoked", "cx-replacement");

    let active_key_id = load(&directory).expect("journal must replace an invalid active pointer");

    assert_eq!(active_key_id, "cx-replacement");
    assert_eq!(read_active_key_id(&directory), "cx-replacement");
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.record_path().exists());
}

/// 自引用记录没有完整性保证：所有旧材料都不再可信，必须换成全新 keyset。
#[test]
fn recovery_discards_all_old_material_from_a_self_referential_record() {
    let directory = TempKeyDir::new("self-referential");
    write_key(&directory, "cx-revoked");
    write_key(&directory, "cx-survivor");
    write_active_key_id(&directory, "cx-revoked");
    fs::write(directory.record_path(), "cx-revoked\ncx-revoked\n").expect("corrupt record");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("self-referential journal must converge to a fresh keyset");

    assert_ne!(active_key_id, "cx-revoked");
    assert_ne!(active_key_id, "cx-survivor");
    assert_eq!(materials.len(), 1);
    assert!(materials.contains_key(&active_key_id));
    assert!(!directory.key_path("cx-revoked").exists());
    assert!(!directory.key_path("cx-survivor").exists());
    assert!(!directory.record_path().exists());
}

/// 第一行也无法识别时不能猜哪个旧 key 被吊销：丢弃整个 keyset，再生成全新 active。
#[test]
fn recovery_discards_all_old_material_when_the_revoked_target_is_unreadable() {
    let directory = TempKeyDir::new("malformed");
    write_key(&directory, "cx-active");
    write_key(&directory, "cx-old");
    write_active_key_id(&directory, "cx-active");
    fs::write(directory.record_path(), "../escape\ncx-active\n").expect("corrupt record");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("unidentifiable journal must converge to a fresh keyset");

    assert_ne!(active_key_id, "cx-active");
    assert_ne!(active_key_id, "cx-old");
    assert_eq!(materials.len(), 1);
    assert!(materials.contains_key(&active_key_id));
    assert!(!directory.key_path("cx-active").exists());
    assert!(!directory.key_path("cx-old").exists());
    assert!(!directory.record_path().exists());
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

/// 轮换崩溃在“意图已落盘、active kid 还没改写”之间（Issue #318）：新材料在盘上
/// 就补完切换，绝不把未完成启用流程的材料留在盘上冒充“最新”。
#[test]
fn rotation_recovery_completes_a_rotation_interrupted_before_the_key_switch() {
    let directory = TempKeyDir::new("rotation-before-switch");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    write_rotation_record(&directory, "cx-new", "cx-previous");

    let active_key_id = load(&directory).expect("load must complete the pending rotation");

    assert_eq!(active_key_id, "cx-new");
    assert_eq!(read_active_key_id(&directory), "cx-new");
    assert!(
        directory.key_path("cx-previous").exists(),
        "旧 key 必须保留完整验证窗口"
    );
    assert!(
        !directory.rotation_record_path().exists(),
        "记录做完后必须清除"
    );
}

/// 崩溃发生在写私钥材料之前：轮换从未生效，加载回滚意图并保留旧 active。
#[test]
fn rotation_recovery_aborts_a_rotation_whose_material_was_never_persisted() {
    let directory = TempKeyDir::new("rotation-never-persisted");
    write_key(&directory, "cx-previous");
    write_active_key_id(&directory, "cx-previous");
    write_rotation_record(&directory, "cx-new", "cx-previous");

    let active_key_id = load(&directory).expect("aborted rotation must not break the load");

    assert_eq!(active_key_id, "cx-previous");
    assert_eq!(read_active_key_id(&directory), "cx-previous");
    assert!(!directory.key_path("cx-new").exists());
    assert!(
        !directory.rotation_record_path().exists(),
        "回滚后意图记录必须清除，运维重试一次轮换即可"
    );
}

/// 崩溃发生在“active kid 已改写”之后：切换已完成，恢复只清除意图记录。
#[test]
fn rotation_recovery_keeps_a_switch_that_already_completed() {
    let directory = TempKeyDir::new("rotation-after-switch");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-new");
    write_rotation_record(&directory, "cx-new", "cx-previous");

    let active_key_id = load(&directory).expect("completed rotation must load cleanly");

    assert_eq!(active_key_id, "cx-new");
    assert_eq!(read_active_key_id(&directory), "cx-new");
    assert!(directory.key_path("cx-previous").exists());
    assert!(!directory.rotation_record_path().exists());
}

/// 轮换意图记录损坏时与吊销记录同样处理：丢弃整个 keyset，生成全新 active。
#[test]
fn rotation_recovery_discards_all_old_material_from_a_corrupt_record() {
    let directory = TempKeyDir::new("rotation-corrupt");
    write_key(&directory, "cx-active");
    write_key(&directory, "cx-old");
    write_active_key_id(&directory, "cx-active");
    fs::write(directory.rotation_record_path(), "../escape\ncx-active\n").expect("corrupt record");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("corrupt rotation journal must converge to a fresh keyset");

    assert_ne!(active_key_id, "cx-active");
    assert_ne!(active_key_id, "cx-old");
    assert_eq!(materials.len(), 1);
    assert!(materials.contains_key(&active_key_id));
    assert!(!directory.key_path("cx-active").exists());
    assert!(!directory.key_path("cx-old").exists());
    assert!(!directory.rotation_record_path().exists());
}

/// 轮换记录文件不能被误当成密钥材料或中断的原子写临时文件。
#[test]
fn the_rotation_record_file_is_outside_the_key_and_temporary_namespaces() {
    let directory = TempKeyDir::new("rotation-namespace");
    write_key(&directory, "cx-active");
    write_active_key_id(&directory, "cx-active");
    // kid 已指向记录里的新 key，恢复只做一次幂等清除。
    write_rotation_record(&directory, "cx-active", "cx-previous");

    let (active_key_id, materials) = load_materials(
        directory.path(),
        RETENTION,
        OffsetDateTime::now_utc(),
        false,
    )
    .expect("rotation record must not be read as key material");

    assert_eq!(active_key_id, "cx-active");
    assert!(
        !materials.keys().any(|key_id| key_id.contains("rotation")),
        "记录文件不得被 discover_key_files 收进材料集合"
    );
    assert!(materials.contains_key("cx-active"));
    assert!(!directory.rotation_record_path().exists());
}
