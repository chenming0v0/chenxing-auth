//! published → active 状态机与落盘恢复（Issue #454）。

use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::super::KeyManagerError;
use super::super::KeyMaterial;
use super::super::persistence::{ACTIVE_KEY_ID_FILE, key_file_name, load_materials};
use super::{
    PENDING_ACTIVATION_FILE, PendingPublishedKey, activate_at, activation_deadline, clear, record,
    recover,
};

const RETENTION: Duration = Duration::from_secs(3600);

struct TempKeyDir(PathBuf);

impl TempKeyDir {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let path = std::env::temp_dir().join(format!("chenxing-activation-{name}-{unique}"));
        fs::create_dir_all(&path).expect("key directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn activation_path(&self) -> PathBuf {
        self.0.join(PENDING_ACTIVATION_FILE)
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

fn test_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid test timestamp")
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

fn write_activation(directory: &TempKeyDir, pending: &PendingPublishedKey) {
    record(directory.path(), pending).expect("activation record");
}

fn load_at(
    directory: &TempKeyDir,
    now: OffsetDateTime,
) -> Result<(String, std::collections::BTreeMap<String, KeyMaterial>), KeyManagerError> {
    load_materials(directory.path(), RETENTION, Duration::ZERO, now, false)
}

#[test]
fn activate_at_is_now_when_delay_is_zero() {
    let now = test_now();
    assert_eq!(activate_at(now, Duration::ZERO), now);
}

#[test]
fn activate_at_adds_a_bounded_delay() {
    let now = test_now();
    assert_eq!(
        activate_at(now, Duration::from_secs(65)),
        now + TimeDuration::seconds(65)
    );
}

#[test]
fn activation_deadline_includes_the_configured_clock_skew_fence() {
    let now = test_now();
    assert_eq!(
        activation_deadline(now, Duration::from_secs(65), Duration::from_secs(30),),
        now + TimeDuration::seconds(95)
    );
}

#[test]
fn a_fast_instance_cannot_activate_before_the_real_propagation_window() {
    let writer_now = test_now();
    let delay = Duration::from_secs(65);
    let skew = Duration::from_secs(30);
    let pending = PendingPublishedKey::new(
        "cx-new".to_owned(),
        "cx-previous".to_owned(),
        activation_deadline(writer_now, delay, skew),
    );

    let fast_clock_just_before_the_window = writer_now + TimeDuration::seconds(65 + 30 - 1);
    assert!(
        !pending.is_due(fast_clock_just_before_the_window),
        "a reader ahead by the allowed skew must not shorten the 65-second propagation window"
    );
    assert!(pending.is_due(writer_now + TimeDuration::seconds(65 + 30)));
}

#[test]
fn a_slow_instance_delays_activation_instead_of_shortening_the_window() {
    let writer_now = test_now();
    let delay = Duration::from_secs(65);
    let skew = Duration::from_secs(30);
    let pending = PendingPublishedKey::new(
        "cx-new".to_owned(),
        "cx-previous".to_owned(),
        activation_deadline(writer_now, delay, skew),
    );

    assert!(
        !pending.is_due(writer_now + TimeDuration::seconds(65)),
        "the conservative fence may delay a slow clock, but it must never activate early"
    );
    assert!(pending.is_due(writer_now + TimeDuration::seconds(95)));
}

#[test]
fn recover_leaves_a_future_activation_unpublished_for_signing() {
    let directory = TempKeyDir::new("not-due");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new(
            "cx-new".to_owned(),
            "cx-previous".to_owned(),
            test_now() + TimeDuration::seconds(65),
        ),
    );

    recover(directory.path(), test_now()).expect("recover");

    assert_eq!(read_active_key_id(&directory), "cx-previous");
    assert!(
        directory.activation_path().exists(),
        "future activation must survive a restart"
    );
}

#[test]
fn recover_promotes_a_due_published_key() {
    let directory = TempKeyDir::new("due");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new("cx-new".to_owned(), "cx-previous".to_owned(), test_now()),
    );

    recover(directory.path(), test_now()).expect("recover");

    assert_eq!(read_active_key_id(&directory), "cx-new");
    assert!(
        !directory.activation_path().exists(),
        "activation record must clear after promotion"
    );
}

#[test]
fn recover_discards_an_activation_whose_material_is_gone() {
    let directory = TempKeyDir::new("missing-material");
    write_key(&directory, "cx-previous");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new("cx-new".to_owned(), "cx-previous".to_owned(), test_now()),
    );

    recover(directory.path(), test_now()).expect("recover");

    assert_eq!(read_active_key_id(&directory), "cx-previous");
    assert!(!directory.activation_path().exists());
}

/// 崩溃发生在 activation record 已持久化、私钥材料尚未落盘之间：旧 active
/// 继续签发，发布意图被清理，绝不能生成或激活一个没有材料的 kid。
#[test]
fn load_rolls_back_a_published_rotation_before_material_persistence() {
    let directory = TempKeyDir::new("record-before-material");
    write_key(&directory, "cx-previous");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new(
            "cx-new".to_owned(),
            "cx-previous".to_owned(),
            test_now() + TimeDuration::seconds(65),
        ),
    );

    let (active_key_id, materials) = load_at(&directory, test_now()).expect("load");

    assert_eq!(active_key_id, "cx-previous");
    assert_eq!(read_active_key_id(&directory), "cx-previous");
    assert!(!materials.contains_key("cx-new"));
    assert!(!directory.activation_path().exists());
}

#[test]
fn recover_discards_a_corrupt_activation_without_touching_the_active_key() {
    let directory = TempKeyDir::new("corrupt");
    write_key(&directory, "cx-previous");
    write_active_key_id(&directory, "cx-previous");
    fs::write(directory.activation_path(), b"not-a-record").expect("corrupt record");

    recover(directory.path(), test_now()).expect("corrupt record must not fail closed");

    assert_eq!(read_active_key_id(&directory), "cx-previous");
    assert!(!directory.activation_path().exists());
}

/// 第二实例在窗口内加载：新 kid 必须进材料集合（因此进 JWKS），签发权仍是旧 key。
#[test]
fn load_before_activate_at_publishes_the_new_key_without_signing() {
    let directory = TempKeyDir::new("second-instance");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new(
            "cx-new".to_owned(),
            "cx-previous".to_owned(),
            test_now() + TimeDuration::seconds(65),
        ),
    );

    let (active_key_id, materials) = load_at(&directory, test_now()).expect("load");

    assert_eq!(active_key_id, "cx-previous");
    assert!(
        materials.contains_key("cx-new"),
        "new public key must be visible before it signs"
    );
    assert!(
        materials.contains_key("cx-previous"),
        "old key stays published for verification"
    );
    assert!(
        materials["cx-new"].retired_at.is_none(),
        "a published key is not retired"
    );
    assert!(
        directory.activation_path().exists(),
        "second instance must keep the same activate_at"
    );
}

#[test]
fn load_after_activate_at_promotes_and_retires_the_previous_key() {
    let directory = TempKeyDir::new("promote-on-load");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    write_activation(
        &directory,
        &PendingPublishedKey::new("cx-new".to_owned(), "cx-previous".to_owned(), test_now()),
    );

    let (active_key_id, materials) = load_at(&directory, test_now()).expect("load");

    assert_eq!(active_key_id, "cx-new");
    assert!(materials["cx-previous"].retired_at.is_some());
    assert!(materials["cx-new"].retired_at.is_none());
    assert!(!directory.activation_path().exists());
}

#[test]
fn clear_is_idempotent() {
    let directory = TempKeyDir::new("clear");
    clear(directory.path()).expect("clear missing");
    write_activation(
        &directory,
        &PendingPublishedKey::new("cx-new".to_owned(), "cx-previous".to_owned(), test_now()),
    );
    clear(directory.path()).expect("clear existing");
    clear(directory.path()).expect("clear again");
    assert!(!directory.activation_path().exists());
}

/// 轮换 journal 与激活记录同时存在时，签发切换必须听 `activate_at`，不能被旧
/// journal 恢复路径立即切走。
#[test]
fn a_rotation_journal_does_not_bypass_a_future_activation() {
    let directory = TempKeyDir::new("journal-and-activation");
    write_key(&directory, "cx-previous");
    write_key(&directory, "cx-new");
    write_active_key_id(&directory, "cx-previous");
    fs::write(
        directory.path().join("pending-rotation.record"),
        "cx-new\ncx-previous\n",
    )
    .expect("rotation journal");
    write_activation(
        &directory,
        &PendingPublishedKey::new(
            "cx-new".to_owned(),
            "cx-previous".to_owned(),
            test_now() + TimeDuration::seconds(65),
        ),
    );

    let (active_key_id, materials) = load_at(&directory, test_now()).expect("load");

    assert_eq!(active_key_id, "cx-previous");
    assert!(materials.contains_key("cx-new"));
    assert!(directory.activation_path().exists());
    assert!(
        !directory.path().join("pending-rotation.record").exists(),
        "persist-phase journal must clear once the activation record is authoritative"
    );
}

#[test]
fn activation_record_round_trips_rfc3339() {
    let directory = TempKeyDir::new("round-trip");
    let pending = PendingPublishedKey::new(
        "cx-new".to_owned(),
        "cx-previous".to_owned(),
        test_now() + TimeDuration::seconds(65),
    );
    write_activation(&directory, &pending);

    let recorded = fs::read_to_string(directory.activation_path()).expect("record");
    let mut lines = recorded.lines();
    assert_eq!(lines.next(), Some("cx-new"));
    assert_eq!(lines.next(), Some("cx-previous"));
    assert_eq!(
        OffsetDateTime::parse(lines.next().expect("timestamp"), &Rfc3339).expect("rfc3339"),
        pending.activate_at
    );
}
