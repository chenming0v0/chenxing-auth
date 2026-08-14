//! 单元测试：退役时刻记录与不变量收敛（Issue #298）。
//!
//! 覆盖的核心事实是 `reconcile` 双向维持“active / published-pending key 没有记录，其余都有记录”：
//! 升级前就存在的历史目录会被补齐，崩溃或吊销留下的错误记录会被清掉。两个方向
//! 都必须正确，否则同一个 bug 换个入口复现。

use std::{collections::BTreeMap, fs, path::PathBuf};

use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use super::super::{KeyMaterial, key_material};
use super::{clear, load_into, reconcile, retirement_file_name, stamp};

/// 独占临时密钥目录，drop 时清理。
struct TempKeyDir(PathBuf);

impl TempKeyDir {
    fn new(name: &str) -> Self {
        let unique = uuid::Uuid::new_v4().simple();
        let path = std::env::temp_dir().join(format!("chenxing-retirement-{name}-{unique}"));
        fs::create_dir_all(&path).expect("key directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }

    fn record_path(&self, key_id: &str) -> PathBuf {
        self.0.join(retirement_file_name(key_id))
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

fn material(byte: u8) -> KeyMaterial {
    key_material(Zeroizing::new(vec![byte]), test_now())
}

#[test]
fn a_stamped_retirement_instant_round_trips() {
    let directory = TempKeyDir::new("round-trip");
    let retired_at = test_now();

    stamp(directory.path(), "cx-old", retired_at).expect("stamp");
    let mut loaded = material(1);
    load_into(directory.path(), "cx-old", &mut loaded).expect("load");

    assert_eq!(loaded.retired_at, Some(retired_at));
}

#[test]
fn a_missing_record_loads_as_still_active() {
    let directory = TempKeyDir::new("missing");
    let mut loaded = material(1);

    load_into(directory.path(), "cx-active", &mut loaded).expect("load");

    assert_eq!(loaded.retired_at, None);
}

/// 记录损坏不能让服务起不来：它是元数据而不是凭据，重盖一份只会多给一个窗口。
#[test]
fn an_unreadable_record_is_treated_as_missing_instead_of_failing_closed() {
    let directory = TempKeyDir::new("corrupt");
    fs::write(directory.record_path("cx-old"), b"not-a-timestamp").expect("corrupt record");
    let mut loaded = material(1);

    load_into(directory.path(), "cx-old", &mut loaded).expect("corrupt record must not fail");

    assert_eq!(loaded.retired_at, None);
}

#[test]
fn clearing_a_missing_record_succeeds() {
    let directory = TempKeyDir::new("clear-missing");

    clear(directory.path(), "cx-absent").expect("clearing must be idempotent");
}

/// 历史目录（升级前写入、没有任何记录）必须被补齐，而不是按创建时刻推断。
#[test]
fn reconcile_stamps_retired_keys_that_have_no_record() {
    let directory = TempKeyDir::new("stamp-legacy");
    let mut materials = BTreeMap::new();
    materials.insert("cx-active".to_owned(), material(1));
    materials.insert("cx-old".to_owned(), material(2));

    reconcile(
        directory.path(),
        "cx-active",
        &mut materials,
        test_now(),
        None,
    )
    .expect("reconcile");

    assert_eq!(materials["cx-old"].retired_at, Some(test_now()));
    let recorded = fs::read_to_string(directory.record_path("cx-old")).expect("record written");
    assert_eq!(
        OffsetDateTime::parse(recorded.trim(), &Rfc3339).expect("parse record"),
        test_now()
    );
    assert!(
        !directory.record_path("cx-active").exists(),
        "active key must not get a retirement record"
    );
}

/// 已有记录不得被 reconcile 推后，否则每次加载都把窗口起点往后挪。
#[test]
fn reconcile_preserves_an_existing_retirement_instant() {
    let directory = TempKeyDir::new("preserve");
    let retired_at = test_now() - TimeDuration::hours(3);
    stamp(directory.path(), "cx-old", retired_at).expect("stamp");
    let mut materials = BTreeMap::new();
    materials.insert("cx-active".to_owned(), material(1));
    let mut old = material(2);
    load_into(directory.path(), "cx-old", &mut old).expect("load");
    materials.insert("cx-old".to_owned(), old);

    reconcile(
        directory.path(),
        "cx-active",
        &mut materials,
        test_now(),
        None,
    )
    .expect("reconcile");

    assert_eq!(materials["cx-old"].retired_at, Some(retired_at));
}

/// 吊销把 active 退回一个更旧的 key 时，那个 key 重新在役，记录必须消失。
#[test]
fn reconcile_clears_the_record_of_a_key_that_is_active_again() {
    let directory = TempKeyDir::new("clear-active");
    stamp(
        directory.path(),
        "cx-back",
        test_now() - TimeDuration::hours(1),
    )
    .expect("stamp");
    let mut materials = BTreeMap::new();
    let mut back = material(1);
    load_into(directory.path(), "cx-back", &mut back).expect("load");
    assert!(back.retired_at.is_some(), "fixture must start retired");
    materials.insert("cx-back".to_owned(), back);

    reconcile(
        directory.path(),
        "cx-back",
        &mut materials,
        test_now(),
        None,
    )
    .expect("reconcile");

    assert_eq!(materials["cx-back"].retired_at, None);
    assert!(
        !directory.record_path("cx-back").exists(),
        "a key that is active again must not keep a retirement record"
    );
}

/// 材料已被回收、记录残留时必须清掉，否则目录随时间单调增长。
#[test]
fn reconcile_removes_records_without_matching_key_material() {
    let directory = TempKeyDir::new("orphan");
    stamp(directory.path(), "cx-gone", test_now()).expect("stamp");
    let mut materials = BTreeMap::new();
    materials.insert("cx-active".to_owned(), material(1));

    reconcile(
        directory.path(),
        "cx-active",
        &mut materials,
        test_now(),
        None,
    )
    .expect("reconcile");

    assert!(
        !directory.record_path("cx-gone").exists(),
        "orphaned retirement records must be collected"
    );
}

/// 已发布、尚未签发的 key 仍在签发生命周期内，不能被盖上退役章（Issue #454）。
#[test]
fn reconcile_does_not_retire_a_published_pending_key() {
    let directory = TempKeyDir::new("published");
    let mut materials = BTreeMap::new();
    materials.insert("cx-active".to_owned(), material(1));
    materials.insert("cx-pending".to_owned(), material(2));

    reconcile(
        directory.path(),
        "cx-active",
        &mut materials,
        test_now(),
        Some("cx-pending"),
    )
    .expect("reconcile");

    assert_eq!(materials["cx-pending"].retired_at, None);
    assert!(
        !directory.record_path("cx-pending").exists(),
        "a published key must not get a retirement record before it signs"
    );
    assert!(!directory.record_path("cx-active").exists());
}
