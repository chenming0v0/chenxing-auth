//! Issue #710 stage 0: source wiring contract for the opt-in test DB timing
//! diagnostics.
//!
//! These are pure source-level assertions and never connect to a database. The
//! behavioral serialization contract (exact schema, disabled mode, omitted
//! phases, concurrent appends, invalid sinks) is covered by the unit tests in
//! `src/db/test_timing/tests.rs`.

const DB_MODULE: &str = include_str!("../../src/db/mod.rs");
const DB_ISOLATION: &str = include_str!("../support/db_isolation.rs");
const MIGRATION_COMPAT: &str = include_str!("../../src/db/migration_compat.rs");
const TEST_TIMING: &str = include_str!("../../src/db/test_timing.rs");

#[test]
fn timing_helper_is_public_but_doc_hidden_and_opt_in() {
    assert!(
        DB_MODULE.contains("#[doc(hidden)]\npub mod test_timing;"),
        "the helper must be declared once, public for integration support, doc-hidden"
    );
    assert!(TEST_TIMING.contains("CHENXING_TEST_DB_TIMING_FILE"));
    assert!(
        TEST_TIMING.contains(".filter(|value| !value.is_empty())"),
        "an empty timing file must disable diagnostics"
    );
}

#[test]
fn fixture_instruments_every_contract_phase() {
    for phase in [
        "PHASE_BOOTSTRAP_CONNECTION",
        "PHASE_DROP_CREATE_SCHEMA",
        "PHASE_POOL_CONNECT",
        "PHASE_MIGRATE",
        "PHASE_SEQUENCE_RESET",
    ] {
        assert!(
            DB_ISOLATION.contains(phase),
            "fixture is missing timing wiring for {phase}"
        );
    }
    assert!(DB_ISOLATION.contains("Timing::from_env()"));
    assert!(DB_ISOLATION.contains("emit_fixture"));
    assert!(DB_ISOLATION.contains("record_zero"));
    assert!(
        DB_ISOLATION.contains("pg_get_serial_sequence('users', 'id')"),
        "the user-ID sequence algorithm must remain in place"
    );
}

#[test]
fn migration_hook_emits_only_after_unlock() {
    let lock = MIGRATION_COMPAT
        .find("Migrate::lock(&mut *connection).await?;")
        .expect("migration must acquire SQLx's advisory lock");
    let run = MIGRATION_COMPAT
        .find("migrator.run_direct(&mut *connection).await")
        .expect("run_direct must remain the instrumented apply step");
    let apply = MIGRATION_COMPAT
        .find("timing.record(PHASE_MIGRATION_APPLY, apply_start)")
        .expect("apply phase must be instrumented");
    let unlock = MIGRATION_COMPAT
        .find("Migrate::unlock(&mut *connection).await")
        .expect("migration must release SQLx's advisory lock");
    let emit = MIGRATION_COMPAT
        .find("timing.emit(outcome)")
        .expect("the event must be emitted after unlock");

    assert!(lock < run, "run_direct must stay inside the migration lock");
    assert!(run < apply, "the apply phase must wrap run_direct");
    assert!(apply < unlock, "the apply phase must finish before unlock");
    assert!(
        unlock < emit,
        "the migration event must never be emitted while the lock is held"
    );

    // The pooled connection must be released (running close_on_drop first when
    // unlock failed) before any diagnostic await.
    let close_on_drop = MIGRATION_COMPAT
        .find("connection.close_on_drop();")
        .expect("a failed unlock must still close the connection on drop");
    let release = MIGRATION_COMPAT
        .rfind("drop(connection);")
        .expect("the connection must be dropped before diagnostics");
    assert!(unlock < close_on_drop && close_on_drop < release);
    assert!(
        release < emit,
        "no migration resource may be held during the diagnostic file write"
    );

    assert!(
        MIGRATION_COMPAT.contains("migrator.set_locking(false);"),
        "the nested SQLx lock must stay disabled"
    );
}

#[test]
fn migration_lock_failure_records_wait_and_releases_before_emit() {
    let record = MIGRATION_COMPAT
        .find("timing.record(PHASE_MIGRATION_LOCK_WAIT, lock_start);")
        .expect("lock wait must be recorded");
    let inspect = MIGRATION_COMPAT
        .find("if let Err(error) = lock_acquired {")
        .expect("the lock result must be inspected");
    assert!(
        record < inspect,
        "a failed lock attempt consumed wait time and must be recorded before the failure is inspected"
    );

    let release_then_emit = MIGRATION_COMPAT
        .find("drop(connection);\n        timing.emit(Outcome::Error).await;")
        .expect("the lock-failure path must release the connection before the diagnostic await");
    let returned = MIGRATION_COMPAT[release_then_emit..]
        .find("return Err(error);")
        .expect("the original lock error must still be returned");
    assert!(
        returned > 0,
        "diagnostics must not precede the original failed-lock return"
    );
}
