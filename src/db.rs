use std::borrow::Cow;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

pub type Database = PgPool;

fn normalize_migration_sql(sql: &'static str) -> Cow<'static, str> {
    if sql.contains('\r') {
        Cow::Owned(sql.replace("\r\n", "\n"))
    } else {
        Cow::Borrowed(sql)
    }
}

pub fn connect(config: &Config) -> Result<Database, crate::sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect_lazy(&config.database_url)
}

pub async fn migrate(database: &Database) -> Result<(), crate::sqlx::migrate::MigrateError> {
    embedded_migrator().run(database).await
}

fn embedded_migrator() -> crate::sqlx::migrate::Migrator {
    use crate::sqlx::migrate::{Migration, MigrationType, Migrator};

    let migrations = vec![
        Migration::new(
            1,
            Cow::Borrowed("unified identity baseline"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0001_initial.sql")),
            false,
        ),
        Migration::new(
            2,
            Cow::Borrowed("plans and entitlements"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0002_plans.sql")),
            false,
        ),
        Migration::new(
            3,
            Cow::Borrowed("session outbox consistency"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0003_session_outbox.sql")),
            false,
        ),
        Migration::new(
            4,
            Cow::Borrowed("session outbox deleted target cleanup"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0004_relax_deleted_session_outbox_target.sql"
            )),
            false,
        ),
        Migration::new(
            5,
            Cow::Borrowed("session outbox event user retention"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!(
                "../migrations/0005_session_outbox_event_user.sql"
            )),
            false,
        ),
        Migration::new(
            6,
            Cow::Borrowed("session revocation epochs"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0006_session_epochs.sql")),
            false,
        ),
    ];

    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_migration_sql;

    #[test]
    fn migration_sql_normalizes_windows_line_endings() {
        assert_eq!(
            normalize_migration_sql("CREATE TABLE test;\r\n"),
            "CREATE TABLE test;\n"
        );
    }
}
