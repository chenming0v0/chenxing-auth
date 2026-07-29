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
            Cow::Borrowed("initial"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0001_initial.sql")),
            false,
        ),
        Migration::new(
            2,
            Cow::Borrowed("audit events"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0002_audit_events.sql")),
            false,
        ),
        Migration::new(
            3,
            Cow::Borrowed("admins"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0003_admins.sql")),
            false,
        ),
        Migration::new(
            4,
            Cow::Borrowed("user sessions"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0004_ui_sessions.sql")),
            false,
        ),
        Migration::new(
            5,
            Cow::Borrowed("client owners"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0005_client_owners.sql")),
            false,
        ),
        Migration::new(
            6,
            Cow::Borrowed("client owner cascade"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0006_client_owner_cascade.sql")),
            false,
        ),
        Migration::new(
            7,
            Cow::Borrowed("authentication factors"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0007_auth_factors.sql")),
            false,
        ),
        Migration::new(
            8,
            Cow::Borrowed("admin usernames"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0008_admin_usernames.sql")),
            false,
        ),
        Migration::new(
            9,
            Cow::Borrowed("integer user ids"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0009_user_integer_ids.sql")),
            false,
        ),
        Migration::new(
            10,
            Cow::Borrowed("application settings"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0010_app_settings.sql")),
            false,
        ),
        Migration::new(
            11,
            Cow::Borrowed("usernames"),
            MigrationType::Simple,
            normalize_migration_sql(include_str!("../migrations/0011_usernames.sql")),
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
