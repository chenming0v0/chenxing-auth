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
