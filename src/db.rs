use std::borrow::Cow;

use crate::sqlx::{PgPool, PgPoolOptions};

use crate::config::Config;

pub type Database = PgPool;

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
            Cow::Borrowed(include_str!("../migrations/0001_initial.sql")),
            false,
        ),
        Migration::new(
            2,
            Cow::Borrowed("audit events"),
            MigrationType::Simple,
            Cow::Borrowed(include_str!("../migrations/0002_audit_events.sql")),
            false,
        ),
        Migration::new(
            3,
            Cow::Borrowed("admins"),
            MigrationType::Simple,
            Cow::Borrowed(include_str!("../migrations/0003_admins.sql")),
            false,
        ),
        Migration::new(
            4,
            Cow::Borrowed("external oauth providers"),
            MigrationType::Simple,
            Cow::Borrowed(include_str!("../migrations/0004_external_oauth.sql")),
            false,
        ),
    ];

    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}
