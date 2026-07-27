use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::config::Config;

pub type Database = PgPool;

pub fn connect(config: &Config) -> Result<Database, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect_lazy(&config.database_url)
}

pub async fn migrate(database: &Database) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(database).await
}
