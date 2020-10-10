use log::debug;
use sqlx::prelude::*;
use sqlx::{Error, PgPool};

/// The database pool type. We're using Postgres for now.
pub type DbPool = PgPool;

/// The database connection type, used to simplify the migrations
pub type Connection = sqlx::pool::PoolConnection<sqlx::PgConnection>;

/// A database transaction type, used to simplify imports in the migrations
pub type Transaction = sqlx::Transaction<Connection>;

/// Connects to the database specified in the CLI `opts` and ten returns the Postgres client
/// instance
pub async fn init(postgres_url: &str) -> Result<PgPool, anyhow::Error> {
    let conn = connect(postgres_url).await?;

    Ok(conn)
}

/// Sets up the schema migration using the given postgres `conn` and returns the current migration
/// version, if any
pub async fn init_migration(conn: &mut PgPool) -> Result<(), Error> {
    // Create migration table if it doesn't exist
    prepare_migration(&conn).await?;

    debug!(
        "Current migration version: {}",
        get_migration_version(&conn)
            .await?
            .unwrap_or_else(|| "none".to_owned())
    );

    Ok(())
}

/// Prepares the database by creating migration tables if they don't already exist
///
/// Returns the number of rows modified
pub async fn prepare_migration(db: &PgPool) -> Result<u64, Error> {
    let res = sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            filename VARCHAR(255) NOT NULL PRIMARY KEY
        )",
    )
    .execute(db)
    .await?;

    Ok(res)
}

/// Returns the latest migration filename applied to the database, as a string
pub async fn get_migration_version(db: &PgPool) -> Result<Option<String>, Error> {
    let row: Option<String> =
        sqlx::query_as("SELECT filename FROM schema_migrations ORDER BY filename DESC LIMIT 1")
            .fetch_optional(db)
            .await?
            .map(|row: (String,)| row.0);

    Ok(row)
}

pub async fn connect(url: &str) -> Result<PgPool, Error> {
    let pool = PgPool::builder().max_size(5).build(url).await?;

    Ok(pool)
}
