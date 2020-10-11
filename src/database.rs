use log::debug;
use sqlx::prelude::*;
use sqlx::{Error, PgPool};

use crate::ct::Operator;

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

/// Finds and returns the id of a given operator by its name, provided that it exists, returns
/// `None` if it doesn't
pub async fn find_operator_id_by_name(pool: &PgPool, name: &str) -> Result<Option<i64>, Error> {
    match sqlx::query_as("SELECT id FROM operators WHERE name = $1")
        .bind(name)
        .fetch_optional(&*pool)
        .await?
    {
        Some((id,)) => Ok(id),
        None => Ok(None),
    }
}

/// Inserts the given `operator` into the database, returning the row id
pub async fn create_operator(pool: &PgPool, operator: &Operator) -> Result<i64, Error> {
    println!("Creating operator {}", operator.name);
    let res: (i64,) = sqlx::query_as("INSERT INTO operators (name) VALUES ($1) RETURNING id")
        .bind(&operator.name)
        .fetch_one(&*pool)
        .await?;

    Ok(res.0)
}

/// Finds and returns the id of a log operator email with a given `email_addr` under the given
/// operator id if it exists
pub async fn find_operator_email_id_by_email_and_op_id(
    pool: &PgPool,
    email: &str,
    op_id: i64,
) -> Result<Option<i64>, Error> {
    match sqlx::query_as("SELECT id FROM operator_emails WHERE email = $1 AND operator_id = $2")
        .bind(email)
        .bind(op_id)
        .fetch_optional(&*pool)
        .await?
    {
        Some((id,)) => Ok(id),
        None => Ok(None),
    }
}

/// Inserts the give operator `email` into the database under the given `op_id`, returning the row id
pub async fn create_operator_email(pool: &PgPool, email: &str, op_id: i64) -> Result<i64, Error> {
    println!("Creating operator email {} under op_id {}", email, op_id);

    let res: (i64,) = sqlx::query_as(
        "INSERT INTO operator_emails (email, operator_id) VALUES ($1, $2) RETURNING id",
    )
    .bind(&email)
    .bind(&op_id)
    .fetch_one(&*pool)
    .await?;

    Ok(res.0)
}

pub async fn sync_operator_list(pool: &PgPool, operators: &[Operator]) -> Result<(), Error> {
    for operator in operators {
        // Find or insert the operator into the database
        let operator_id = match find_operator_id_by_name(&*pool, &operator.name).await? {
            Some(id) => id,
            None => create_operator(&*pool, &operator).await?,
        };

        // Find or insert the operator emails into the database
        for email in &operator.email {
            if find_operator_email_id_by_email_and_op_id(&*pool, &email, operator_id)
                .await?
                .is_none()
            {
                create_operator_email(&*pool, &email, operator_id).await?;
            }
        }

        println!("op_id: {:?}", operator_id);
    }

    Ok(())
}
