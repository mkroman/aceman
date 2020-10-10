use std::future::Future;
use std::pin::Pin;

use crate::database::Transaction;
use crate::migrations::{self, MigrationMap};

use log::debug;
use sqlx::PgPool;

/// A pinned and boxed future that yields a `sqlx::Result`
pub type MigrationFuture = Pin<Box<dyn Future<Output = sqlx::Result<Transaction>>>>;

/// A function pointer type that takes a `Transaction` and returns a `MigrationFuture`
pub type MigrationFn = fn(crate::database::Transaction) -> MigrationFuture;

/// A migration interface that makes it easier to do transactional migrations to specific versions
pub struct MigrationRunner<'a> {
    pool: &'a mut PgPool,
    /// The current migration version
    current_version: Option<String>,
    /// Initialized binary tree that holds all our migrations
    migrations_up: MigrationMap<'a>,
    /// Initialized binary tree that holds all our migrations
    migrations_down: MigrationMap<'a>,
}

impl<'a> MigrationRunner<'a> {
    /// Creates a new `MigrationRunner` using the given postgres `client`
    pub fn new(pool: &mut PgPool, current_version: Option<String>) -> MigrationRunner {
        let (migrations_up, migrations_down) = migrations::init();

        MigrationRunner {
            pool,
            current_version,
            migrations_up,
            migrations_down,
        }
    }

    /// Runs all migrations newer than the current, up to and including the specified
    /// `version`
    ///
    /// If `version` is `None`, then all newer migrations are run
    pub async fn migrate_up_to_version(
        &mut self,
        version: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Set the target version to the one specified, otherwise use the most recent
        let target_ver = match version {
            Some(v) => v,
            None => self.migrations_up.keys().max().unwrap(),
        };

        // Create a list of migrations to apply
        let migrations: Vec<(&&str, &MigrationFn)> = match &self.current_version {
            Some(current_ver) => self
                .migrations_up
                .iter()
                .filter(|(&key, _)| key > current_ver.as_str() && key <= target_ver)
                .collect(),
            None => self
                .migrations_up
                .iter()
                .filter(|(&key, _)| key <= target_ver)
                .collect(),
        };

        if !migrations.is_empty() {
            for (name, &up_fn) in migrations {
                // Create a new transaction
                let tx = self.pool.begin().await?;
                debug!("Applying migration {}", name);

                // Run the migration and store the returned transaction
                let mut tx = up_fn(tx).await?;

                sqlx::query("INSERT INTO schema_migrations (filename) VALUES ($1::TEXT)")
                    .bind(name)
                    .execute(&mut tx)
                    .await?;

                tx.commit().await?;
            }
        }

        Ok(())
    }

    /// Runs all migrations from the currently active version back until the given `version`
    pub async fn migrate_down_to_version(
        &mut self,
        version: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let migrations: Vec<(&&str, &MigrationFn)> = match self.current_version.as_ref() {
            Some(current_ver) => self
                .migrations_down
                .iter()
                .filter(|(&key, _)| key <= current_ver.as_str() && key > version)
                .collect(),
            None => vec![],
        };

        if !migrations.is_empty() {
            for (name, &down_fn) in migrations.iter().rev() {
                // Create a new transaction
                let tx = self.pool.begin().await?;

                debug!("Applying downwards migration {}", name);

                // Run the migration and store the returned transaction
                let mut tx = down_fn(tx).await?;

                sqlx::query("DELETE FROM schema_migrations WHERE (filename = $1::TEXT)")
                    .bind(name)
                    .execute(&mut tx)
                    .await?;

                tx.commit().await?;
            }
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! up {
    ($sql:literal) => {
        /// The migration SQL
        pub const SQL_MIGRATION_UP: &'static str = $sql;

        /// Applies the migration
        pub async fn up(
            mut tx: crate::database::Transaction,
        ) -> ::sqlx::Result<crate::database::Transaction> {
            use sqlx::executor::Executor;
            tx.execute(SQL_MIGRATION_UP).await?;

            Ok(tx)
        }
    };
}

#[macro_export]
macro_rules! down {
    ($sql:literal) => {
        /// The migration SQL
        pub const SQL_MIGRATION_DOWN: &'static str = $sql;

        /// Undoes the migration
        pub async fn down(
            mut tx: crate::database::Transaction,
        ) -> ::sqlx::Result<crate::database::Transaction> {
            use sqlx::executor::Executor;
            tx.execute(SQL_MIGRATION_DOWN).await?;

            Ok(tx)
        }
    };
}
