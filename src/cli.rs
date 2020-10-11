use structopt::StructOpt;

const DEFAULT_POSTGRES_URL: &str = "postgresql://aceman@localhost/aceman_development";

#[derive(StructOpt, Debug, Clone)]
pub struct ListOpts {
    // The maximum amount of logs to show
    #[structopt(short = "n")]
    pub num_logs: Option<u64>,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    /// List the known operator logs
    #[structopt(name = "list")]
    List(ListOpts),

    /// Synchronizes the certificate logs to the local database
    Sync(ListOpts),

    /// Perform database operations
    #[structopt(name = "database", alias = "db")]
    DbCommand(DbSubCommand),
}

#[derive(StructOpt, Debug)]
pub enum MigrateCommand {
    /// Migrates the database to the specified version
    Up(MigrateUpOpts),
    /// Performs a rollback to the specified version
    Down(MigrateDownOpts),
}

#[derive(StructOpt, Debug)]
pub enum DbSubCommand {
    /// Perform migrations on the database
    Migrate(MigrateCommand),
}

/// Migration CLI options in the down direction where `version` is not an optional argument
#[derive(StructOpt, Debug)]
pub struct MigrateDownOpts {
    /// The version to migrate to
    pub version: String,
}

/// Migration CLI options in the up direction where `version` is either a String or None - if it is
/// None, the migration will continue until the latest available option
#[derive(StructOpt, Debug)]
pub struct MigrateUpOpts {
    /// The version to migrate to
    pub version: Option<String>,
}

#[derive(StructOpt, Debug)]
pub struct Opts {
    #[structopt(subcommand)]
    pub command: Command,

    /// PostgreSQL host
    #[structopt(
        long,
        env = "POSTGRES_URL",
        value_name = "HOSTNAME",
        default_value = DEFAULT_POSTGRES_URL
    )]
    pub postgres_url: String,
}
