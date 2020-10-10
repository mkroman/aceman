use anyhow::Context;
use log::error;
use structopt::StructOpt;
use tokio::runtime::Runtime;

use aceman::migration::MigrationRunner;
use aceman::{cli, ct, database, Client};

async fn list_known_certificate_logs(_opts: cli::ListOpts) -> Result<(), anyhow::Error> {
    let log_list = ct::get_log_list()
        .await
        .with_context(|| "failed to fetch known log list")?;
    let log_server_count = log_list
        .operators
        .iter()
        .map(|op| &op.logs)
        .flatten()
        .count();

    println!("Found {} CTLs...", log_server_count);

    for operator in log_list.operators {
        for log_server in operator.logs {
            let client = Client::new(log_server.url.as_ref());

            if let Ok(sth) = client.get_signed_tree_head().await {
                let max_block_size = client.get_max_block_size().await.unwrap_or(0);

                println!("{}", log_server.description);
                println!("    \\- URL:            {}", log_server.url);
                println!("    \\- Owner:          {}", operator.name);
                println!("    \\- Cert Count:     {}", sth.tree_size);
                println!("    \\- Max Block Size: {}", max_block_size);
                println!();
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    // Create an async runtime
    let mut rt = Runtime::new().expect("unable to create runtime");
    // Parse the command-line arguments
    let opts = cli::Opts::from_args();

    match &opts.command {
        cli::Command::List(_) | cli::Command::DbCommand(_) => {
            if let Err(err) = rt.block_on(async_main(opts)) {
                error!("runtime error: {}", err);
            }
        }
    }

    Ok(())
}

async fn async_main(opts: cli::Opts) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the PostgreSQL database
    match opts.command {
        cli::Command::List(list_opts) => list_known_certificate_logs(list_opts).await?,
        cli::Command::DbCommand(cmd) => match &cmd {
            cli::DbSubCommand::Migrate(dir) => {
                let mut pool = database::init(&opts.postgres_url).await?;

                // Create the necessary database schema for migrations if it doesn't exist
                database::init_migration(&mut pool).await?;

                let current_version = database::get_migration_version(&pool).await?;
                let mut runner = MigrationRunner::new(&mut pool, current_version);

                match dir {
                    cli::MigrateCommand::Up(ver) => {
                        runner.migrate_up_to_version(ver.version.as_deref()).await?;
                    }
                    cli::MigrateCommand::Down(ver) => {
                        runner.migrate_down_to_version(ver.version.as_ref()).await?;
                    }
                }
            }
        },
    }

    Ok(())
}
