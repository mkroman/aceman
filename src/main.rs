use clap::{crate_authors, crate_name, crate_version, App, Arg};

mod ct;

async fn print_known_certificate_logs() -> Option<()> {
    let log_list = ct::get_log_list().await.ok()?;
    let log_server_count = log_list
        .operators
        .iter()
        .map(|op| &op.logs)
        .flatten()
        .count();

    println!("Found {} CTLs...", log_server_count);

    for operator in log_list.operators {
        for log_server in operator.logs {
            if let Ok(sth) = ct::get_signed_tree_head(log_server.url.as_ref()).await {
                let max_block_size = ct::get_max_block_size(log_server.url.as_ref())
                    .await
                    .unwrap_or(0);

                println!("{}", log_server.description);
                println!("    \\- URL:            {}", log_server.url);
                println!("    \\- Owner:          {}", operator.name);
                println!("    \\- Cert Count:     {}", sth.tree_size);
                println!("    \\- Max Block Size: {}", max_block_size);
                println!();
            }
        }
    }

    Some(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    pretty_env_logger::init();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .arg(
            Arg::with_name("list")
                .short("l")
                .long("list")
                .help("List known certificate logs"),
        )
        .get_matches();

    if matches.is_present("list") {
        print_known_certificate_logs().await;
    }

    Ok(())
}
