use clap::{crate_authors, crate_name, crate_version, App};

mod ct;

fn main() -> Result<(), anyhow::Error> {
    let _matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .get_matches();

    println!("Hello, world!");

    Ok(())
}
