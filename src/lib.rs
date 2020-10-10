pub mod cli;
mod client;
pub mod ct;
pub mod database;

pub mod migrations {
    include!(concat!(env!("OUT_DIR"), "/migrations.rs"));
}

#[macro_use]
pub mod migration;

pub use client::Client;
