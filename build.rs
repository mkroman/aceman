use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{fs, io};

const MIGRATION_ROOT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");

/// Returns true if the given `path` is a file and the files extension is `rs`, otherwise returns
/// false
fn is_rust_file(path: &PathBuf) -> bool {
    let path = path.as_path();

    path.is_file() && path.extension() == Some(&OsStr::new("rs"))
}

/// Returns a list of subdirectories in the root migration directory
fn get_migration_files() -> Result<Vec<PathBuf>, io::Error> {
    let paths = fs::read_dir(MIGRATION_ROOT_DIR)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(is_rust_file)
        .collect();

    Ok(paths)
}

/// Concats a bunch of `pub mod migration_<name> { … }` statements for each migration path in
/// `paths` to the given `writer`
fn concat_migration_modules<W: Write>(writer: &mut W, paths: &[PathBuf]) -> Result<(), io::Error> {
    for path in paths {
        let path = path.as_path();
        let base_name = path.file_stem().unwrap().to_str().unwrap();

        println!("cargo:rerun-if-changed=migrations/{}.rs", base_name);

        writeln!(
            writer,
            r#"
pub mod migration_{} {{
    include!("{}");
}}"#,
            base_name,
            path.to_str().unwrap()
        )?;
    }

    writeln!(writer)?;

    Ok(())
}

fn write_init<W: Write>(writer: &mut W, paths: &[PathBuf]) -> Result<(), io::Error> {
    write!(
        writer,
        r#"
use std::collections::BTreeMap;

use crate::migration::{{MigrationFn, MigrationFuture}};

/// A binary tree map that maps the migration name to a function pointer which returns a
/// `MigrationFuture`
pub type MigrationMap<'a> = BTreeMap<&'a str, MigrationFn>;

/// Returns a tuple with two `MigrationMap`s in the form `(migrations_up, migrations_down)`
pub fn init<'a>() -> (MigrationMap<'a>, MigrationMap<'a>) {{
    let mut up: MigrationMap<'a> = BTreeMap::new();
    let mut down: MigrationMap<'a> = BTreeMap::new();
"#
    )?;

    for path in paths.iter().map(|x| x.as_path()) {
        let base_name = path.file_stem().unwrap().to_str().unwrap();
        writeln!(
            writer,
            r#"
    up.insert("{base_name}", move |tx| -> MigrationFuture {{
        Box::pin(migration_{base_name}::up(tx))
    }});

    down.insert("{base_name}", move |tx| -> MigrationFuture {{
        Box::pin(migration_{base_name}::down(tx))
    }});
"#,
            base_name = base_name
        )?;
    }

    writeln!(writer, "    (up, down)\n}}")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=migrations");

    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let migration_files = get_migration_files().expect("could not get migrations");

    let dest_path = Path::new(&out_dir).join("migrations.rs");

    // Create the $OUT_DIR/migrations directory
    fs::create_dir_all(Path::new(&out_dir).join("migrations"))?;

    // Create the $OUT_DIR/migrations.rs file that will be included by the lib
    let mut migrations_rs = fs::File::create(dest_path).expect("could not create migrations.rs");

    concat_migration_modules(&mut migrations_rs, &migration_files)?;
    write_init(&mut migrations_rs, &migration_files)?;

    Ok(())
}
