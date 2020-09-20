use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LogList {
    operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
struct Operator {
    /// Name of this log operator
    name: String,
    /// CT log operator email addresses
    email: Vec<String>,
    /// Details of Certificate Transparency logs run by this operator
    logs: Vec<Log>,
}

#[derive(Debug, Deserialize)]
struct TemporalInterval {
    /// All certificates must expire on this date or later
    start_inclusive: DateTime<Utc>,
    /// All certificates must expire before this date
    end_exclusive: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum LogType {
    Prod,
    Test,
}

#[derive(Debug, Deserialize)]
struct FinalTreeHead {
    tree_size: u64,
    sha256_root_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum State {
    Pending {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
    },
    Qualified {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
    },
    Usable {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
    },
    ReadOnly {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
        /// The tree head (tree size and root hash) at which the log was made read-only
        final_tree_head: FinalTreeHead,
    },
    Retired {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
    },
    Rejected {
        /// The time at which the log entered this state
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Deserialize)]
struct Log {
    /// Description of the CT log
    description: String,
    /// The public key of the CT log
    key: String,
    /// The SHA-256 hash of the CT log's public key, base64-encoded
    log_id: String,
    /// The Maximum Merge Delay, in seconds
    mmd: u64,
    /// The base URL of the CT log's HTTP API
    url: String,
    /// The domain name of the CT log's DNS API
    dns: Option<String>,
    /// The log will only accept certificates that expire (have a NotAfter date) between these dates
    temporal_interval: Option<TemporalInterval>,
    /// The purpose of this log, e.g. test.
    log_type: Option<LogType>,
    /// The state of the log from the log list distributor's perspective
    state: Option<State>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::{fs, path::Path};

    #[test]
    fn it_parses_log_list() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("1600565322-log_list.json");
        let file = fs::File::open(&path).unwrap();

        serde_json::from_reader::<_, LogList>(BufReader::new(file)).unwrap();
    }

    #[test]
    fn it_parses_all_logs_list() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("1600567112-all_logs_list.json");
        let file = fs::File::open(&path).unwrap();

        serde_json::from_reader::<_, LogList>(BufReader::new(file)).unwrap();
    }
}
