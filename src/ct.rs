use std::array::TryFromSliceError;
use std::convert::TryInto;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer};
use thiserror::Error;

const LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v2/log_list.json";

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("The input was too small to be a merkle tree leaf")]
    InputTooSmall,

    #[error("Invalid merkle leaf")]
    InvalidMerkleLeaf,
}

#[derive(Debug)]
#[repr(u8)]
pub enum MerkleTreeLeafEntry {
    TimestampedEntry {
        timestamp: u64,
        entry: Cert,
        /// Future extensions to this protocol version (v1)
        /// Currently there are none
        extensions: u16,
    },
}

#[derive(Debug)]
#[repr(u16)]
// > opaque ASN.1Cert<1..2^24-1>;
pub enum Cert {
    X509(Vec<u8>),
    PreCert(Vec<u8>),
}

#[derive(Debug)]
#[repr(u8)]
pub enum Version {
    V1 = 0,
}

#[derive(Debug, Deserialize)]
pub struct EntryList {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
pub struct Entry {
    pub leaf_input: MerkleTreeLeaf,
    pub extra_data: String,
}

#[derive(Debug, Deserialize)]
pub struct TreeHeadSignature {}

#[derive(Debug, Deserialize)]
pub struct SignedTreeHead {
    /// The size of the tree, in entries, in decimal
    pub tree_size: u64,
    /// The timestamp, in decimal
    pub timestamp: u64,
    /// The Merkle Tree Hash of the tree, in base64
    pub sha256_root_hash: String,
    /// A TreeHeadSignature for the above data
    pub tree_head_signature: String,
}

#[derive(Debug)]
pub struct MerkleTreeLeaf {
    version: Version,
    leaf: MerkleTreeLeafEntry,
}

impl From<u8> for Version {
    fn from(version: u8) -> Version {
        match version {
            0 => Version::V1,
            _ => unreachable!(),
        }
    }
}

impl MerkleTreeLeafEntry {
    pub fn timestamped_entry_from_slice(buf: &[u8]) -> Result<MerkleTreeLeafEntry, DecodeError> {
        impl From<TryFromSliceError> for DecodeError {
            fn from(_error: TryFromSliceError) -> DecodeError {
                DecodeError::InvalidMerkleLeaf
            }
        }

        if buf.len() < 13 {
            return Err(DecodeError::InputTooSmall);
        }

        // Parse the first 64 bits as a timestamp
        let timestamp =
            u64::from_be_bytes(buf[0x0..0x8].try_into().expect("could not get timestamp"));
        // Parse the next 16 bits as a type identifier
        let entry_type =
            u16::from_be_bytes(buf[0x8..0xa].try_into().expect("could not get entry type"));

        // Parse the entry based on the entry type
        let entry = match entry_type {
            0 => {
                // Parse as a X509 ASN.1 cert
                let len = u32::from_be_bytes([0, buf[0xa], buf[0xb], buf[0xc]]);
                let data = &buf[0xd..0xd + (len as usize)];

                Cert::X509(data.to_vec())
            }
            1 => Cert::PreCert(buf[0xa..buf.len() - 2].to_vec()),
            _ => unreachable!(),
        };

        let extensions = u16::from_be_bytes(buf[buf.len() - 2..].try_into()?);

        Ok(MerkleTreeLeafEntry::TimestampedEntry {
            timestamp,
            entry,
            extensions,
        })
    }
}

impl MerkleTreeLeaf {
    pub fn from_slice(buf: &[u8]) -> Result<MerkleTreeLeaf, DecodeError> {
        if buf.len() < 2 {
            return Err(DecodeError::InputTooSmall);
        }

        let version = buf[0];
        let leaf_type = buf[1];

        let leaf_entry = match leaf_type {
            0 => MerkleTreeLeafEntry::timestamped_entry_from_slice(&buf[2..])?,
            _ => unreachable!(),
        };

        Ok(MerkleTreeLeaf {
            version: version.into(),
            leaf: leaf_entry,
        })
    }
}

impl<'de> Deserialize<'de> for MerkleTreeLeaf {
    fn deserialize<D>(deserializer: D) -> Result<MerkleTreeLeaf, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LeafVisitor;

        impl<'de> de::Visitor<'de> for LeafVisitor {
            type Value = MerkleTreeLeaf;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing base64 data that is a merkle tree leaf")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let res = base64::decode(v).map_err(E::custom)?;
                let tree_leaf = MerkleTreeLeaf::from_slice(&res).map_err(E::custom)?;

                Ok(tree_leaf)
            }
        }

        deserializer.deserialize_str(LeafVisitor)
    }
}

#[derive(Debug, Deserialize)]
pub struct LogList {
    pub operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
pub struct Operator {
    /// Name of this log operator
    pub name: String,
    /// CT log operator email addresses
    pub email: Vec<String>,
    /// Details of Certificate Transparency logs run by this operator
    pub logs: Vec<Log>,
}

#[derive(Debug, Deserialize)]
pub struct TemporalInterval {
    /// All certificates must expire on this date or later
    start_inclusive: DateTime<Utc>,
    /// All certificates must expire before this date
    end_exclusive: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogType {
    Prod,
    Test,
}

#[derive(Debug, Deserialize)]
pub struct FinalTreeHead {
    tree_size: u64,
    sha256_root_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
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
pub struct Log {
    /// Description of the CT log
    pub description: String,
    /// The public key of the CT log
    pub key: String,
    /// The SHA-256 hash of the CT log's public key, base64-encoded
    pub log_id: String,
    /// The Maximum Merge Delay, in seconds
    pub mmd: u64,
    /// The base URL of the CT log's HTTP API
    pub url: String,
    /// The domain name of the CT log's DNS API
    pub dns: Option<String>,
    /// The log will only accept certificates that expire (have a NotAfter date) between these dates
    pub temporal_interval: Option<TemporalInterval>,
    /// The purpose of this log, e.g. test.
    pub log_type: Option<LogType>,
    /// The state of the log from the log list distributor's perspective
    pub state: Option<State>,
}

/// Requests the latest log list that is compliant with Chrome's CT policy and is included in
/// Google Chrome
pub async fn get_log_list() -> Result<LogList, reqwest::Error> {
    reqwest::get(LOG_LIST_URL).await?.json::<LogList>().await
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

    #[test]
    fn it_decodes_merkle_tree_leaf_from_json() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("google-argon2020")
            .join("0-32.json");
        let file = fs::File::open(&path).unwrap();

        let list = serde_json::from_reader::<_, EntryList>(BufReader::new(file)).unwrap();

        println!("{:?}", list);
    }
}
