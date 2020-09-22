//! This implements a HTTP client interface that makes it easier to pool and reuse connections

use log::debug;
use url::Url;

use std::time::Duration;

use crate::ct::{EntryList, SignedTreeHead};

pub struct Client {
    url: Url,
    inner: reqwest::Client,
}

impl Client {
    /// Constructs a new Client
    pub fn new(log_server_url: &str) -> Client {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(20))
            .gzip(true)
            .build()
            .expect("could not build http client");

        let url: Url = log_server_url.parse().unwrap();

        Client { inner, url }
    }

    /// Returns a list of entries from the certificate log
    pub async fn get_entries(&self, start: u64, end: u64) -> Result<EntryList, reqwest::Error> {
        assert!(end > start);

        let mut url = self.build_ct_url(&["ct", "v1", "get-entries"]);

        url.query_pairs_mut()
            .extend_pairs(&[("start", start.to_string()), ("end", end.to_string())]);

        self.inner.get(url).send().await?.json::<EntryList>().await
    }

    /// Returns the maximum amount of entries returned in a single request by the server
    pub async fn get_max_block_size(&self) -> Result<u64, reqwest::Error> {
        let list = self.get_entries(0, 10_000).await?;

        Ok(list.entries.len() as u64)
    }

    /// Returns the latest signed tree head
    pub async fn get_signed_tree_head(&self) -> Result<SignedTreeHead, reqwest::Error> {
        let url = self.build_ct_url(&["ct", "v1", "get-sth"]);

        debug!("Requesting signed tree head from {}", url.as_str());

        self.inner
            .get(url)
            .send()
            .await?
            .json::<SignedTreeHead>()
            .await
    }

    /// Builds a url on the current log server with the given path segments
    fn build_ct_url<I>(&self, segments: I) -> Url
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let mut url: Url = self.url.clone();

        url.path_segments_mut()
            .unwrap()
            .pop_if_empty()
            .extend(segments);

        url
    }
}
