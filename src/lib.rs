use axum::http::{HeaderMap, HeaderValue};
use blake3::Hasher;
use regex::RegexSet;
use std::collections::BTreeMap;

pub mod auth_manager;
#[path = "./transmission/bidirectional.rs"]
pub mod bidirectional;
pub mod credentials;
pub mod cryptography;
pub mod error;
#[path = "./transmission/request.rs"]
pub mod request;
#[path = "./transmission/response.rs"]
pub mod response;
pub mod serde;
pub mod token;
pub mod r#trait;
pub mod user;
#[path = "./flows/user_login.rs"]
pub mod user_login;
#[path = "./flows/user_setup.rs"]
pub mod user_setup;
pub mod user_session;

///hashes with blake3
pub fn hash_string(data: &str) -> String {
    let mut hasher = Hasher::new();
    let _ = hasher.update(data.as_bytes());
    hasher.finalize().to_string()
}

pub fn filter_headers_into_btreeset(
    headers: &HeaderMap,
    regex_whitelist: &RegexSet,
) -> BTreeMap<String, HeaderValue> {
    let mut filtered_headers: BTreeMap<String, HeaderValue> = BTreeMap::new();
    headers.iter().for_each(|header| {
        if regex_whitelist.is_match(header.0.as_str()) {
            let _ = filtered_headers.insert(header.0.to_string(), header.1.to_owned());
        }
    });
    filtered_headers
}
