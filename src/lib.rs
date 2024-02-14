use axum::http::{HeaderMap, HeaderValue};
use regex::RegexSet;
use std::collections::BTreeMap;

pub mod auth_manager;
pub mod auth_server;
pub mod cryptography;
pub mod database;
pub mod error;
pub mod flows;
pub mod model;
pub mod response;
pub mod routes;
pub mod schema;
pub mod smtp_manager;
pub mod token;
pub mod user;
pub mod user_session;

pub const DEFAULT_READ_LIFETIME_SECONDS: i64 = 900;
pub const DEFAULT_WRITE_LIFETIME_SECONDS: i64 = 300;
pub const DEFAULT_REFRESH_IN_LAST_X_SECONDS: i64 = 60;
pub const DEFAULT_MAX_SESSION_LIFETIME_SECONDS: i64 = 36000;

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
