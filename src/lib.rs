use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum_extra::headers::{self, Header};
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
mod tests {
    #[test]
    pub fn test_signing() {
        let encryption_keys = crate::cryptography::EncryptionKeys::new().unwrap();
        let tokenised = crate::token::Token::create_signed_and_encrypted(
            "Test".to_string(),
            None,
            encryption_keys.get_signing_key(),
            encryption_keys.get_symmetric_key(),
            true,
        )
        .unwrap();
        println!("{tokenised}");
        let token = crate::token::Token::from_str(&tokenised).unwrap();
        let (data, _) = token
            .verify_and_decrypt::<String>(
                encryption_keys.get_verifying_key(),
                encryption_keys.get_symmetric_key(),
            )
            .unwrap();
        assert_eq!(data, "Test".to_string())
    }
}

pub const DEFAULT_READ_LIFETIME_SECONDS: i64 = 900;
pub const DEFAULT_WRITE_LIFETIME_SECONDS: i64 = 300;
pub const DEFAULT_REFRESH_IN_LAST_X_SECONDS: i64 = 60;
pub const DEFAULT_MAX_SESSION_LIFETIME_SECONDS: i64 = 36000;
pub const DEFAULT_INVITE_LIFETIME_SECONDS: i64 = 600;
pub const DEFAULT_LOGIN_FLOW_LIFETIME_SECONDS: i64 = 300;
pub const DEFAULT_INVITE_FLOW_LIFETIME_SECONDS: i64 = 300;

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

pub fn str_to_two_fa(input: &str) -> Option<[u8; 6]> {
    let bytes = input.as_bytes();
    if bytes.len() != 6 {
        return None;
    }
    let mut array = [0u8; 6];
    array.copy_from_slice(bytes);
    Some(array)
}

#[derive(Debug, Clone)]
pub struct Identity(pub String);

impl Header for Identity {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("identity");
        &NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        if let Some(value) = values.next() {
            let value = value.to_str().map_err(|_| headers::Error::invalid())?;
            Ok(Identity(value.to_string()))
        } else {
            Err(headers::Error::invalid())
        }
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        let value: HeaderValue = self.0.clone().try_into().unwrap();
        values.extend(std::iter::once(value));
    }
}
