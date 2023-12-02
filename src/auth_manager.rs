use crate::{
    bidirectional::LoginFlow,
    error::{AuthFlowError, Error, InternalError},
    r#trait::{Expired, HashDebug}, filter_headers_into_btreeset,
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use regex::RegexSet;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

pub struct Regexes {
    pub roaming_header_profile: RegexSet,
    pub restricted_header_profile: RegexSet,
}

impl Default for Regexes {
    fn default() -> Self {
        let mut keys = vec![
            "host",
            "user-agent",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "referer",
            "origin",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-dest",
            "sec-fetch-site",
            "sec-fetch-mode",
            "accept-language",
            "dnt",
            "connection",
            "accept-encoding",
        ];
        let roaming_header_profile = RegexSet::new(&keys.iter().map(|&key| format!(r"^{}$", regex::escape(key))).collect::<Vec<String>>()).unwrap();
        keys.push("x-real-ip");
        keys.push("x-forwarded-for");
        let restricted_header_profile = RegexSet::new(&keys.into_iter().map(|key| format!(r"^{}$", regex::escape(key))).collect::<Vec<String>>()).unwrap();
        
        Self { roaming_header_profile, restricted_header_profile }
    }
}

pub struct AuthManager {
    auth_lifetime: Duration,

    login_flows: Arc<RwLock<HashMap<String, (Uuid, DateTime<Utc>)>>>,

    regexes: Regexes,
}

impl Default for AuthManager {
    fn default() -> Self {
        Self {
            login_flows: Arc::new(RwLock::new(HashMap::new())),
            auth_lifetime: Duration::minutes(5),
            regexes: Regexes::default(),
        }
    }
}

impl AuthManager {
    pub fn setup_login_flow(&self, headers: &HeaderMap) -> (String, DateTime<Utc>) {
        let headers = filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);
        let salt: Uuid = Uuid::new_v4();
        let key: String = headers.hash_debug(salt);
        let expiry = Utc::now() + self.auth_lifetime;
        self.login_flows
            .write()
            .insert(key.to_owned(), (salt, expiry.to_owned()));
        (key, expiry)
    }
    pub fn verify_login_flow(
        &self,
        login_flow: &LoginFlow,
        headers: &HeaderMap,
    ) -> Result<bool, Error> {
        if let Some((salt, expiry)) = self.login_flows.read().get(login_flow.get_key()) {
            if expiry.expired() {
                return Err(InternalError::AuthFlow(AuthFlowError::Expired).into());
            }
            let headers = filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);
            let regenerated_key = headers.hash_debug(*salt);
            return Ok(&regenerated_key == login_flow.get_key());
        }
        Err(InternalError::AuthFlow(AuthFlowError::Invalid).into())
    }
    pub fn remove_expired_auth_flows(&self) {
        let mut keys = Vec::new();
        {
            for (key, (_, expiry)) in self.login_flows.read().iter() {
                if expiry.expired() {
                    keys.push(key.to_owned());
                }
            }
        }
        let mut auth_flows_write_lock = self.login_flows.write();
        for key in keys.iter() {
            let _ = auth_flows_write_lock.remove(key);
        }
    }
    /* fn validate_login_credentials(&self, credentials: LoginCredentials) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_1(&self, ) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_2(&self, cookie_token: String, header_token: String, two_fa_code: [u8; 6]) -> Result<()/* Option<User> */, Error> {

    } */
}
