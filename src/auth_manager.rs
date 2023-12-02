use crate::{
    bidirectional::LoginFlow,
    error::{AuthFlowError, Error, InternalError},
    r#trait::{Expired, HashDebug},
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

pub struct AuthManager {
    auth_lifetime: Duration,

    login_flows: Arc<RwLock<HashMap<String, (Uuid, DateTime<Utc>)>>>,
}

impl Default for AuthManager {
    fn default() -> Self {
        Self {
            login_flows: Arc::new(RwLock::new(HashMap::new())),
            auth_lifetime: Duration::minutes(5),
        }
    }
}

impl AuthManager {
    pub fn setup_login_flow(&self, headers: &HeaderMap) -> (String, DateTime<Utc>) {
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
            let t = headers.hash_debug(*salt);
            println!("{:?}", t);
            let k = login_flow.get_key();
            println!("{:?}", k);
            return Ok(&t == k);
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
