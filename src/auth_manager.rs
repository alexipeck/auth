use crate::{
    bidirectional::LoginFlow,
    error::{AuthFlowError, Error, InternalError, AuthenticationError, AccountSetupError},
    r#trait::{Expired, HashDebug}, filter_headers_into_btreeset, user::User, cryptography::generate_token,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use google_authenticator::GoogleAuthenticator;
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

pub struct Config {
    cookie_name: String,
    allowed_origin: HeaderValue,
}

impl Config {
    pub fn new(cookie_name: String, allowed_origin: HeaderValue) -> Self {
        Self {
            cookie_name,
            allowed_origin,
        }
    }
    pub fn get_cookie_name(&self) -> &String {
        &self.cookie_name
    }
    pub fn get_allowed_origin(&self) -> &HeaderValue {
        &self.allowed_origin
    }
}

pub struct AuthManager {
    auth_lifetime: Duration,

    login_flows: Arc<RwLock<HashMap<String, (Uuid, DateTime<Utc>)>>>,
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>>,

    regexes: Regexes,
    pub config: Config,
}

impl AuthManager {
    pub fn new(cookie_name: String, allowed_origin: String) -> Result<Self, Error> {
        let allowed_origin: HeaderValue = match allowed_origin.parse() {
            Ok(allowed_origin) => allowed_origin,
            Err(err) => return Err(InternalError::InvalidOrigin(err.into()).into()),
        };
        Ok(Self {
            login_flows: Arc::new(RwLock::new(HashMap::new())),
            auth_lifetime: Duration::minutes(5),
            users: Arc::new(RwLock::new(HashMap::new())),
            email_to_id_registry: Arc::new(RwLock::new(HashMap::new())),

            regexes: Regexes::default(),
            config: Config::new(cookie_name, allowed_origin),
        })
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

    pub fn generate_user_uid(&self) -> Uuid {
        loop {
            let uid = Uuid::new_v4();
            if self.users.read().contains_key(&uid) {
                continue;
            }
            return uid;
        }
    }

    pub fn add_user(
        &self,
        email: EmailAddress,
        password: String,
        display_name: String,
        two_fa_client_secret: String,
    ) -> Result<(), Error> {
        let salt = generate_token(32);
        let hashed_and_salted_password =
            match argon2::hash_encoded(password.as_bytes(), salt.as_bytes(), &argon2::Config::default()) {
                Ok(hashed_and_salted_password) => hashed_and_salted_password,
                Err(err) => return Err(InternalError::AccountSetup(AccountSetupError::Argon2(err)).into()),
            };
        let user = User {
            id: self.generate_user_uid(),
            email: email.to_owned(),
            hashed_and_salted_password,
            display_name,
            two_fa_client_secret,
        };
        /* let mut data_connection = establish_connection(DBSource::AgentManager);
        if let Err(err) = save_authorisation_profile(&mut data_connection, &authorisation) {
            warn!("{}", err);
        }
        if let Err(err) = save_user(&mut data_connection, &user) {
            panic!("{}", err);
        } */

        /* self.authorisations
            .write()
            .insert(authorisation_uid, authorisation); */
        self.email_to_id_registry.write().insert(email, user.id);
        self.users.write().insert(user.id, user);
        //TODO: Send this user to authenticated clients to update in the list without reload
        Ok(())
    }

    pub fn validate_user_credentials(
        &self,
        email: &EmailAddress,
        password: &String,
        two_factor_code: String,
    ) -> Result<Uuid, Error> {
        match self.email_to_id_registry.read().get(email) {
            Some(user_id) => {
                match self.users.read().get(user_id) {
                    Some(user) => {
                        match argon2::verify_encoded(
                            &user.hashed_and_salted_password,
                            password.as_bytes(),
                        ) {
                            Ok(verified) => {
                                if verified {
                                    let auth = GoogleAuthenticator::new();
                                    match auth.get_code(user.two_fa_client_secret.as_str(), 0) {
                                        Ok(current_code) => {
                                            if two_factor_code == current_code {
                                                Ok(user.id)
                                            } else {
                                                Err(InternalError::Authentication(AuthenticationError::Incorrect2FACode).into())
                                            }
                                        }
                                        Err(err) => Err(InternalError::Authentication(AuthenticationError::GoogleAuthenticator(err)).into()),
                                    }
                                } else {
                                    Err(InternalError::Authentication(AuthenticationError::IncorrectCredentials).into())
                                }
                            }
                            Err(err) => Err(InternalError::Authentication(AuthenticationError::InvalidPasswordFormat(err)).into()),
                        }
                    }
                    None => Err(InternalError::Authentication(AuthenticationError::UserUIDNotRegisteredToEmail(email.to_owned())).into()),
                }
            }
            None => Err(InternalError::Authentication(AuthenticationError::EmailNotRegistered(email.to_owned())).into()),
        }
    }
    /* fn validate_login_credentials(&self, credentials: LoginCredentials) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_1(&self, ) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_2(&self, cookie_token: String, header_token: String, two_fa_code: [u8; 6]) -> Result<()/* Option<User> */, Error> {

    } */
}
