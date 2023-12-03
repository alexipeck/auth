use crate::{
    bidirectional::LoginFlow,
    cryptography::generate_token,
    error::{
        AccountSetupError, AuthFlowError, AuthenticationError, Error, InternalError, StartupError,
    },
    filter_headers_into_btreeset,
    r#trait::{Expired, HashDebug},
    user::User,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use google_authenticator::GoogleAuthenticator;
use openssl::{
    pkey::{PKey, Private, Public},
    rsa::Rsa,
};
use parking_lot::RwLock;
use rand::Rng;
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
        let roaming_header_profile = RegexSet::new(
            &keys
                .iter()
                .map(|&key| format!(r"^{}$", regex::escape(key)))
                .collect::<Vec<String>>(),
        )
        .unwrap();
        keys.push("x-real-ip");
        keys.push("x-forwarded-for");
        let restricted_header_profile = RegexSet::new(
            &keys
                .into_iter()
                .map(|key| format!(r"^{}$", regex::escape(key)))
                .collect::<Vec<String>>(),
        )
        .unwrap();

        Self {
            roaming_header_profile,
            restricted_header_profile,
        }
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

pub struct EncryptionKeys {
    private_key: PKey<Private>,
    public_key: PKey<Public>,
    symmetric_key: [u8; 32],
    iv: [u8; 16],
}

impl Default for EncryptionKeys {
    fn default() -> Self {
        let rsa: Rsa<Private> = match Rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(err) => {
                panic!();
            }
        };
        let private_key: PKey<Private> = match PKey::from_rsa(rsa.clone()) {
            Ok(private_key) => private_key,
            Err(err) => {
                panic!();
            }
        };
        let public_key_pem: Vec<u8> = match rsa.public_key_to_pem() {
            Ok(public_key_pem) => public_key_pem,
            Err(err) => {
                panic!();
            }
        };
        let public_key: PKey<Public> = match PKey::public_key_from_pem(&public_key_pem) {
            Ok(public_key) => public_key,
            Err(err) => {
                panic!();
            }
        };
        let symmetric_key: [u8; 32] = rand::thread_rng().gen(); // 256-bit key for AES-256
        let iv: [u8; 16] = rand::thread_rng().gen(); // 128-bit IV for AES
        Self {
            private_key,
            public_key,
            symmetric_key,
            iv,
        }
    }
}

impl EncryptionKeys {}

pub struct AuthManager {
    auth_lifetime: Duration,

    login_flows: Arc<RwLock<HashMap<String, (Uuid, DateTime<Utc>)>>>,
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>>,

    regexes: Regexes,
    pub config: Config,
    pub encryption_keys: EncryptionKeys,
}

impl AuthManager {
    pub fn new(cookie_name: String, allowed_origin: String) -> Result<Self, Error> {
        let allowed_origin: HeaderValue = match allowed_origin.parse() {
            Ok(allowed_origin) => allowed_origin,
            Err(err) => {
                return Err(
                    InternalError::StartupError(StartupError::InvalidOrigin(err.into())).into(),
                )
            }
        };
        let users: Arc<parking_lot::lock_api::RwLock<parking_lot::RawRwLock, HashMap<_, _>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let debug_user: User = User::new(Uuid::parse_str("cad8de7f-5507-48ef-9d4e-68939b4ade81").unwrap(), "Alexi Peck".to_string(), EmailAddress::new_unchecked("alexinicolaspeck@gmail.com"), "$argon2id$v=19$m=2097152,t=1,p=1$RF5ndW4oU15VTHpnNFpRNHJmW30vRmoqU3lTPyxhRHE$Xl3u7HaK8/TMaukl0xTBwATjGkfHBS1GH8LHVILgkw".to_string(), "HX4IXEYSPJMHEG36YNEOQDPTKAUDF6YMFBDRCO3Z5LWXQGVO25KOTVWB2UOYWJFH".to_string());
        users.write().insert(*debug_user.get_id(), debug_user);
        Ok(Self {
            login_flows: Arc::new(RwLock::new(HashMap::new())),
            auth_lifetime: Duration::minutes(5),
            users,
            email_to_id_registry: Arc::new(RwLock::new(HashMap::new())),

            regexes: Regexes::default(),
            config: Config::new(cookie_name, allowed_origin),
            encryption_keys: EncryptionKeys::default(),
        })
    }
}

impl AuthManager {
    pub fn setup_login_flow(&self, headers: &HeaderMap) -> (String, DateTime<Utc>) {
        let headers =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);
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
            let headers =
                filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);
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
        let hashed_and_salted_password = match argon2::hash_encoded(
            password.as_bytes(),
            salt.as_bytes(),
            &argon2::Config::default(),
        ) {
            Ok(hashed_and_salted_password) => hashed_and_salted_password,
            Err(err) => {
                return Err(InternalError::AccountSetup(AccountSetupError::Argon2(err)).into())
            }
        };
        let user: User = User::new(
            self.generate_user_uid(),
            display_name,
            email.to_owned(),
            hashed_and_salted_password,
            two_fa_client_secret,
        );
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
        self.email_to_id_registry
            .write()
            .insert(email, user.get_id().to_owned());
        self.users.write().insert(user.get_id().to_owned(), user);
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
            Some(user_id) => match self.users.read().get(user_id) {
                Some(user) => {
                    match argon2::verify_encoded(
                        user.get_hashed_and_salted_password(),
                        password.as_bytes(),
                    ) {
                        Ok(verified) => {
                            if verified {
                                let auth = GoogleAuthenticator::new();
                                match auth.get_code(&user.get_two_fa_client_secret(), 0) {
                                    Ok(current_code) => {
                                        if two_factor_code == current_code {
                                            Ok(*user.get_id())
                                        } else {
                                            Err(InternalError::Authentication(
                                                AuthenticationError::Incorrect2FACode,
                                            )
                                            .into())
                                        }
                                    }
                                    Err(err) => Err(InternalError::Authentication(
                                        AuthenticationError::GoogleAuthenticator(err),
                                    )
                                    .into()),
                                }
                            } else {
                                Err(InternalError::Authentication(
                                    AuthenticationError::IncorrectCredentials,
                                )
                                .into())
                            }
                        }
                        Err(err) => Err(InternalError::Authentication(
                            AuthenticationError::InvalidPasswordFormat(err),
                        )
                        .into()),
                    }
                }
                None => Err(InternalError::Authentication(
                    AuthenticationError::UserUIDNotRegisteredToEmail(email.to_owned()),
                )
                .into()),
            },
            None => Err(
                InternalError::Authentication(AuthenticationError::EmailNotRegistered(
                    email.to_owned(),
                ))
                .into(),
            ),
        }
    }
    /* fn validate_login_credentials(&self, credentials: LoginCredentials) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_1(&self, ) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_2(&self, cookie_token: String, header_token: String, two_fa_code: [u8; 6]) -> Result<()/* Option<User> */, Error> {

    } */
}
