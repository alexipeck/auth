use crate::{
    cryptography::EncryptionKeys,
    error::{
        AccountSetupError, AuthenticationError, Error, InternalError, LoginError, StartupError,
    },
    filter_headers_into_btreeset,
    flows::user_setup::UserInvite,
    r#trait::HashDebug,
    smtp_manager::SmtpManager,
    token::Token,
    user::{User, UserProfile},
    user_session::UserAccessToken,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use google_authenticator::GoogleAuthenticator;
use parking_lot::RwLock;
use regex::RegexSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Debug)]
pub enum FlowType {
    Login,
    Setup,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Flow<T> {
    header_key: String,
    r#type: FlowType,
    data: T,
}

impl<T> Flow<T> {
    pub fn new(header_key: String, r#type: FlowType, data: T) -> Self {
        Self {
            header_key,
            r#type,
            data,
        }
    }
    pub fn get_header_key(&self) -> &String {
        &self.header_key
    }
    pub fn get_type(&self) -> &FlowType {
        &self.r#type
    }
    pub fn get_data(&self) -> &T {
        &self.data
    }
    pub fn collapse(self) -> (String, FlowType, T) {
        (self.header_key, self.r#type, self.data)
    }
    pub fn collapse_data(self) -> T {
        self.data
    }
}

pub struct AuthManager {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>>,

    regexes: Regexes,
    pub config: Config,
    pub encryption_keys: EncryptionKeys,
    pub smtp_manager: SmtpManager,
}

impl AuthManager {
    pub fn new(
        cookie_name: String,
        allowed_origin: String,
        smtp_server: String,
        smtp_sender_address: String,
        smtp_username: String,
        smtp_password: String,
    ) -> Result<Self, Error> {
        let allowed_origin: HeaderValue = match allowed_origin.parse() {
            Ok(allowed_origin) => allowed_origin,
            Err(err) => {
                return Err(InternalError::Startup(StartupError::InvalidOrigin(err.into())).into())
            }
        };
        let email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let users: Arc<parking_lot::lock_api::RwLock<parking_lot::RawRwLock, HashMap<_, _>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let encryption_keys: EncryptionKeys = EncryptionKeys::new()?;
        let smtp_manager: SmtpManager = SmtpManager::new(
            smtp_server,
            smtp_sender_address,
            smtp_username,
            smtp_password,
        )?;
        Ok(Self {
            users,
            email_to_id_registry,
            regexes: Regexes::default(),
            config: Config::new(cookie_name, allowed_origin),
            encryption_keys,
            smtp_manager,
        })
    }
}

impl AuthManager {
    pub fn setup_flow<T: Serialize + DeserializeOwned>(
        &self,
        headers: &HeaderMap,
        r#type: FlowType,
        lifetime: Duration,
        data: T,
    ) -> Result<(String, DateTime<Utc>), Error> {
        let headers =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);

        let key: String = headers.hash_debug();
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        let login_flow: Flow<T> = Flow::new(key, r#type, data);

        let token: String = Token::create_signed_and_encrypted(
            login_flow,
            expiry,
            self.encryption_keys.get_private_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )?;
        Ok((token, expiry))
    }

    pub fn user_setup_incomplete(&self, user_id: &Uuid) -> Option<bool> {
        if let Some(user) = self.users.read().get(user_id) {
            return Some(user.incomplete());
        }
        None
    }

    pub fn validate_invite_token(
        &self,
        token: String,
    ) -> Result<(UserInvite, DateTime<Utc>), Error> {
        Token::verify_and_decrypt::<UserInvite>(
            &token,
            self.encryption_keys.get_public_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )
    }

    pub fn verify_and_decrypt_token(
        &self,
        token: String,
    ) -> Result<(UserAccessToken, DateTime<Utc>), Error> {
        Token::verify_and_decrypt::<UserAccessToken>(
            &token,
            self.encryption_keys.get_public_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )
    }

    pub fn verify_flow<T: Serialize + DeserializeOwned>(
        &self,
        token: &String,
        headers: &HeaderMap,
    ) -> Result<T, Error> {
        let (flow, expiry): (Flow<T>, DateTime<Utc>) = Token::verify_and_decrypt::<Flow<T>>(
            &token,
            self.encryption_keys.get_public_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )?;
        let headers: std::collections::BTreeMap<String, HeaderValue> =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);

        let key: String = headers.hash_debug();
        if &key != flow.get_header_key() {
            return Err(InternalError::Login(LoginError::HeaderKeysDontMatch).into());
        }
        Ok(flow.data)
    }

    pub fn get_user_id_from_email(&self, email: &EmailAddress) -> Option<Uuid> {
        self.email_to_id_registry.read().get(email).cloned()
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

    pub fn invite_user(&self, email: EmailAddress) -> Result<String, Error> {
        let user_id: Uuid = self.generate_user_uid();
        let user: User = User::new(
            user_id,
            String::new(),
            email.to_owned(),
            String::new(),
            String::new(),
        );
        let invite_token: String = Token::create_signed_and_encrypted(
            UserInvite::new(email.to_owned(), user_id),
            Utc::now() + Duration::minutes(600),
            self.encryption_keys.get_private_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )?;
        let _ = self.users.write().insert(user_id, user);
        self.email_to_id_registry.write().insert(email, user_id);
        Ok(invite_token)
    }

    pub fn setup_user(
        &self,
        email: &EmailAddress,
        password: String,
        display_name: String,
        two_fa_client_secret: String,
    ) -> Result<(), Error> {
        let user_id: Uuid = match self.get_user_id_from_email(email) {
            Some(user_id) => user_id,
            None => {
                return Err(InternalError::AccountSetup(
                    AccountSetupError::CouldntGetUserIDFromEmail,
                )
                .into())
            }
        };
        return if let Some(user) = self.users.write().get_mut(&user_id) {
            user.setup_user(password, display_name, two_fa_client_secret)
        } else {
            Err(InternalError::AccountSetup(AccountSetupError::UserNotFound(user_id)).into())
        };
    }

    pub fn validate_user_credentials(
        &self,
        email: &EmailAddress,
        password: &String,
        two_factor_code: String,
    ) -> Result<UserProfile, Error> {
        match self.email_to_id_registry.read().get(email) {
            Some(user_id) => match self.users.read().get(user_id) {
                Some(user) => {
                    if user.incomplete() {
                        return Err(InternalError::Authentication(
                            AuthenticationError::AccountSetupIncomplete,
                        )
                        .into());
                    }
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
                                            Ok(user.to_user_profile())
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

    /* fn validate_auth_level_1(&self, ) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_2(&self, cookie_token: String, header_token: String, two_fa_code: [u8; 6]) -> Result<()/* Option<User> */, Error> {

    } */
}
