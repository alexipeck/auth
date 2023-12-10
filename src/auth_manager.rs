use crate::{
    cryptography::generate_token,
    error::{
        AccountSetupError, AuthenticationError, EncryptionError, Error, InternalError, LoginError,
        OpenSSLError, StartupError, Utf8Error,
    },
    filter_headers_into_btreeset,
    flows::user_setup::UserInvite,
    r#trait::HashDebug,
    token::Token,
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
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, str::from_utf8, sync::Arc};
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
    signing_private_key: PKey<Private>,
    signing_public_key: PKey<Public>,
    private_key: PKey<Private>,
    public_key: PKey<Public>,
    symmetric_key: [u8; 32], // 256-bit key for AES-256
    iv: [u8; 16],            // 128-bit IV for AES
}

impl EncryptionKeys {
    pub fn new() -> Result<Self, Error> {
        let (public_key, private_key) = Self::generate_asymmetric_keys()?;
        let (signing_public_key, signing_private_key) = Self::generate_asymmetric_keys()?;
        Ok(Self {
            signing_private_key,
            signing_public_key,
            private_key,
            public_key,
            symmetric_key: rand::thread_rng().gen(),
            iv: rand::thread_rng().gen(),
        })
    }

    pub fn generate_asymmetric_keys() -> Result<(PKey<Public>, PKey<Private>), Error> {
        let rsa: Rsa<Private> = match Rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(err) => {
                return Err(
                    InternalError::Encryption(EncryptionError::GeneratingRSABase(OpenSSLError(
                        err,
                    )))
                    .into(),
                )
            }
        };
        let private_key = match PKey::from_rsa(rsa.clone()) {
            Ok(private_key) => private_key,
            Err(err) => {
                return Err(
                    InternalError::Encryption(EncryptionError::GeneratingRSAPrivate(OpenSSLError(
                        err,
                    )))
                    .into(),
                )
            }
        };
        let public_key_pem: Vec<u8> = match rsa.public_key_to_pem() {
            Ok(public_key_pem) => public_key_pem,
            Err(err) => {
                return Err(
                    InternalError::Encryption(EncryptionError::GeneratingRSAPublicPEM(
                        OpenSSLError(err),
                    ))
                    .into(),
                )
            }
        };
        let public_key = match PKey::public_key_from_pem(&public_key_pem) {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(
                    InternalError::Encryption(EncryptionError::GeneratingRSAPublic(OpenSSLError(
                        err,
                    )))
                    .into(),
                )
            }
        };
        Ok((public_key, private_key))
    }

    pub fn get_private_signing_key(&self) -> &PKey<Private> {
        &self.signing_private_key
    }

    pub fn get_public_signing_key(&self) -> &PKey<Public> {
        &self.signing_public_key
    }

    pub fn get_public_encryption_key(&self) -> &PKey<Public> {
        &self.public_key
    }

    pub fn get_public_encryption_key_string(&self) -> Result<String, Error> {
        let public_pem_bytes = match self.public_key.public_key_to_pem() {
            Ok(t) => t,
            Err(err) => {
                println!("{}", err);
                return Err(
                    InternalError::Encryption(EncryptionError::PublicToPEMConversion(
                        OpenSSLError(err),
                    ))
                    .into(),
                );
            }
        };
        match from_utf8(&public_pem_bytes) {
            Ok(public_pem_str) => Ok(public_pem_str.to_string()),
            Err(err) => {
                println!("{}", err);
                Err(
                    InternalError::Encryption(EncryptionError::PublicPEMBytesToString(Utf8Error(
                        err,
                    )))
                    .into(),
                )
            }
        }
    }

    pub fn get_private_decryption_key(&self) -> &PKey<Private> {
        &self.private_key
    }

    pub fn get_symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_key
    }

    pub fn get_iv(&self) -> &[u8; 16] {
        &self.iv
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
}

impl AuthManager {
    pub fn new(cookie_name: String, allowed_origin: String) -> Result<Self, Error> {
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
        Ok(Self {
            users,
            email_to_id_registry,
            regexes: Regexes::default(),
            config: Config::new(cookie_name, allowed_origin),
            encryption_keys,
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
    ) -> Result<Uuid, Error> {
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

    /* fn validate_auth_level_1(&self, ) -> Result<()/* Option<User> */, Error> {

    } */

    /* fn validate_auth_level_2(&self, cookie_token: String, header_token: String, two_fa_code: [u8; 6]) -> Result<()/* Option<User> */, Error> {

    } */
}
