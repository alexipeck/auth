use crate::{
    cryptography::generate_token,
    error::{
        AccountSetupError, AuthenticationError, EncryptionError, Error, InternalError, LoginError,
        OpenSSLError, StartupError, TokenError,
    },
    filter_headers_into_btreeset,
    r#trait::HashDebug,
    token::Token,
    user::User,
    user_login::LoginFlow,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{Duration, Utc};
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

pub struct AuthManager {
    auth_lifetime: Duration,
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
        let email_to_id_registry = Arc::new(RwLock::new(HashMap::new()));
        let users: Arc<parking_lot::lock_api::RwLock<parking_lot::RawRwLock, HashMap<_, _>>> =
            Arc::new(RwLock::new(HashMap::new()));
        {
            let user_id = Uuid::parse_str("cad8de7f-5507-48ef-9d4e-68939b4ade81").unwrap();
            let email = EmailAddress::new_unchecked("alexinicolaspeck@gmail.com");
            let debug_user: User = User::new(user_id, "Alexi Peck".to_string(), email.to_owned(), "$argon2id$v=19$m=2097152,t=1,p=1$RF5ndW4oU15VTHpnNFpRNHJmW30vRmoqU3lTPyxhRHE$Xl3u7HaK8/TMaukl0xTBwATjGkfHBS1GH8LHVILgkw".to_string(), "HX4IXEYSPJMHEG36YNEOQDPTKAUDF6YMFBDRCO3Z5LWXQGVO25KOTVWB2UOYWJFH".to_string());
            users.write().insert(*debug_user.get_id(), debug_user);
            email_to_id_registry.write().insert(email, user_id);
        }

        let encryption_keys = EncryptionKeys::new()?;
        Ok(Self {
            auth_lifetime: Duration::minutes(5),
            users,
            email_to_id_registry,

            regexes: Regexes::default(),
            config: Config::new(cookie_name, allowed_origin),
            encryption_keys,
        })
    }
}

impl AuthManager {
    pub fn setup_login_flow(&self, headers: &HeaderMap) -> Result<LoginFlow, Error> {
        let headers =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);

        let key: String = headers.hash_debug();
        let expiry = Utc::now() + self.auth_lifetime;
        let login_flow: LoginFlow = LoginFlow::new(key, expiry.to_owned());
        Ok(LoginFlow::new(
            Token::create_signed_and_encrypted(
                login_flow,
                expiry,
                self.encryption_keys.get_private_signing_key(),
                self.encryption_keys.get_symmetric_key(),
                self.encryption_keys.get_iv(),
            )?,
            expiry,
        ))
    }
    pub fn verify_login_flow(&self, token: String, headers: &HeaderMap) -> Result<(), Error> {
        let login_flow = Token::verify_and_decrypt::<LoginFlow>(
            &token,
            self.encryption_keys.get_public_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )?;
        let headers =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);

        let key: String = headers.hash_debug();
        if &key != login_flow.get_key() {
            return Err(InternalError::Login(LoginError::KeysDontMatch).into());
        }
        Ok(())
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
        self.email_to_id_registry
            .write()
            .insert(email, user.get_id().to_owned());
        self.users.write().insert(user.get_id().to_owned(), user);
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
