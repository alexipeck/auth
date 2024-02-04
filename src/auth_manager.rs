use crate::{
    cryptography::EncryptionKeys,
    database::{establish_connection, get_all_users, save_user, update_user},
    error::{
        AccountSetupError, AuthenticationError, Error, LoginError, ReadTokenAsRefreshTokenError,
        ReadTokenValidationError, StartupError, TokenError, WriteTokenValidationError,
    },
    filter_headers_into_btreeset,
    flows::user_setup::UserInvite,
    smtp_manager::SmtpManager,
    token::Token,
    user::{User, UserProfile, UserSafe},
    user_session::{ReadInternal, TokenMode, TokenPair, UserToken},
    MAX_SESSION_LIFETIME_SECONDS, READ_LIFETIME_SECONDS, REFRESH_IN_LAST_X_SECONDS,
    WRITE_LIFETIME_SECONDS,
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use peck_lib::{
    datetime::r#trait::Expired, hashing::r#trait::HashDebug, uid::authority::UIDAuthority,
};
use regex::RegexSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

pub struct Regexes {
    pub roaming_header_profile: RegexSet,
    pub restricted_header_profile: RegexSet,
}

impl Default for Regexes {
    fn default() -> Self {
        let mut keys = vec![
            /* "host", */
            "user-agent",
            /* "x-forwarded-host", */
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
    Read,
    Write,
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
    pub database_url: String,
    pub port: u16,

    uid_authority: Option<Arc<UIDAuthority>>,
}

impl AuthManager {
    pub async fn new(
        cookie_name: String,
        allowed_origin: String,
        smtp_server: String,
        smtp_sender_address: String,
        smtp_username: String,
        smtp_password: String,
        database_url: String,
        port: u16,
        uid_authority: Option<Arc<UIDAuthority>>,
    ) -> Result<Self, Error> {
        let allowed_origin: HeaderValue = match allowed_origin.parse() {
            Ok(allowed_origin) => allowed_origin,
            Err(err) => return Err(Error::Startup(StartupError::InvalidOrigin(err.into()))),
        };
        let users = get_all_users(&mut establish_connection(&database_url))?;
        if let Some(uid_authority) = uid_authority.as_ref() {
            uid_authority
                .insert_bulk(users.keys().map(|uid| *uid).collect::<Vec<Uuid>>())
                .await?;
        }
        let email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>> = Arc::new(RwLock::new(
            users
                .iter()
                .map(|(user_id, user)| (user.get_email().to_owned(), *user_id))
                .collect::<HashMap<EmailAddress, Uuid>>(),
        ));
        let users: Arc<RwLock<HashMap<Uuid, User>>> = Arc::new(RwLock::new(users));
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
            database_url,
            port,
            uid_authority,
        })
    }
}

impl AuthManager {
    pub fn setup_flow_with_lifetime<T: Serialize + DeserializeOwned>(
        &self,
        headers: &HeaderMap,
        r#type: FlowType,
        lifetime: Duration,
        data: T,
    ) -> Result<TokenPair, Error> {
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        self.setup_flow_with_expiry(headers, r#type, expiry, data)
    }

    pub fn setup_flow_with_expiry<T: Serialize + DeserializeOwned>(
        &self,
        headers: &HeaderMap,
        r#type: FlowType,
        expiry: DateTime<Utc>,
        data: T,
    ) -> Result<TokenPair, Error> {
        let headers =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);
        let key: String = headers.hash_debug();
        let flow: Flow<T> = Flow::new(key, r#type, data);
        self.create_signed_and_encrypted_token_with_expiry(flow, expiry)
    }

    pub async fn user_setup_incomplete(&self, user_id: &Uuid) -> Option<bool> {
        if let Some(user) = self.users.read().await.get(user_id) {
            return Some(user.incomplete());
        }
        None
    }

    pub fn verify_and_decrypt<T: Serialize + DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<(T, Option<DateTime<Utc>>), Error> {
        Token::verify_and_decrypt::<T>(
            token,
            self.encryption_keys.get_public_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )
    }

    pub async fn email_exists(&self, email: &EmailAddress) -> bool {
        for (_, user) in self.users.read().await.iter() {
            if user.get_email() == email {
                return true;
            }
        }
        return false;
    }

    pub fn generate_read_token(
        &self,
        headers: &HeaderMap,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<TokenPair, Error> {
        self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(
                TokenMode::Read(Box::new(ReadInternal::new(
                    filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile)
                        .hash_debug(),
                    session_id,
                    Duration::seconds(MAX_SESSION_LIFETIME_SECONDS),
                ))),
                user_id,
            ),
            Duration::seconds(READ_LIFETIME_SECONDS),
        )
    }

    pub fn generate_read_and_write_token(
        &self,
        headers: &HeaderMap,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<(TokenPair, TokenPair), Error> {
        let read_internal: ReadInternal = ReadInternal::new(
            filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile)
                .hash_debug(),
            session_id,
            Duration::seconds(MAX_SESSION_LIFETIME_SECONDS),
        );
        let write_internal: crate::user_session::WriteInternal =
            read_internal.generate_write_internal();
        let read_token: TokenPair = self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Read(Box::new(read_internal)), user_id),
            Duration::seconds(READ_LIFETIME_SECONDS),
        )?;
        let write_token: TokenPair = self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Write(Box::new(write_internal)), user_id),
            Duration::seconds(WRITE_LIFETIME_SECONDS),
        )?;
        Ok((read_token, write_token))
    }

    pub fn refresh_read_token(&self, token: &str, headers: &HeaderMap) -> Result<TokenPair, Error> {
        let (user_token, existing_expiry) = self.verify_and_decrypt::<UserToken>(token)?;
        let existing_expiry = match existing_expiry {
            Some(expiry) => expiry,
            None => return Err(Error::Token(TokenError::MissingExpiry)),
        };
        if existing_expiry.expired() {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::Expired,
            ));
        } else if existing_expiry.timestamp() - Utc::now().timestamp() > REFRESH_IN_LAST_X_SECONDS {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::NotUsedWithinValidRefreshPeriod,
            ));
        }
        let (user_id, mut token_mode) = user_token.extract();
        let expiry: DateTime<Utc>;
        if let TokenMode::Read(read_mode) = &mut token_mode {
            expiry = read_mode.upgrade(
                &filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile)
                    .hash_debug(),
            )?;
        } else {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::NotReadToken,
            ));
        };

        let user_token: UserToken = UserToken::new(token_mode, user_id);

        let t = self.create_signed_and_encrypted_token_with_expiry(user_token, expiry);
        if t.is_ok() {
            info!("Read token refreshed for user {}", user_id);
        }
        t
        //TODO: Add requirement for minimum number of expected headers to be present to prevent clients sending minimal headers
    }

    pub async fn generate_write_token(
        &self,
        read_token: &str,
        two_fa_code: String,
        headers: &HeaderMap,
    ) -> Result<TokenPair, Error> {
        let (user_id, read_internal) = self.validate_read_token(read_token, headers)?;
        if let Some(user) = self.users.read().await.get(&user_id) {
            user.validate_two_fa_code(&two_fa_code)?;
        } else {
            return Err(Error::Authentication(AuthenticationError::UserNotFound(
                user_id,
            )));
        }
        let write_internal: crate::user_session::WriteInternal =
            read_internal.generate_write_internal();
        self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Write(Box::new(write_internal)), user_id),
            Duration::seconds(WRITE_LIFETIME_SECONDS),
        )
        //TODO: Add requirement for minimum number of expected headers to be present to prevent clients sending minimal headers
    }

    pub fn verify_flow<T: Serialize + DeserializeOwned>(
        &self,
        token: &String,
        headers: &HeaderMap,
    ) -> Result<(T, Option<DateTime<Utc>>), Error> {
        let (flow, expiry): (Flow<T>, Option<DateTime<Utc>>) =
            self.verify_and_decrypt::<Flow<T>>(token)?;
        let headers: std::collections::BTreeMap<String, HeaderValue> =
            filter_headers_into_btreeset(headers, &self.regexes.restricted_header_profile);

        let key: String = headers.hash_debug();
        if &key != flow.get_header_key() {
            return Err(Error::Login(LoginError::HeaderKeysDontMatch));
        }
        Ok((flow.data, expiry))
    }

    pub async fn get_users_safe(&self) -> HashMap<Uuid, UserSafe> {
        self.users
            .read()
            .await
            .iter()
            .map(|(user_id, user)| (*user_id, user.to_safe()))
            .collect::<HashMap<Uuid, UserSafe>>()
    }

    pub async fn get_user_id_from_email(&self, email: &EmailAddress) -> Option<Uuid> {
        self.email_to_id_registry.read().await.get(email).cloned()
    }

    ///generates UUIDv4, if a UIDAuthority is available, this is guaranteed unique, otherwise is just generated using Uuid::new_v4()
    pub async fn generate_session_id(&self) -> Uuid {
        if let Some(uid_authority) = self.uid_authority.as_ref() {
            return uid_authority.generate_uid().await;
        }
        Uuid::new_v4()
    }

    ///generates UUIDv4, if a UIDAuthority is available, this is guaranteed globally unique across everything which utilises
    ///the authority for generation, otherwise is guaranteed unique across all currently registered users
    pub async fn generate_user_uid(&self) -> Uuid {
        if let Some(uid_authority) = self.uid_authority.as_ref() {
            return uid_authority.generate_uid().await;
        }
        loop {
            let uid = Uuid::new_v4();
            if self.users.read().await.contains_key(&uid) {
                continue;
            }
            return uid;
        }
    }

    pub fn create_signed_and_encrypted_token_with_lifetime<T: Serialize + DeserializeOwned>(
        &self,
        data: T,
        lifetime: Duration,
    ) -> Result<TokenPair, Error> {
        let expiry = Utc::now() + lifetime;
        self.create_signed_and_encrypted_token_with_expiry(data, expiry)
    }

    pub fn create_signed_and_encrypted_token_with_expiry<T: Serialize + DeserializeOwned>(
        &self,
        data: T,
        expiry: DateTime<Utc>,
    ) -> Result<TokenPair, Error> {
        Ok(TokenPair {
            token: Token::create_signed_and_encrypted(
                data,
                Some(expiry),
                self.encryption_keys.get_private_signing_key(),
                self.encryption_keys.get_symmetric_key(),
                self.encryption_keys.get_iv(),
            )?,
            expiry,
        })
    }

    pub fn create_signed_and_encrypted_token<T: Serialize + DeserializeOwned>(
        &self,
        data: T,
    ) -> Result<String, Error> {
        Token::create_signed_and_encrypted(
            data,
            None,
            self.encryption_keys.get_private_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            self.encryption_keys.get_iv(),
        )
    }

    pub async fn invite_user(&self, email: EmailAddress) -> Result<Uuid, Error> {
        let user_id: Uuid = self.generate_user_uid().await;
        let user: User = User::new(
            user_id,
            String::new(),
            email.to_owned(),
            String::new(),
            String::new(),
        );
        let token_pair = self.create_signed_and_encrypted_token_with_lifetime(
            UserInvite::new(email.to_owned(), user_id),
            Duration::minutes(600),
        )?;
        if let Err(err) = save_user(&mut establish_connection(&self.database_url), &user) {
            panic!("{}", err);
        }
        let _ = self.users.write().await.insert(user_id, user);
        self.email_to_id_registry
            .write()
            .await
            .insert(email, user_id);
        self.smtp_manager.send_email_to_recipient(
            "alexinicolaspeck@gmail.com".into(),
            "Invite Link".into(),
            format!(
                "http://dev.clouduam.com:81/invite?token={}",
                token_pair.token
            ), //https://clouduam.com
        )?;
        Ok(user_id)
    }

    pub async fn setup_user(
        &self,
        email: &EmailAddress,
        password: String,
        display_name: String,
        two_fa_client_secret: String,
    ) -> Result<(), Error> {
        let user_id: Uuid = match self.get_user_id_from_email(email).await {
            Some(user_id) => user_id,
            None => {
                return Err(Error::AccountSetup(
                    AccountSetupError::CouldntGetUserIDFromEmail,
                ))
            }
        };
        return if let Some(user) = self.users.write().await.get_mut(&user_id) {
            user.setup_user(password, display_name, two_fa_client_secret)?;
            if let Err(err) = update_user(&mut establish_connection(&self.database_url), user) {
                panic!("{}", err);
            }
            Ok(())
        } else {
            Err(Error::AccountSetup(AccountSetupError::UserNotFound(
                user_id,
            )))
        };
    }

    pub fn validate_read_token(
        &self,
        token: &str,
        headers: &HeaderMap,
    ) -> Result<(Uuid, ReadInternal), Error> {
        let (user_token, _) = self.verify_and_decrypt::<UserToken>(token)?;
        let (user_id, token_mode) = user_token.extract();
        if let TokenMode::Read(read_mode) = token_mode {
            if read_mode.get_headers_hash()
                != &filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile)
                    .hash_debug()
            {
                return Err(Error::ReadTokenValidation(
                    ReadTokenValidationError::InvalidHeaders,
                ));
            }
            Ok((user_id, *read_mode))
        } else {
            return Err(Error::ReadTokenValidation(
                ReadTokenValidationError::NotReadToken,
            ));
        }
    }

    pub fn validate_write_token(&self, token: &str, headers: &HeaderMap) -> Result<Uuid, Error> {
        let (read_token, write_token) = {
            let t: Vec<&str> = token.split(':').into_iter().collect::<Vec<&str>>();
            if t.len() != 2 {
                return Err(Error::BearerTokenPairInvalidFormat);
            }
            (t[0], t[1])
        };
        let (read_user_id, read_internal) = self.validate_read_token(read_token, headers)?;
        let (user_token, _) = self.verify_and_decrypt::<UserToken>(write_token)?;
        let (write_user_id, token_mode) = user_token.extract();
        if read_user_id != write_user_id {
            return Err(Error::WriteTokenValidation(
                WriteTokenValidationError::UserIDNotMatchCorrespondingRead,
            ));
        }
        if let TokenMode::Write(write_mode) = token_mode {
            if write_mode.get_headers_hash()
                != &filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile)
                    .hash_debug()
            {
                return Err(Error::WriteTokenValidation(
                    WriteTokenValidationError::InvalidHeaders,
                ));
            }
            if write_mode.get_session_id() != read_internal.get_session_id() {
                return Err(Error::WriteTokenValidation(
                    WriteTokenValidationError::WriteUIDNotMatchReadUID,
                ));
            }
        } else {
            return Err(Error::WriteTokenValidation(
                WriteTokenValidationError::NotWriteToken,
            ));
        }
        Ok(write_user_id)
    }

    pub async fn validate_user_credentials(
        &self,
        email: &EmailAddress,
        password: &String,
        two_fa_code: String,
    ) -> Result<UserProfile, Error> {
        match self.email_to_id_registry.read().await.get(email) {
            Some(user_id) => match self.users.read().await.get(user_id) {
                Some(user) => {
                    if user.incomplete() {
                        return Err(Error::Authentication(
                            AuthenticationError::AccountSetupIncomplete,
                        ));
                    }
                    match argon2::verify_encoded(
                        user.get_hashed_and_salted_password(),
                        password.as_bytes(),
                    ) {
                        Ok(verified) => {
                            if verified {
                                user.validate_two_fa_code(&two_fa_code)?;
                                Ok(user.to_user_profile())
                            } else {
                                Err(Error::Authentication(
                                    AuthenticationError::IncorrectCredentials,
                                ))
                            }
                        }
                        Err(err) => Err(Error::Authentication(
                            AuthenticationError::InvalidPasswordFormat(err),
                        )),
                    }
                }
                None => Err(Error::Authentication(
                    AuthenticationError::UserUIDNotRegisteredToEmail(email.to_owned()),
                )),
            },
            None => Err(Error::Authentication(
                AuthenticationError::EmailNotRegistered(email.to_owned()),
            )),
        }
    }
}
