use crate::{
    auth_server::RequiredProperties,
    cryptography::EncryptionKeys,
    database::{establish_connection, get_all_users, save_user, update_user},
    error::{
        AccountSetupError, AuthFlowError, AuthServerBuildError, AuthenticationError, Error,
        IdentityError, LoginError, ReadTokenAsRefreshTokenError, ReadTokenValidationError,
        StartupError, TokenError, WriteTokenValidationError,
    },
    filter_headers_into_btreeset,
    flows::user_setup::UserInvite,
    smtp_manager::SmtpManager,
    token::Token,
    user::{IdentityCookie, User, UserProfile, UserSafe},
    user_session::{ReadInternal, TokenMode, UserToken},
};
use axum::http::{HeaderMap, HeaderValue};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use peck_lib::{
    auth::token_pair::TokenPair, datetime::r#trait::Expired, hashing::r#trait::HashDebug,
    uid::authority::UIDAuthority,
};
use regex::RegexSet;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{info, warn};
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
            /* "x-forwarded-host", */
            "x-forwarded-proto",
            /* "x-forwarded-port", */
            /* "origin", */
            /* "sec-ch-ua", */
            /* "sec-ch-ua-mobile", */
            /* "sec-ch-ua-platform", */
            /* "sec-fetch-dest", */
            /* "sec-fetch-site", */
            /* "sec-fetch-mode", */
            "accept-language",
            /* "dnt", */
            /* "connection", */
            "accept-encoding",
        ];
        let roaming_header_profile = RegexSet::new(
            keys.iter()
                .map(|&key| format!(r"^{}$", regex::escape(key)))
                .collect::<Vec<String>>(),
        )
        .unwrap();
        keys.push("x-real-ip");
        keys.push("x-forwarded-for");
        keys.push("referer");
        let restricted_header_profile = RegexSet::new(
            keys.into_iter()
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
    cookie_name_base: String,
    allowed_origins: Vec<HeaderValue>,
    read_lifetime_seconds: i64,
    write_lifetime_seconds: i64,
    refresh_in_last_x_seconds: i64,
    max_session_lifetime_seconds: i64,
    max_read_iterations: u32,
    pub login_flow_lifetime_seconds: i64,
    pub invite_flow_lifetime_seconds: i64,
    pub invite_lifetime_seconds: i64,
}

impl Config {
    pub fn new(
        cookie_name_base: String,
        allowed_origins: Vec<HeaderValue>,
        read_lifetime_seconds: i64,
        write_lifetime_seconds: i64,
        refresh_in_last_x_seconds: i64,
        max_session_lifetime_seconds: i64,
        login_flow_lifetime_seconds: i64,
        invite_flow_lifetime_seconds: i64,
        invite_lifetime_seconds: i64,
    ) -> Self {
        Self {
            cookie_name_base,
            allowed_origins,
            read_lifetime_seconds,
            write_lifetime_seconds,
            refresh_in_last_x_seconds,
            max_session_lifetime_seconds,
            max_read_iterations: (max_session_lifetime_seconds
                / (read_lifetime_seconds - refresh_in_last_x_seconds))
                as u32,
            login_flow_lifetime_seconds,
            invite_flow_lifetime_seconds,
            invite_lifetime_seconds,
        }
    }
    pub fn get_cookie_name_base(&self) -> &str {
        &self.cookie_name_base
    }
    pub fn get_allowed_origin(&self) -> &Vec<HeaderValue> {
        &self.allowed_origins
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum FlowType {
    Login,
    Setup,
    Read,
    Write,
    Identity,
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
    pub cookie_domain: String, //Should include http:// or https://

    uid_authority: Option<Arc<UIDAuthority>>,
}

impl AuthManager {
    pub(crate) async fn new(
        cookie_name_base: String,
        allowed_origins: Vec<String>,
        smtp_server: String,
        smtp_sender_address: String,
        smtp_username: String,
        smtp_password: String,
        database_url: String,
        port: u16,
        cookie_domain: String,
        uid_authority: Option<Arc<UIDAuthority>>,
        persistent_encryption_keys_path: Option<String>,
        read_lifetime_seconds: i64,
        write_lifetime_seconds: i64,
        refresh_in_last_x_seconds: i64,
        max_session_lifetime_seconds: i64,
        login_flow_lifetime_seconds: i64,
        invite_flow_lifetime_seconds: i64,
        invite_lifetime_seconds: i64,
    ) -> Result<Self, Error> {
        if allowed_origins.is_empty() {
            return Err(Error::AuthServerBuild(
                AuthServerBuildError::MissingProperties(format!(
                    "{:?}",
                    RequiredProperties::AllowedOrigin
                )),
            ));
        }
        let mut allowed_origins_: Vec<HeaderValue> = Vec::new();
        for allowed_origin in allowed_origins.into_iter() {
            let allowed_origin_: HeaderValue = match allowed_origin.parse() {
                Ok(allowed_origin) => allowed_origin,
                Err(err) => {
                    return Err(Error::Startup(StartupError::InvalidOrigin(
                        err.into(),
                        allowed_origin,
                    )))
                }
            };
            allowed_origins_.push(allowed_origin_);
        }
        let users = get_all_users(&mut establish_connection(&database_url))?;
        if let Some(uid_authority) = uid_authority.as_ref() {
            uid_authority
                .insert_bulk(users.keys().copied().collect::<Vec<Uuid>>())
                .await?;
        }
        let email_to_id_registry: Arc<RwLock<HashMap<EmailAddress, Uuid>>> = Arc::new(RwLock::new(
            users
                .iter()
                .map(|(user_id, user)| (user.get_email().to_owned(), *user_id))
                .collect::<HashMap<EmailAddress, Uuid>>(),
        ));
        let users: Arc<RwLock<HashMap<Uuid, User>>> = Arc::new(RwLock::new(users));
        let encryption_keys: EncryptionKeys = match persistent_encryption_keys_path {
            Some(path) => {
                if !Path::new(&path).exists() {
                    let agent_encryption_keys: EncryptionKeys = EncryptionKeys::new()?;
                    agent_encryption_keys.save_to_file(&path)?;
                    agent_encryption_keys
                } else {
                    EncryptionKeys::from_file(&path)?
                }
            }
            None => {
                let encryption_keys = EncryptionKeys::new()?;
                info!("Auth server running in ephemeral key mode, they will not survive a server restart");
                encryption_keys
            }
        };
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
            config: Config::new(
                cookie_name_base,
                allowed_origins_,
                read_lifetime_seconds,
                write_lifetime_seconds,
                refresh_in_last_x_seconds,
                max_session_lifetime_seconds,
                login_flow_lifetime_seconds,
                invite_flow_lifetime_seconds,
                invite_lifetime_seconds,
            ),
            encryption_keys,
            smtp_manager,
            database_url,
            port,
            cookie_domain,
            uid_authority,
        })
    }
}

impl AuthManager {
    pub fn get_read_lifetime_seconds(&self) -> i64 {
        self.config.read_lifetime_seconds.to_owned()
    }
    pub fn setup_flow_with_lifetime<T: Serialize + DeserializeOwned>(
        &self,
        headers: &HeaderMap,
        r#type: FlowType,
        lifetime: Duration,
        restricted_header_profile: bool,
        data: T,
    ) -> Result<TokenPair, Error> {
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        self.setup_flow_with_expiry(headers, r#type, expiry, restricted_header_profile, data)
    }

    pub fn setup_flow_with_expiry<T: Serialize + DeserializeOwned>(
        &self,
        headers: &HeaderMap,
        r#type: FlowType,
        expiry: DateTime<Utc>,
        restricted_header_profile: bool,
        data: T,
    ) -> Result<TokenPair, Error> {
        let headers: BTreeMap<String, HeaderValue> = filter_headers_into_btreeset(
            headers,
            if restricted_header_profile {
                &self.regexes.restricted_header_profile
            } else {
                &self.regexes.roaming_header_profile
            },
        );
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
        let token: Token = Token::from_str(token)?;
        token.verify_and_decrypt::<T>(
            self.encryption_keys.get_verifying_key(),
            self.encryption_keys.get_symmetric_key(),
        )
    }

    pub async fn email_exists(&self, email: &EmailAddress) -> bool {
        for (_, user) in self.users.read().await.iter() {
            if user.get_email() == email {
                return true;
            }
        }
        false
    }

    pub fn generate_identity(
        &self,
        headers: &HeaderMap,
        user_id: &Uuid,
        expiry: DateTime<Utc>,
    ) -> Result<IdentityCookie, Error> {
        #[cfg(feature = "debug-logging")]
        tracing::debug!("Headers for generating identity {:?}", headers);
        let token = self
            .setup_flow_with_expiry(&headers, FlowType::Identity, expiry, false, *user_id)?
            .token;
        Ok(IdentityCookie {
            name: self.config.cookie_name_base.to_owned(),
            token,
            expiry,
        })
    }

    pub async fn validate_identity(
        &self,
        identity: &str,
        key: &str,
        headers: &HeaderMap,
    ) -> Result<(UserProfile, DateTime<Utc>), Error> {
        //TODO: Validate that key and identity headers are the same
        #[cfg(feature = "debug-logging")]
        tracing::debug!("Headers for validating identity {:?}", headers);
        let _ = match self.verify_flow::<Option<bool>>(&key, &headers, &FlowType::Login, true) {
            Ok(_) => {}
            Err(err) => {
                warn!("{err}");
                return Err(err);
            }
        };
        let (user_id, expiry) =
            match self.verify_flow::<Uuid>(identity, headers, &FlowType::Identity, false) {
                Ok(t) => t,
                Err(err) => {
                    warn!("{err}");
                    return Err(err);
                }
            };
        let expiry = match expiry {
            Some(expiry) => expiry,
            None => return Err(Error::Identity(IdentityError::MissingExpiry)),
        };
        let user_profile = match self.users.read().await.get(&user_id) {
            Some(user) => {
                if user.incomplete() {
                    return Err(Error::Authentication(
                        AuthenticationError::AccountSetupIncomplete,
                    ));
                }
                if user.disabled() {
                    return Err(Error::Authentication(AuthenticationError::Disabled));
                }
                user.to_user_profile()
            }
            None => {
                return Err(Error::Authentication(AuthenticationError::UserNotFound(
                    user_id,
                )))
            }
        };
        Ok((user_profile, expiry))
    }

    pub fn generate_aligned_read_token(
        &self,
        headers: &HeaderMap,
        session_id: Uuid,
        user_id: Uuid,
        expiry: DateTime<Utc>,
    ) -> Result<TokenPair, Error> {
        let headers: BTreeMap<String, HeaderValue> =
            filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile);
        self.create_signed_and_encrypted_token_with_expiry(
            UserToken::new(
                TokenMode::Read(Box::new(ReadInternal::new(
                    headers.hash_debug(),
                    session_id,
                    Duration::seconds(self.config.max_session_lifetime_seconds),
                    self.config.max_read_iterations,
                ))),
                user_id,
            ),
            expiry,
        )
    }

    pub fn generate_read_and_write_token(
        &self,
        headers: &HeaderMap,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<(TokenPair, TokenPair, DateTime<Utc>), Error> {
        let headers: BTreeMap<String, HeaderValue> =
            filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile);
        let read_internal: ReadInternal = ReadInternal::new(
            headers.hash_debug(),
            session_id,
            Duration::seconds(self.config.max_session_lifetime_seconds),
            self.config.max_read_iterations,
        );
        let latest_expiry: DateTime<Utc> = read_internal.get_latest_expiry().to_owned();
        let write_internal: crate::user_session::WriteInternal =
            read_internal.generate_write_internal();
        let read_token: TokenPair = self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Read(Box::new(read_internal)), user_id),
            Duration::seconds(self.config.read_lifetime_seconds),
        )?;
        let write_token: TokenPair = self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Write(Box::new(write_internal)), user_id),
            Duration::seconds(self.config.write_lifetime_seconds),
        )?;
        Ok((read_token, write_token, latest_expiry))
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
        } else if existing_expiry.timestamp() - Utc::now().timestamp()
            > self.config.refresh_in_last_x_seconds
        {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::NotUsedWithinValidRefreshPeriod,
            ));
        }
        let (user_id, mut token_mode) = user_token.extract();
        let expiry: DateTime<Utc>;
        let headers: BTreeMap<String, HeaderValue> =
            filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile);
        if let TokenMode::Read(read_mode) = &mut token_mode {
            expiry = read_mode.upgrade(&headers.hash_debug(), self.config.read_lifetime_seconds)?;
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
        two_fa_code: &[u8; 6],
        headers: &HeaderMap,
    ) -> Result<TokenPair, Error> {
        let (user_id, read_internal) = self.validate_read_token(read_token, headers)?;
        if let Some(user) = self.users.read().await.get(&user_id) {
            user.validate_two_fa_code(two_fa_code)?;
        } else {
            return Err(Error::Authentication(AuthenticationError::UserNotFound(
                user_id,
            )));
        }
        let write_internal: crate::user_session::WriteInternal =
            read_internal.generate_write_internal();
        self.create_signed_and_encrypted_token_with_lifetime(
            UserToken::new(TokenMode::Write(Box::new(write_internal)), user_id),
            Duration::seconds(self.config.write_lifetime_seconds),
        )
        //TODO: Add requirement for minimum number of expected headers to be present to prevent clients sending minimal headers
    }

    pub fn verify_flow<T: Serialize + DeserializeOwned>(
        &self,
        token: &str,
        headers: &HeaderMap,
        r#type: &FlowType,
        restricted_header_profile: bool,
    ) -> Result<(T, Option<DateTime<Utc>>), Error> {
        let (flow, expiry): (Flow<T>, Option<DateTime<Utc>>) =
            self.verify_and_decrypt::<Flow<T>>(token)?;
        if flow.get_type() != r#type {
            #[cfg(feature = "debug-logging")]
            tracing::debug!(
                "Flow is of type {:?} but is expecting {:?}.",
                flow.get_type(),
                r#type
            );
            return Err(Error::AuthFlow(AuthFlowError::IncorrectType));
        }
        let headers: std::collections::BTreeMap<String, HeaderValue> = filter_headers_into_btreeset(
            headers,
            if restricted_header_profile {
                &self.regexes.restricted_header_profile
            } else {
                &self.regexes.roaming_header_profile
            },
        );

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
                self.encryption_keys.get_signing_key(),
                self.encryption_keys.get_symmetric_key(),
                true,
            )?
            .to_string(),
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
            self.encryption_keys.get_signing_key(),
            self.encryption_keys.get_symmetric_key(),
            true,
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
            true,
        );
        let token_pair = self.create_signed_and_encrypted_token_with_lifetime(
            UserInvite::new(email.to_owned(), user_id),
            Duration::minutes(self.config.invite_lifetime_seconds),
        )?;
        if let Err(err) = save_user(&mut establish_connection(&self.database_url), &user) {
            panic!("{}", err);
        }
        let _ = self.users.write().await.insert(user_id, user);
        self.email_to_id_registry
            .write()
            .await
            .insert(email.to_owned(), user_id);
        self.smtp_manager.send_email_to_recipient(
            email.into(),
            "Invite Link".into(),
            format!("{}/invite?token={}", &self.cookie_domain, token_pair.token), //https://clouduam.com
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
        #[cfg(feature = "debug-logging")]
        tracing::debug!("Headers for validating read token {:?}", headers);
        let (user_token, _) = self.verify_and_decrypt::<UserToken>(token)?;
        let (user_id, token_mode) = user_token.extract();
        if let TokenMode::Read(read_mode) = token_mode {
            let headers =
                filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile);
            if read_mode.get_headers_hash() != &headers.hash_debug() {
                return Err(Error::ReadTokenValidation(
                    ReadTokenValidationError::InvalidHeaders,
                ));
            }
            Ok((user_id, *read_mode))
        } else {
            Err(Error::ReadTokenValidation(
                ReadTokenValidationError::NotReadToken,
            ))
        }
    }

    pub fn validate_write_token(&self, token: &str, headers: &HeaderMap) -> Result<Uuid, Error> {
        #[cfg(feature = "debug-logging")]
        tracing::debug!("Headers for validating write token {:?}", headers);
        let (read_token, write_token) = {
            let t: Vec<&str> = token.split(':').collect::<Vec<&str>>();
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
            let headers =
                filter_headers_into_btreeset(headers, &self.regexes.roaming_header_profile);
            if write_mode.get_headers_hash() != &headers.hash_debug() {
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
        two_fa_code: &[u8; 6],
    ) -> Result<UserProfile, Error> {
        match self.email_to_id_registry.read().await.get(email) {
            Some(user_id) => match self.users.read().await.get(user_id) {
                Some(user) => {
                    if user.incomplete() {
                        return Err(Error::Authentication(
                            AuthenticationError::AccountSetupIncomplete,
                        ));
                    }
                    if user.disabled() {
                        return Err(Error::Authentication(AuthenticationError::Disabled));
                    }
                    match argon2::verify_encoded(
                        user.get_hashed_and_salted_password(),
                        password.as_bytes(),
                    ) {
                        Ok(verified) => {
                            if verified {
                                user.validate_two_fa_code(two_fa_code)?;
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
