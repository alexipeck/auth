use crate::{
    auth_manager::AuthManager,
    error::{Error, ReadTokenAsRefreshTokenError},
    serde::datetime_utc,
    MAX_READ_ITERATIONS, READ_LIFETIME_SECONDS,
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;

/// Client representation of their session, with read and write being their tokenised rights for read and write at any given time,
/// each with their own expiry with writes having much shorter expiry and requiring periodic upgrade using 2FA code to perform write actions

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    pub token: String,
    #[serde(with = "datetime_utc")]
    pub expiry: DateTime<Utc>,
}

#[derive(Debug, Serialize /* Deserialize */)]
pub struct UserSession {
    read: TokenPair,
    write: TokenPair,
}

impl UserSession {
    pub fn create_from_user_id(
        user_id: Uuid,
        headers: HeaderMap,
        auth_manager: Arc<AuthManager>,
    ) -> Result<Self, Error> {
        let (read, write): (TokenPair, TokenPair) =
            auth_manager.generate_read_and_write_token(&headers, user_id)?;
        Ok(Self { read, write })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteInternal {
    pub headers_hash: String,
    pub uid: Uuid,
}

impl WriteInternal {
    pub fn get_headers_hash(&self) -> &String {
        &self.headers_hash
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadInternal {
    headers_hash: String,
    uid: Uuid,
    iteration: u32,
    session_start: DateTime<Utc>,
    iteration_limit: u32,
    latest_expiry: DateTime<Utc>,
}

impl ReadInternal {
    pub fn new(headers_hash: String, max_lifetime: Duration) -> Self {
        let session_start: DateTime<Utc> = Utc::now();
        Self {
            headers_hash,
            uid: Uuid::new_v4(),
            iteration: 0,
            session_start,
            iteration_limit: MAX_READ_ITERATIONS,
            latest_expiry: session_start + max_lifetime,
        }
    }
    pub fn get_uid(&self) -> &Uuid {
        &self.uid
    }
    pub fn generate_write_internal(&self) -> WriteInternal {
        WriteInternal {
            headers_hash: self.headers_hash.to_owned(),
            uid: self.uid,
        }
    }
    pub fn upgrade(&mut self, headers_hash: &String) -> Result<DateTime<Utc>, Error> {
        if &self.headers_hash != headers_hash {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::InvalidHeaders,
            ));
        }
        self.iteration += 1;
        if self.iteration >= self.iteration_limit {
            return Err(Error::ReadTokenAsRefreshToken(
                ReadTokenAsRefreshTokenError::HasHitIterationLimit,
            ));
        }
        let expiry: DateTime<Utc> = {
            let proposed_expiry: DateTime<Utc> =
                Utc::now() + Duration::seconds(READ_LIFETIME_SECONDS);
            if proposed_expiry > self.latest_expiry {
                debug!("Read token expiry truncated to latest_expiry");
                self.latest_expiry
            } else {
                proposed_expiry
            }
        };
        Ok(expiry)
    }

    pub fn get_headers_hash(&self) -> &String {
        &self.headers_hash
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenMode {
    Read(Box<ReadInternal>),
    Write(Box<WriteInternal>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserToken {
    user_id: Uuid,
    token_mode: TokenMode,
    _salt: Uuid,
    __salt: Uuid,
}

impl UserToken {
    pub fn new(token_mode: TokenMode, user_id: Uuid) -> Self {
        Self {
            user_id,
            token_mode,
            _salt: Uuid::new_v4(),
            __salt: Uuid::new_v4(),
        }
    }

    pub fn extract(self) -> (Uuid, TokenMode) {
        (self.user_id, self.token_mode)
    }

    pub fn get_user_id(&self) -> &Uuid {
        &self.user_id
    }
}
