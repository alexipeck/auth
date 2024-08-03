use crate::{
    auth_manager::AuthManager,
    error::{Error, ReadTokenAsRefreshTokenError},
};
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, Utc};
use peck_lib::auth::token_pair::TokenPair;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Client representation of their session, with read and write being their tokenised rights for read and write at any given time,
/// each with their own expiry with writes having much shorter expiry and requiring periodic upgrade using 2FA code to perform write actions

#[derive(Debug, Serialize /* Deserialize */)]
pub struct UserSession {
    read: TokenPair,
    write: Option<TokenPair>,
    session_id: Uuid,
}

impl UserSession {
    pub async fn create_read_write_from_user_id(
        user_id: Uuid,
        headers: &HeaderMap,
        auth_manager: Arc<AuthManager>,
    ) -> Result<(Self, DateTime<Utc>), Error> {
        let session_id = auth_manager.generate_session_id().await;
        let (read, write, latest_expiry): (TokenPair, TokenPair, DateTime<Utc>) =
            auth_manager.generate_read_and_write_token(headers, session_id, user_id)?;
        Ok((
            Self {
                read,
                write: Some(write),
                session_id,
            },
            latest_expiry,
        ))
    }
    pub async fn create_aligned_read_from_user_id(
        user_id: Uuid,
        headers: &HeaderMap,
        auth_manager: Arc<AuthManager>,
        expiry: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let session_id = auth_manager.generate_session_id().await;
        let read: TokenPair =
            auth_manager.generate_aligned_read_token(headers, session_id, user_id, expiry)?;
        Ok(Self {
            read,
            write: None,
            session_id,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteInternal {
    headers_hash: String,
    session_id: Uuid,
}

impl WriteInternal {
    pub fn new(headers_hash: String, session_id: Uuid) -> Self {
        Self {
            headers_hash,
            session_id,
        }
    }
    pub fn get_headers_hash(&self) -> &String {
        &self.headers_hash
    }
    pub fn get_session_id(&self) -> &Uuid {
        &self.session_id
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadInternal {
    headers_hash: String,
    session_id: Uuid,
    iteration: u32,
    session_start: DateTime<Utc>,
    iteration_limit: u32,
    latest_expiry: DateTime<Utc>,
}

impl ReadInternal {
    pub fn new(
        headers_hash: String,
        session_id: Uuid,
        max_lifetime: Duration,
        iteration_limit: u32,
    ) -> Self {
        let session_start: DateTime<Utc> = Utc::now();
        Self {
            headers_hash,
            session_id,
            iteration: 0,
            session_start,
            iteration_limit,
            latest_expiry: session_start + max_lifetime,
        }
    }
    pub fn get_session_id(&self) -> &Uuid {
        &self.session_id
    }
    pub fn get_latest_expiry(&self) -> &DateTime<Utc> {
        &self.latest_expiry
    }
    pub fn generate_write_internal(&self) -> WriteInternal {
        WriteInternal {
            headers_hash: self.headers_hash.to_owned(),
            session_id: self.session_id,
        }
    }
    pub fn upgrade(
        &mut self,
        headers_hash: &String,
        read_lifetime_seconds: i64,
    ) -> Result<DateTime<Utc>, Error> {
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
                Utc::now() + Duration::seconds(read_lifetime_seconds);
            if proposed_expiry > self.latest_expiry {
                tracing::debug!("Read token expiry truncated to latest_expiry");
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
}

impl UserToken {
    pub fn new(token_mode: TokenMode, user_id: Uuid) -> Self {
        Self {
            user_id,
            token_mode,
        }
    }

    pub fn extract(self) -> (Uuid, TokenMode) {
        (self.user_id, self.token_mode)
    }

    pub fn get_user_id(&self) -> &Uuid {
        &self.user_id
    }
}
