use crate::error::{Error, ReadTokenAsRefreshTokenError};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteInternal {
    headers_hash: String,
    session_uid: Uuid,
}

impl WriteInternal {
    pub fn new(headers_hash: String, session_uid: Uuid) -> Self {
        Self {
            headers_hash,
            session_uid,
        }
    }
    pub fn get_headers_hash(&self) -> &String {
        &self.headers_hash
    }
    pub fn get_session_uid(&self) -> &Uuid {
        &self.session_uid
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadInternal {
    headers_hash: String,
    session_uid: Uuid,
    iteration: u32,
    session_start: DateTime<Utc>,
    iteration_limit: u32,
    latest_expiry: DateTime<Utc>,
}

impl ReadInternal {
    pub fn new(
        headers_hash: String,
        session_uid: Uuid,
        max_lifetime: Duration,
        iteration_limit: u32,
    ) -> Self {
        let session_start: DateTime<Utc> = Utc::now();
        Self {
            headers_hash,
            session_uid,
            iteration: 0,
            session_start,
            iteration_limit,
            latest_expiry: session_start + max_lifetime,
        }
    }
    pub fn get_session_uid(&self) -> &Uuid {
        &self.session_uid
    }
    pub fn get_latest_expiry(&self) -> &DateTime<Utc> {
        &self.latest_expiry
    }
    pub fn generate_write_internal(&self) -> WriteInternal {
        WriteInternal {
            headers_hash: self.headers_hash.to_owned(),
            session_uid: self.session_uid,
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
    user_uid: Uuid,
    token_mode: TokenMode,
}

impl UserToken {
    pub fn new(token_mode: TokenMode, user_uid: Uuid) -> Self {
        Self {
            user_uid,
            token_mode,
        }
    }

    pub fn extract(self) -> (Uuid, TokenMode) {
        (self.user_uid, self.token_mode)
    }

    pub fn get_user_uid(&self) -> &Uuid {
        &self.user_uid
    }
}
