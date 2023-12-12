use crate::{error::Error, token::Token};
use chrono::{DateTime, Duration, Utc};
use core::fmt;
use openssl::pkey::{PKey, Private};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Client representation of their session, with read and write being their tokenised rights for read and write at any given time,
/// each with their own expiry with writes having much shorter expiry and requiring periodic upgrade using 2FA code to perform write actions
#[derive(Debug, Serialize, /* Deserialize */)]
pub struct UserSession {
    read_token: String,
    read_expiry: DateTime<Utc>,
    write_token: String,
    write_expiry: DateTime<Utc>,
}

impl UserSession {
    pub fn create_from_user_id(
        user_id: Uuid,
        private_key: &PKey<Private>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<Self, Error> {
        let read_expiry: DateTime<Utc> = Utc::now() + Duration::seconds(90);
        let write_expiry: DateTime<Utc> = Utc::now() + Duration::minutes(1);
        let read_token: String = Token::create_signed_and_encrypted(
            UserAccessToken::new(AccessLevel::Read, user_id),
            read_expiry.to_owned(),
            private_key,
            symmetric_key,
            iv,
        )?;
        let write_token: String = Token::create_signed_and_encrypted(
            UserAccessToken::new(AccessLevel::Write, user_id),
            write_expiry.to_owned(),
            private_key,
            symmetric_key,
            iv,
        )?;
        Ok(Self {
            read_token,
            read_expiry,
            write_token,
            write_expiry,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AccessLevel {
    Read,
    Write,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Read => "Read",
                Self::Write => "Write",
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserAccessToken {
    access_level: AccessLevel,
    user_id: Uuid,
    _salt: Uuid,
    __salt: Uuid,
}

impl UserAccessToken {
    pub fn new(access_level: AccessLevel, user_id: Uuid) -> Self {
        Self {
            access_level,
            user_id,
            _salt: Uuid::new_v4(),
            __salt: Uuid::new_v4(),
        }
    }
}
