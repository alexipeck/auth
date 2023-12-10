use crate::serde::datetime_utc;
use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct LoginFlow {
    token: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>, //only needed for the client, actual expiry is handled within token and verify_and_decrypt()
    public_encryption_key: String,
}

impl LoginFlow {
    pub fn new(token: String, expiry: DateTime<Utc>, public_encryption_key: String) -> Self {
        Self {
            token,
            expiry,
            public_encryption_key,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginCredentials {
    pub email: EmailAddress,
    pub password: String,
    pub two_fa_code: String,
}

#[derive(Debug, Deserialize)]
pub struct UserLogin {
    pub key: String,
    pub encrypted_credentials: String,
}
