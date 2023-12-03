use crate::serde::datetime_utc;
use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct UserInvite {
    email: EmailAddress,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
    _salt: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFlow {
    key: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

impl LoginFlow {
    pub fn new(key: String, expiry: DateTime<Utc>) -> Self {
        Self { key, expiry }
    }

    pub fn get_key(&self) -> &String {
        &self.key
    }

    pub fn get_expiry(&self) -> &DateTime<Utc> {
        &self.expiry
    }
}
