use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::serde::datetime_utc;

#[derive(Serialize, Deserialize)]
pub struct UserInvite {
    email: EmailAddress,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
    _salt: Uuid,
}
