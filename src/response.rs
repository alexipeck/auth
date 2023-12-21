use crate::serde::datetime_utc;
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct UserAuthenticated {
    token: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}
