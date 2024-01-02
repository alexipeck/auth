use chrono::{DateTime, Utc};
use peck_lib::datetime::serde::datetime_utc;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct UserAuthenticated {
    token: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}
