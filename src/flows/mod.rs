pub mod user_login;
pub mod user_setup;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Lifetime {
    pub lifetime_seconds: i64,
}
