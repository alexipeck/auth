use crate::user_session::TokenPair;
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct LoginFlow {
    token_pair: TokenPair,
    public_encryption_key: String,
}

impl LoginFlow {
    pub fn new(token_pair: TokenPair, public_encryption_key: String) -> Self {
        Self {
            token_pair,
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
