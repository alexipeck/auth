use email_address::EmailAddress;
use peck_lib::auth::token_pair::TokenPair;
pub use rsa::RsaPublicKey;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Serialize)]
pub struct LoginFlow {
    token_pair: TokenPair,
    public_encryption_key: RsaPublicKey,
}

impl LoginFlow {
    pub fn new(token_pair: TokenPair, public_encryption_key: RsaPublicKey) -> Self {
        Self {
            token_pair,
            public_encryption_key,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginCredentials {
    pub email: EmailAddress,
    pub password: String,
    #[serde(rename = "twoFACode")]
    pub two_fa_code: SixDigitString,
}

#[derive(Serialize, Debug)]
pub struct SixDigitString(pub String);

impl TryFrom<String> for SixDigitString {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 6 && value.chars().all(|c| c.is_digit(10)) {
            Ok(SixDigitString(value))
        } else {
            Err("Input String must be a 6-digit number")
        }
    }
}

impl<'de> Deserialize<'de> for SixDigitString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        SixDigitString::try_from(s).map_err(serde::de::Error::custom)
    }
}
