use crate::error::{AuthenticationError, Error};
use aead::OsRng;
use email_address::EmailAddress;
use peck_lib::auth::{
    error::{RSAError, SerdeError},
    token_pair::TokenPair,
};
use rsa::Pkcs1v15Encrypt;
pub use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};

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
    pub two_fa_code: [u8; 6],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserLogin {
    pub key: String,
    pub encrypted_credentials: Vec<u8>,
}

impl UserLogin {
    pub fn new(
        login_flow_key: String,
        login_credentials: LoginCredentials,
        public_encryption_key: RsaPublicKey,
    ) -> Result<Self, Error> {
        let serialised_login_credentials = match serde_json::to_vec(&login_credentials) {
            Ok(serialised_login_credentials) => serialised_login_credentials,
            Err(err) => {
                return Err(Error::Authentication(
                    AuthenticationError::SerialisingLoginCredentials(SerdeError(err)),
                ))
            }
        };
        let encrypted_login_credentlais = match public_encryption_key.encrypt(
            &mut OsRng,
            Pkcs1v15Encrypt,
            &serialised_login_credentials,
        ) {
            Ok(encrypted_login_credentlais) => encrypted_login_credentlais,
            Err(err) => {
                return Err(Error::Authentication(
                    AuthenticationError::EncryptLoginCredentials(RSAError(err)),
                ))
            }
        };
        Ok(Self {
            key: login_flow_key,
            encrypted_credentials: encrypted_login_credentlais,
        })
    }
}
