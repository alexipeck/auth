use std::fmt;

use crate::error::Error;
use crate::error::{Base64DecodeError, FromUtf8Error, OpenSSLError, SerdeError, TokenError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
    symm::{decrypt, encrypt, Cipher},
};
use peck_lib::datetime::r#trait::Expired;
use peck_lib::datetime::serde::datetime_utc_option;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    RSA,
    RSASHA256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RSA => "RSA",
                Self::RSASHA256 => "RSA-SHA256",
            }
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Header {
    alg: Algorithm,
}

impl Header {
    pub fn signed_encrypted() -> Self {
        Self {
            alg: Algorithm::RSASHA256,
        }
    }
    pub fn signed() -> Self {
        Self {
            alg: Algorithm::RSA,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenWrapper<T> {
    pub data: T,
    #[serde(with = "datetime_utc_option")]
    pub expiry: Option<DateTime<Utc>>,
    pub _salt: Uuid,
    pub __salt: Uuid,
}

#[derive(Debug, Clone)]
pub struct Token {}

impl Token {
    pub fn create_signed_expiry<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: DateTime<Utc>,
        private_signing_key: &PKey<Private>,
    ) -> Result<String, Error> {
        let serialised_data_base64: String = {
            let data: TokenWrapper<T> = TokenWrapper {
                data,
                expiry: Some(expiry),
                _salt: Uuid::new_v4(),
                __salt: Uuid::new_v4(),
            };
            let serialised_data: String = match serde_json::to_string(&data) {
                Ok(serialised_data) => serialised_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&serialised_data)
        };
        let header_base64 = {
            let header_str = match serde_json::to_string(&Header::signed()) {
                Ok(header_str) => header_str,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&header_str)
        };
        let signature_base64 = {
            let mut signer = match Signer::new(MessageDigest::sha256(), private_signing_key) {
                Ok(signer) => signer,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::CreateSigner(OpenSSLError(err))));
                }
            };
            if let Err(err) = signer.update(header_base64.as_bytes()) {
                warn!("{}", err);
                return Err(Error::Token(TokenError::FeedSigner(OpenSSLError(err))));
            }
            if let Err(err) = signer.update(serialised_data_base64.as_bytes()) {
                warn!("{}", err);
                return Err(Error::Token(TokenError::FeedSigner(OpenSSLError(err))));
            }
            let signature = match signer.sign_to_vec() {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::FinaliseSignature(OpenSSLError(
                        err,
                    ))));
                }
            };
            URL_SAFE_NO_PAD.encode(&signature)
        };
        Ok(format!(
            "{}.{}.{}",
            header_base64, serialised_data_base64, signature_base64
        ))
    }
    pub fn create_signed_and_encrypted_lifetime<T: Serialize + DeserializeOwned>(
        data: T,
        lifetime: Duration,
        private_signing_key: &PKey<Private>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<String, Error> {
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        Self::create_signed_and_encrypted(
            data,
            Some(expiry),
            private_signing_key,
            symmetric_key,
            iv,
        )
    }
    pub fn create_signed_and_encrypted<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: Option<DateTime<Utc>>,
        private_signing_key: &PKey<Private>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<String, Error> {
        let encrypted_data_base64: String = {
            let data: TokenWrapper<T> = TokenWrapper {
                data,
                expiry,
                _salt: Uuid::new_v4(),
                __salt: Uuid::new_v4(),
            };
            let serialised_data: String = match serde_json::to_string(&data) {
                Ok(serialised_data) => serialised_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };
            let encrypted_data: Vec<u8> = match encrypt(
                Cipher::aes_256_cbc(),
                symmetric_key,
                Some(iv),
                serialised_data.as_bytes(),
            ) {
                Ok(encrypted_data) => encrypted_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataEncryption(OpenSSLError(err))).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&encrypted_data)
        };
        let header_base64: String = {
            let header_str: String = match serde_json::to_string(&Header::signed_encrypted()) {
                Ok(header_str) => header_str,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&header_str)
        };
        let signature_base64: String = {
            let mut signer = match Signer::new(MessageDigest::sha256(), private_signing_key) {
                Ok(signer) => signer,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::CreateSigner(OpenSSLError(err))).into());
                }
            };
            if let Err(err) = signer.update(header_base64.as_bytes()) {
                warn!("{}", err);
                return Err(Error::Token(TokenError::FeedSigner(OpenSSLError(err))));
            }
            if let Err(err) = signer.update(encrypted_data_base64.as_bytes()) {
                warn!("{}", err);
                return Err(Error::Token(TokenError::FeedSigner(OpenSSLError(err))));
            }
            let signature: Vec<u8> = match signer.sign_to_vec() {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::FinaliseSignature(OpenSSLError(
                        err,
                    ))));
                }
            };
            URL_SAFE_NO_PAD.encode(&signature)
        };
        Ok(format!(
            "{}.{}.{}",
            header_base64, encrypted_data_base64, signature_base64
        ))
    }
    pub fn verify_and_decrypt<T: Serialize + DeserializeOwned>(
        token: &str,
        public_signing_key: &PKey<Public>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<(T, Option<DateTime<Utc>>), Error> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            println!("{:?}", parts);
            return Err(Error::Token(TokenError::InvalidFormatForDecoding));
        }

        //Header validation
        {
            let header_str_bytes: Vec<u8> = match URL_SAFE_NO_PAD.decode(parts[0]) {
                Ok(header_str_bytes) => header_str_bytes,
                Err(err) => {
                    return Err(Error::Token(TokenError::HeaderBase64Decode(
                        Base64DecodeError(err),
                    )))
                }
            };
            let header: Header = match serde_json::from_slice(&header_str_bytes) {
                Ok(header) => header,
                Err(err) => {
                    return Err(Error::Token(TokenError::HeaderDeserialisation(SerdeError(
                        err,
                    ))))
                }
            };
            if header.alg != Algorithm::RSASHA256 {
                return Err(Error::Token(TokenError::HeadedUnexpectedAlgorithm));
            }
            drop(header);
            drop(header_str_bytes);
        }

        //Signature verification
        {
            let signature_bytes: Vec<u8> = match URL_SAFE_NO_PAD.decode(parts[2]) {
                Ok(signature_bytes) => signature_bytes,
                Err(err) => {
                    return Err(Error::Token(TokenError::SignatureBase64Decode(
                        Base64DecodeError(err),
                    )))
                }
            };
            let mut verifier: Verifier<'_> =
                match Verifier::new(MessageDigest::sha256(), public_signing_key) {
                    Ok(verifier) => verifier,
                    Err(err) => {
                        return Err(
                            Error::Token(TokenError::CreateVerifier(OpenSSLError(err))).into()
                        )
                    }
                };
            if let Err(err) = verifier.update(parts[0].as_bytes()) {
                return Err(Error::Token(TokenError::FeedVerifier(OpenSSLError(err))).into());
            }
            if let Err(err) = verifier.update(parts[1].as_bytes()) {
                return Err(Error::Token(TokenError::FeedVerifier(OpenSSLError(err))).into());
            }
            let verified: bool = match verifier.verify(&signature_bytes) {
                Ok(verified) => verified,
                Err(err) => {
                    return Err(
                        Error::Token(TokenError::FinaliseVerifier(OpenSSLError(err))).into(),
                    )
                }
            };
            if !verified {
                return Err(Error::Token(TokenError::SignatureVerificationFailed));
            }
        }

        let encrypted_payload: Vec<u8> = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(encrypted_payload) => encrypted_payload,
            Err(err) => {
                return Err(Error::Token(TokenError::PayloadBase64Decode(
                    Base64DecodeError(err),
                )))
            }
        };

        let cipher: Cipher = Cipher::aes_256_cbc();
        let decrypted_data: Vec<u8> =
            match decrypt(cipher, symmetric_key, Some(iv), &encrypted_payload) {
                Ok(decrypted_data) => decrypted_data,
                Err(err) => {
                    return Err(Error::Token(TokenError::DataDecryption(OpenSSLError(err))).into())
                }
            };

        let decrypted_data_str: String = match String::from_utf8(decrypted_data) {
            Ok(decrypted_data_str) => decrypted_data_str,
            Err(err) => {
                return Err(Error::Token(TokenError::DataBytesToString(FromUtf8Error(err))).into())
            }
        };

        let decrypted_data_struct: TokenWrapper<T> =
            match serde_json::from_str::<TokenWrapper<T>>(&decrypted_data_str) {
                Ok(decrypted_data_struct) => decrypted_data_struct,
                Err(err) => {
                    return Err(
                        Error::Token(TokenError::DataDeserialisation(SerdeError(err))).into(),
                    )
                }
            };

        if let Some(expiry) = decrypted_data_struct.expiry {
            if expiry.expired() {
                return Err(Error::Token(TokenError::Expired));
            }
        }

        Ok((decrypted_data_struct.data, decrypted_data_struct.expiry))
    }
}
