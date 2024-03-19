use crate::error::{
    Base64DecodeError, Error, FromUtf8Error, SerdeError, SignatureError, TokenError,
};
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use cipher::generic_array::GenericArray;
use cipher::KeyInit;
use peck_lib::datetime::r#trait::Expired;
use peck_lib::datetime::serde::datetime_utc_option;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::SignerMut;
use rsa::signature::Verifier;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
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
}

#[derive(Debug, Clone)]
pub struct Token {}

impl Token {
    pub fn create_signed_expiry<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: DateTime<Utc>,
        signing_key: &mut SigningKey<Sha256>,
    ) -> Result<String, Error> {
        let serialised_data_base64: String = {
            let data: TokenWrapper<T> = TokenWrapper {
                data,
                expiry: Some(expiry),
                _salt: Uuid::new_v4(),
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
        let header_base64: String = {
            let header_str = match serde_json::to_string(&Header::signed()) {
                Ok(header_str) => header_str,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&header_str)
        };
        let signature_base64: String = {
            let mut data_to_hash: Vec<u8> = Vec::new();
            data_to_hash.extend_from_slice(header_base64.as_bytes());
            data_to_hash.extend_from_slice(serialised_data_base64.as_bytes());
            let signature: Signature = signing_key.sign(&data_to_hash);
            let signature_bytes: Box<[u8]> = signature.into();
            URL_SAFE_NO_PAD.encode(&signature_bytes)
        };
        Ok(format!(
            "{}.{}.{}",
            header_base64, serialised_data_base64, signature_base64
        ))
    }
    pub fn create_signed_and_encrypted_lifetime<T: Serialize + DeserializeOwned>(
        data: T,
        lifetime: Duration,
        signing_key: SigningKey<Sha256>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<String, Error> {
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        Self::create_signed_and_encrypted(data, Some(expiry), signing_key, symmetric_key, iv)
    }
    pub fn create_signed_and_encrypted<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: Option<DateTime<Utc>>,
        mut signing_key: SigningKey<Sha256>,
        symmetric_key: &[u8],
        iv: &[u8],
    ) -> Result<String, Error> {
        let encrypted_data_base64: String = {
            let data: TokenWrapper<T> = TokenWrapper {
                data,
                expiry,
                _salt: Uuid::new_v4(),
            };
            let serialised_data: String = match serde_json::to_string(&data) {
                Ok(serialised_data) => serialised_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };

            let cipher = Aes256Gcm::new(GenericArray::from_slice(&symmetric_key));

            let encrypted_data: Vec<u8> = match cipher
                .encrypt(GenericArray::from_slice(&iv), serialised_data.as_bytes())
            {
                Ok(encrypted_data) => encrypted_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataEncryption(err.to_string())).into());
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
            let mut data_to_hash: Vec<u8> = Vec::new();
            data_to_hash.extend_from_slice(header_base64.as_bytes());
            data_to_hash.extend_from_slice(encrypted_data_base64.as_bytes());
            let signature: Signature = signing_key.sign(&data_to_hash);
            URL_SAFE_NO_PAD.encode(&signature.to_string()) //Maybe wrong?
        };
        Ok(format!(
            "{}.{}.{}",
            header_base64, encrypted_data_base64, signature_base64
        ))
    }

    pub fn verify_and_decrypt<T: Serialize + DeserializeOwned>(
        token: &str,
        verifying_key: VerifyingKey<Sha256>,
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
            let signature: Signature = match Signature::try_from(signature_bytes.as_slice()) {
                Ok(signature) => signature,
                Err(err) => {
                    return Err(Error::Token(TokenError::ConvertingBytesToSignature(
                        SignatureError(err),
                    )))
                }
            };
            let mut data_to_hash: Vec<u8> = Vec::new();
            data_to_hash.extend_from_slice(parts[0].as_bytes());
            data_to_hash.extend_from_slice(parts[1].as_bytes());

            if let Err(err) = verifying_key.verify(&data_to_hash, &signature) {
                return Err(Error::Token(TokenError::SignatureVerificationFailed(
                    SignatureError(err),
                )));
            };
        }

        let encrypted_payload: Vec<u8> = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(encrypted_payload) => encrypted_payload,
            Err(err) => {
                return Err(Error::Token(TokenError::PayloadBase64Decode(
                    Base64DecodeError(err),
                )))
            }
        };
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&symmetric_key));
        let decrypted_data: Vec<u8> =
            match cipher.decrypt(GenericArray::from_slice(&iv), &*encrypted_payload) {
                Ok(decrypted_data) => decrypted_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataDecryption(err.to_string())).into());
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
