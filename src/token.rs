use crate::error::{Base64DecodeError, DecodeError, Error, SignatureError, TokenError};
use aead::{AeadCore, Nonce, OsRng};
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use cipher::generic_array::GenericArray;
use cipher::KeyInit;
use peck_lib::auth::error::SerdeError;
use peck_lib::datetime::r#trait::Expired;
use peck_lib::datetime::serde::datetime_utc_option;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::SignerMut;
use rsa::signature::Verifier;
use serde::de::{self, DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
struct TokenInnerInner<T> {
    pub data: T,
    #[serde(with = "datetime_utc_option")]
    pub expiry: Option<DateTime<Utc>>,
    pub _salt: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct NonceAes256Gcm(Nonce<Aes256Gcm>);

impl Serialize for NonceAes256Gcm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0.as_slice()))
    }
}

impl<'de> Deserialize<'de> for NonceAes256Gcm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BinaryDataVisitor;

        impl<'de> Visitor<'de> for BinaryDataVisitor {
            type Value = NonceAes256Gcm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a base64 encoded string representing Nonce<Aes256Gcm>")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match URL_SAFE_NO_PAD.decode(value) {
                    Ok(bytes) => Ok(NonceAes256Gcm(*Nonce::<Aes256Gcm>::from_slice(&bytes))),
                    Err(e) => Err(E::custom(format!("base64 decode error: {}", e))),
                }
            }
        }

        deserializer.deserialize_str(BinaryDataVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TokenInner {
    ///serialised_data
    RSASigned(String),
    ///(encrypted_data_base64, nonce/iv): (String, Nonce<Aes256Gcm>)
    RSASignedSHA265Encrypted(String, NonceAes256Gcm),
}

#[derive(Debug, Clone)]
pub struct SignatureWrapper(Signature);

impl Serialize for SignatureWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let signature_bytes: Box<[u8]> = self.0.to_owned().into();

        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&signature_bytes))
    }
}

impl<'de> Deserialize<'de> for SignatureWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BinaryDataVisitor;

        impl<'de> Visitor<'de> for BinaryDataVisitor {
            type Value = SignatureWrapper;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a base64 encoded string representing rsa::pkcs1v15::signature::Signature",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match URL_SAFE_NO_PAD.decode(value) {
                    Ok(bytes) => match Signature::try_from(bytes.as_slice()) {
                        Ok(signature) => Ok(SignatureWrapper(signature)),
                        Err(err) => {
                            return Err(E::custom(Error::Token(
                                TokenError::ConvertingBytesToSignature(SignatureError(err)),
                            )))
                        }
                    },
                    Err(e) => Err(E::custom(format!("base64 decode error: {}", e))),
                }
            }
        }

        deserializer.deserialize_str(BinaryDataVisitor)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Token {
    /* pub alg: Algorithm, */
    pub inner: TokenInner,
    pub signature: SignatureWrapper,
}

impl Token {
    pub fn from_str(value: &str) -> Result<Self, Error> {
        let serialised_data = match URL_SAFE_NO_PAD.decode(value) {
            Ok(token) => token,
            Err(err) => {
                return Err(Error::Token(TokenError::DecodeURLSafeBase64(DecodeError(
                    err,
                ))))
            }
        };
        match serde_json::from_slice::<Self>(&serialised_data) {
            Ok(token) => Ok(token),
            Err(err) => Err(Error::Token(TokenError::DataDeserialisation(SerdeError(
                err,
            )))),
        }
    }
    pub fn to_string(&self) -> Result<String, Error> {
        let serialised_data = match serde_json::to_vec(self) {
            Ok(serialised_data) => serialised_data,
            Err(err) => return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err)))),
        };
        Ok(URL_SAFE_NO_PAD.encode(&serialised_data))
    }
    pub fn create_signed<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: Option<DateTime<Utc>>,
        signing_key: &mut SigningKey<Sha256>,
        salted: bool,
    ) -> Result<String, Error> {
        let serialised_data_base64: String = {
            let data: TokenInnerInner<T> = TokenInnerInner {
                data,
                expiry,
                _salt: if salted { Some(Uuid::new_v4()) } else { None },
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
        let signature: Signature = signing_key.sign(&serialised_data_base64.as_bytes());
        Ok(Self {
            inner: TokenInner::RSASigned(serialised_data_base64),
            signature: SignatureWrapper(signature),
        }
        .to_string()?)
    }
    pub fn create_signed_and_encrypted_lifetime<T: Serialize + DeserializeOwned>(
        data: T,
        lifetime: Duration,
        signing_key: SigningKey<Sha256>,
        symmetric_key: &[u8],
        salted: bool,
    ) -> Result<String, Error> {
        let expiry: DateTime<Utc> = Utc::now() + lifetime;
        Self::create_signed_and_encrypted(data, Some(expiry), signing_key, symmetric_key, salted)
    }

    pub fn create_signed_and_encrypted<T: Serialize + DeserializeOwned>(
        data: T,
        expiry: Option<DateTime<Utc>>,
        mut signing_key: SigningKey<Sha256>,
        symmetric_key: &[u8],
        salted: bool,
    ) -> Result<String, Error> {
        let nonce: Nonce<Aes256Gcm> = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted_data_base64: String = {
            let data: TokenInnerInner<T> = TokenInnerInner {
                data,
                expiry,
                _salt: if salted { Some(Uuid::new_v4()) } else { None },
            };
            let serialised_data: String = match serde_json::to_string(&data) {
                Ok(serialised_data) => serialised_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataSerialisation(SerdeError(err))).into());
                }
            };

            let cipher = Aes256Gcm::new(GenericArray::from_slice(&symmetric_key));
            let encrypted_data: Vec<u8> = match cipher.encrypt(&nonce, serialised_data.as_bytes()) {
                Ok(encrypted_data) => encrypted_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(Error::Token(TokenError::DataEncryption(err.to_string())).into());
                }
            };
            URL_SAFE_NO_PAD.encode(&encrypted_data)
        };
        let signature = signing_key.sign(encrypted_data_base64.as_bytes());
        Ok(Self {
            inner: TokenInner::RSASignedSHA265Encrypted(
                encrypted_data_base64,
                NonceAes256Gcm(nonce),
            ),
            signature: SignatureWrapper(signature),
        }
        .to_string()?)
    }

    pub fn verify_and_decrypt<T: Serialize + DeserializeOwned>(
        &self,
        verifying_key: VerifyingKey<Sha256>,
        symmetric_key: &[u8],
    ) -> Result<(T, Option<DateTime<Utc>>), Error> {
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&symmetric_key));
        let deserialised_data_struct = match &self.inner {
            TokenInner::RSASigned(serialised_data) => {
                if let Err(err) =
                    verifying_key.verify(serialised_data.as_bytes(), &self.signature.0)
                {
                    return Err(Error::Token(TokenError::SignatureVerificationFailed(
                        SignatureError(err),
                    )));
                };
                let deserialised_data_struct: TokenInnerInner<T> =
                    match serde_json::from_str::<TokenInnerInner<T>>(&serialised_data) {
                        Ok(decrypted_data_struct) => decrypted_data_struct,
                        Err(err) => {
                            return Err(Error::Token(TokenError::DataDeserialisation(SerdeError(
                                err,
                            )))
                            .into())
                        }
                    };
                deserialised_data_struct
            }
            TokenInner::RSASignedSHA265Encrypted(encrypted_data_base64, nonce) => {
                if let Err(err) =
                    verifying_key.verify(encrypted_data_base64.as_bytes(), &self.signature.0)
                {
                    return Err(Error::Token(TokenError::SignatureVerificationFailed(
                        SignatureError(err),
                    )));
                };
                let encrypted_data = match URL_SAFE_NO_PAD.decode(encrypted_data_base64) {
                    Ok(encrypted_data) => encrypted_data,
                    Err(err) => {
                        return Err(Error::Token(TokenError::Base64Decode(Base64DecodeError(
                            err,
                        ))))
                    }
                };
                let decrypted_data: Vec<u8> = match cipher.decrypt(&nonce.0, &*encrypted_data) {
                    Ok(decrypted_data) => decrypted_data,
                    Err(err) => {
                        warn!("{}", err);
                        return Err(
                            Error::Token(TokenError::DataDecryption(err.to_string())).into()
                        );
                    }
                };
                let deserialised_data_struct: TokenInnerInner<T> =
                    match serde_json::from_slice::<TokenInnerInner<T>>(&decrypted_data) {
                        Ok(decrypted_data_struct) => decrypted_data_struct,
                        Err(err) => {
                            return Err(Error::Token(TokenError::DataDeserialisation(SerdeError(
                                err,
                            )))
                            .into())
                        }
                    };
                deserialised_data_struct
            }
        };
        if let Some(expiry) = deserialised_data_struct.expiry {
            if expiry.expired() {
                return Err(Error::Token(TokenError::Expired));
            }
        }

        Ok((
            deserialised_data_struct.data,
            deserialised_data_struct.expiry,
        ))
    }
}
