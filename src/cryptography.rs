use std::{fs, str::from_utf8};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openssl::{
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
};
use peck_lib::crypto::prepare_rng;
use rand::Rng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::warn;

use crate::error::{
    Base64DecodeError, ClientPayloadError, EncryptionError, Error, FromUtf8Error, OpenSSLError,
    SerdeError, StdIoError, TomlDeError, TomlSerError, Utf8Error,
};

pub const TOKEN_CHARSET: [char; 88] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+',
    '{', '}', '[', ']', '|', '\\', '/', '?', '>', '.', '<', ',',
];

pub fn generate_token(length: usize) -> String {
    let mut rng = prepare_rng();
    let mut key = String::with_capacity(length);
    for _ in 0..length {
        key.push(TOKEN_CHARSET[rng.gen_range(0..TOKEN_CHARSET.len())]);
    }
    key
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptionKeysModel {
    pub signing_private_key: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub symmetric_key: [u8; 32], // 256-bit key for AES-256
    pub iv: [u8; 16],            // 128-bit IV for AES
}

#[cfg(not(target_os = "windows"))]
pub struct EncryptionKeys {
    signing_private_key: PKey<Private>,
    signing_public_key: PKey<Public>,
    private_key: PKey<Private>,
    public_key: PKey<Public>,
    symmetric_key: [u8; 32], // 256-bit key for AES-256
    iv: [u8; 16],            // 128-bit IV for AES
}

impl EncryptionKeys {
    pub fn new() -> Result<Self, Error> {
        let (public_key, private_key) = Self::generate_asymmetric_keys()?;
        let (signing_public_key, signing_private_key) = Self::generate_asymmetric_keys()?;
        Ok(Self {
            signing_private_key,
            signing_public_key,
            private_key,
            public_key,
            symmetric_key: rand::thread_rng().gen(),
            iv: rand::thread_rng().gen(),
        })
    }

    fn from_model(model: EncryptionKeysModel) -> Result<Self, Error> {
        let signing_private_key = match PKey::private_key_from_pem(&model.signing_private_key) {
            Ok(signing_private_key) => signing_private_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::SigningPrivateKeyFromPEM(OpenSSLError(err)),
                ))
            }
        };
        let signing_public_key = match PKey::public_key_from_pem(&model.signing_public_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::SigningPublicKeyFromPEM(
                    OpenSSLError(err),
                )))
            }
        };
        let private_key = match PKey::private_key_from_pem(&model.private_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::PrivateKeyFromPEM(
                    OpenSSLError(err),
                )))
            }
        };
        let public_key = match PKey::public_key_from_pem(&model.public_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::PublicKeyFromPEM(
                    OpenSSLError(err),
                )))
            }
        };
        Ok(Self {
            signing_private_key,
            signing_public_key,
            private_key,
            public_key,
            symmetric_key: model.symmetric_key,
            iv: model.iv,
        })
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), Error> {
        let signing_private_key = match self.signing_private_key.private_key_to_pem_pkcs8() {
            Ok(signing_private_key) => signing_private_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::ConvertSigningPrivateToPEMPKCS8(OpenSSLError(err)),
                ))
            }
        };
        let signing_public_key = match self.signing_public_key.public_key_to_pem() {
            Ok(signing_public_mey) => signing_public_mey,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::ConvertSigningPublicKeyToPEM(OpenSSLError(err)),
                ))
            }
        };
        let private_key = match self.private_key.private_key_to_pem_pkcs8() {
            Ok(private_key) => private_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::ConvertPrivateToPEMPKCS8(OpenSSLError(err)),
                ))
            }
        };
        let public_key = match self.public_key.public_key_to_pem() {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::ConvertPublicKeyToPEM(
                    OpenSSLError(err),
                )))
            }
        };
        let encryption_keys_model = EncryptionKeysModel {
            signing_private_key,
            signing_public_key,
            private_key,
            public_key,
            symmetric_key: self.symmetric_key.to_owned(),
            iv: self.iv.to_owned(),
        };
        let toml_string = match toml::to_string(&encryption_keys_model) {
            Ok(toml) => toml,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::ConvertModelToTOML(
                    TomlSerError(err),
                )))
            }
        };
        if let Err(err) = fs::write(path, toml_string) {
            return Err(Error::Encryption(EncryptionError::WriteTOMLToFile(
                StdIoError(err),
            )));
        }
        Ok(())
    }

    pub fn from_file(path: &str) -> Result<Self, Error> {
        let toml_string = match fs::read_to_string(path) {
            Ok(toml_string) => toml_string,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::ReadTOMLFromFile(
                    StdIoError(err),
                )))
            }
        };
        let encryption_keys_model = match toml::from_str::<EncryptionKeysModel>(&toml_string) {
            Ok(encryption_keys_model) => encryption_keys_model,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::ConvertTOMLToModel(
                    TomlDeError(err),
                )))
            }
        };
        Self::from_model(encryption_keys_model)
    }

    pub fn generate_asymmetric_keys() -> Result<(PKey<Public>, PKey<Private>), Error> {
        let rsa: Rsa<Private> = match Rsa::generate(2048) {
            Ok(rsa) => rsa,
            Err(err) => {
                return Err(
                    Error::Encryption(EncryptionError::GeneratingRSABase(OpenSSLError(err))).into(),
                )
            }
        };
        let private_key = match PKey::from_rsa(rsa.clone()) {
            Ok(private_key) => private_key,
            Err(err) => {
                return Err(
                    Error::Encryption(EncryptionError::GeneratingRSAPrivate(OpenSSLError(err)))
                        .into(),
                )
            }
        };
        let public_key_pem: Vec<u8> = match rsa.public_key_to_pem() {
            Ok(public_key_pem) => public_key_pem,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::GeneratingRSAPublicPEM(
                    OpenSSLError(err),
                ))
                .into())
            }
        };
        let public_key = match PKey::public_key_from_pem(&public_key_pem) {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(
                    Error::Encryption(EncryptionError::GeneratingRSAPublic(OpenSSLError(err)))
                        .into(),
                )
            }
        };
        Ok((public_key, private_key))
    }

    pub fn get_private_signing_key(&self) -> &PKey<Private> {
        &self.signing_private_key
    }

    pub fn get_public_signing_key(&self) -> &PKey<Public> {
        &self.signing_public_key
    }

    pub fn get_public_encryption_key(&self) -> &PKey<Public> {
        &self.public_key
    }

    pub fn get_public_encryption_key_string(&self) -> Result<String, Error> {
        let public_pem_bytes = match self.public_key.public_key_to_pem() {
            Ok(public_pem_bytes) => public_pem_bytes,
            Err(err) => {
                warn!("{}", err);
                return Err(Error::Encryption(EncryptionError::PublicToPEMConversion(
                    OpenSSLError(err),
                ))
                .into());
            }
        };
        match from_utf8(&public_pem_bytes) {
            Ok(public_pem_str) => Ok(public_pem_str.to_string()),
            Err(err) => Err(
                Error::Encryption(EncryptionError::PublicPEMBytesToString(Utf8Error(err))).into(),
            ),
        }
    }

    pub fn get_private_decryption_key(&self) -> &PKey<Private> {
        &self.private_key
    }

    pub fn get_symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_key
    }

    pub fn get_iv(&self) -> &[u8; 16] {
        &self.iv
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonEncryptedDataWrapper {
    pub data: String,
}
#[cfg(not(target_os = "windows"))]
pub fn decrypt_url_safe_base64_with_private_key<T: DeserializeOwned>(
    encrypted_url_safe_base64_data: String,
    private_key: &PKey<Private>,
) -> Result<T, Error> {
    let encrypted_credentials_bytes: Vec<u8> =
        match URL_SAFE_NO_PAD.decode(encrypted_url_safe_base64_data) {
            Ok(encrypted_data_bytes) => encrypted_data_bytes,
            Err(err) => {
                return Err(
                    Error::ClientPayload(ClientPayloadError::UrlSafeBase64Decode(
                        Base64DecodeError(err),
                    ))
                    .into(),
                )
            }
        };
    let mut decrypted_data_buffer = vec![0; private_key.size()];

    let rsa_private = match private_key.rsa() {
        Ok(rsa_private) => rsa_private,
        Err(err) => {
            return Err(
                Error::Encryption(EncryptionError::RSAPrivateConversion(OpenSSLError(err))).into(),
            )
        }
    };
    let decrypted_data_len = match rsa_private.private_decrypt(
        &encrypted_credentials_bytes,
        &mut decrypted_data_buffer,
        Padding::PKCS1_OAEP,
    ) {
        Ok(decrypted_data_len) => decrypted_data_len,
        Err(err) => {
            return Err(
                Error::Encryption(EncryptionError::DataDecryption(OpenSSLError(err))).into(),
            )
        }
    };
    decrypted_data_buffer.truncate(decrypted_data_len);

    let decrypted_data_str: String = match String::from_utf8(decrypted_data_buffer) {
        Ok(decrypted_data_str) => decrypted_data_str,
        Err(err) => {
            return Err(
                Error::ClientPayload(ClientPayloadError::DataBytesToString(FromUtf8Error(err)))
                    .into(),
            )
        }
    };
    let decrypted_data_struct: T = match serde_json::from_str::<T>(&decrypted_data_str) {
        Ok(decrypted_data_struct) => decrypted_data_struct,
        Err(err) => {
            return Err(
                Error::ClientPayload(ClientPayloadError::DataDeserialisation(SerdeError(err)))
                    .into(),
            )
        }
    };

    Ok(decrypted_data_struct)
}
