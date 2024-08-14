use crate::error::{
    Base64DecodeError, ClientPayloadError, EncryptionError, Error, PKCS1Error, StdIoError,
    TomlDeError, TomlSerError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use peck_lib::{
    auth::error::{RSAError, SerdeError},
    crypto::prepare_rng,
};
use pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding,
};
use rand::Rng;
use rand_core::OsRng;
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::Keypair,
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;

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
    pub signing_private_key: String,
    pub signing_public_key: String,
    pub private_key: String,
    pub public_key: String,
    pub symmetric_key: [u8; 32], // 256-bit key for AES-256
}

pub struct EncryptionKeys {
    signing_private_key: RsaPrivateKey,
    signing_public_key: RsaPublicKey,
    signing_key: SigningKey<Sha256>,
    verifying_key: VerifyingKey<Sha256>,
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
    symmetric_key: [u8; 32], // 256-bit key for AES-256
}

impl EncryptionKeys {
    pub fn new() -> Result<Self, Error> {
        let (public_key, private_key) = Self::generate_asymmetric_keys()?;
        let (signing_public_key, signing_private_key) = Self::generate_asymmetric_keys()?;
        let signing_key = SigningKey::<Sha256>::new(signing_private_key.to_owned());
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_private_key,
            signing_public_key,
            signing_key,
            verifying_key,
            private_key,
            public_key,
            symmetric_key: rand::thread_rng().gen::<[u8; 32]>(),
        })
    }

    fn from_model(model: EncryptionKeysModel) -> Result<Self, Error> {
        let signing_private_key = match RsaPrivateKey::from_pkcs1_pem(&model.signing_private_key) {
            Ok(signing_private_key) => signing_private_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::SigningPrivateKeyFromPEMPKCS1(PKCS1Error(err)),
                ))
            }
        };
        let signing_public_key = match RsaPublicKey::from_pkcs1_pem(&model.signing_public_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::SigningPublicKeyFromPEMPKCS1(PKCS1Error(err)),
                ))
            }
        };
        let private_key = match RsaPrivateKey::from_pkcs1_pem(&model.private_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::PrivateKeyFromPEMPKCS1(
                    PKCS1Error(err),
                )))
            }
        };
        let public_key = match RsaPublicKey::from_pkcs1_pem(&model.public_key) {
            Ok(signing_public_key) => signing_public_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::PublicKeyFromPEMPKCS1(
                    PKCS1Error(err),
                )))
            }
        };
        let signing_key = SigningKey::<Sha256>::new(signing_private_key.to_owned());
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_private_key,
            signing_public_key,
            private_key,
            public_key,
            symmetric_key: model.symmetric_key,
            signing_key,
            verifying_key,
        })
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), Error> {
        let signing_private_key_pkcs1_pem =
            match self.signing_private_key.to_pkcs1_pem(LineEnding::LF) {
                Ok(signing_private_key_pkcs1_pem) => signing_private_key_pkcs1_pem.to_string(),
                Err(err) => {
                    return Err(Error::Encryption(
                        EncryptionError::ConvertSigningPrivateKeyToPEMPKCS1(PKCS1Error(err)),
                    ))
                }
            };
        let signing_public_key_pkcs1_pem =
            match self.signing_public_key.to_pkcs1_pem(LineEnding::LF) {
                Ok(signing_public_key_pkcs1_pem) => signing_public_key_pkcs1_pem,
                Err(err) => {
                    return Err(Error::Encryption(
                        EncryptionError::ConvertSigningPublicKeyToPEMPKCS1(PKCS1Error(err)),
                    ))
                }
            };
        let private_key_pkcs1_pem = match self.private_key.to_pkcs1_pem(LineEnding::LF) {
            Ok(private_key) => private_key.to_string(),
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::ConvertPrivateKeyToPEMPKCS1(PKCS1Error(err)),
                ))
            }
        };
        let public_key_pkcs1_pem = match self.public_key.to_pkcs1_pem(LineEnding::LF) {
            Ok(public_key) => public_key,
            Err(err) => {
                return Err(Error::Encryption(
                    EncryptionError::ConvertPublicKeyToPEMPKCS1(PKCS1Error(err)),
                ))
            }
        };
        let encryption_keys_model = EncryptionKeysModel {
            signing_private_key: signing_private_key_pkcs1_pem,
            signing_public_key: signing_public_key_pkcs1_pem,
            private_key: private_key_pkcs1_pem,
            public_key: public_key_pkcs1_pem,
            symmetric_key: self.symmetric_key.to_owned(),
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

    pub fn generate_asymmetric_keys() -> Result<(RsaPublicKey, RsaPrivateKey), Error> {
        let mut rng: OsRng = OsRng;
        let rsa_private_key: RsaPrivateKey = match RsaPrivateKey::new(&mut rng, 2048) {
            Ok(rsa_private_key) => rsa_private_key,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::GeneratingRSAPrivate(
                    RSAError(err),
                )))
            }
        };
        let rsa_public_key: RsaPublicKey = rsa_private_key.to_public_key();
        Ok((rsa_public_key, rsa_private_key))
    }

    pub fn get_private_signing_key(&self) -> &RsaPrivateKey {
        &self.signing_private_key
    }

    pub fn get_public_signing_key(&self) -> &RsaPublicKey {
        &self.signing_public_key
    }

    pub fn get_public_encryption_key(&self) -> &RsaPublicKey {
        &self.public_key
    }

    pub fn get_signing_key(&self) -> SigningKey<Sha256> {
        self.signing_key.to_owned()
    }

    pub fn get_verifying_key(&self) -> VerifyingKey<Sha256> {
        self.verifying_key.to_owned()
    }

    pub fn get_private_decryption_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    pub fn get_symmetric_key(&self) -> &[u8; 32] {
        &self.symmetric_key
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonEncryptedDataWrapper {
    pub data: String,
}

pub fn decrypt_url_safe_base64_with_private_key<T: DeserializeOwned>(
    encrypted_url_safe_base64_data: Vec<u8>,
    private_key: &RsaPrivateKey,
) -> Result<T, Error> {
    let encrypted_credentials_bytes: Vec<u8> =
        match URL_SAFE_NO_PAD.decode(encrypted_url_safe_base64_data) {
            Ok(encrypted_data_bytes) => encrypted_data_bytes,
            Err(err) => {
                return Err(Error::ClientPayload(
                    ClientPayloadError::UrlSafeBase64Decode(Base64DecodeError(err)),
                ))
            }
        };

    let decrypted_data_bytes =
        match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_credentials_bytes) {
            Ok(rsa_private) => rsa_private,
            Err(err) => {
                return Err(Error::Encryption(EncryptionError::RSAPrivateConversion(
                    RSAError(err),
                )))
            }
        };
    let decrypted_data_struct: T = match serde_json::from_slice::<T>(&decrypted_data_bytes) {
        Ok(decrypted_data_struct) => decrypted_data_struct,
        Err(err) => {
            return Err(Error::ClientPayload(
                ClientPayloadError::DataDeserialisation(SerdeError(err)),
            ))
        }
    };

    Ok(decrypted_data_struct)
}

pub fn decrypt_with_private_key<T: DeserializeOwned>(
    encrypted_data: Vec<u8>,
    private_key: &RsaPrivateKey,
) -> Result<T, Error> {
    let decrypted_data_bytes = match private_key.decrypt(Pkcs1v15Encrypt, &encrypted_data) {
        Ok(rsa_private) => rsa_private,
        Err(err) => {
            return Err(Error::Encryption(EncryptionError::RSAPrivateConversion(
                RSAError(err),
            )))
        }
    };
    let decrypted_data_struct: T = match serde_json::from_slice::<T>(&decrypted_data_bytes) {
        Ok(decrypted_data_struct) => decrypted_data_struct,
        Err(err) => {
            return Err(Error::ClientPayload(
                ClientPayloadError::DataDeserialisation(SerdeError(err)),
            ))
        }
    };

    Ok(decrypted_data_struct)
}
