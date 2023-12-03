use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openssl::{rsa::Rsa, pkey::{PKey, Private, Public}, symm::{Cipher, encrypt, decrypt}, sign::{Signer, Verifier}, hash::MessageDigest};
use serde::{Serialize, Deserialize};
use tracing::warn;
use crate::error::{Error, InternalError, TokenError, OpenSSLError, Base64DecodeError, SerdeError, FromUtf8Error};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Header {
    alg: String,
}

impl Default for Header {
    fn default() -> Self {
        Self { alg: "RSA-SHA256".to_string() }
    }
}

#[derive(Debug, Clone)]
struct Token {}

impl Token {
    fn create<T: Serialize>(data: &T, private_key: &PKey<Private>, symmetric_key: &[u8], iv: &[u8]) -> Result<String, Error> {
        let encrypted_data_base64 = {
            let serialised_data = match serde_json::to_string(data) {
                Ok(serialised_data) => serialised_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(InternalError::Token(TokenError::DataSerialisation(SerdeError(err))).into())
                },
            };
            let encrypted_data = match encrypt(
                Cipher::aes_256_cbc(),
                symmetric_key,
                Some(iv),
                serialised_data.as_bytes()
            ) {
                Ok(encrypted_data) => encrypted_data,
                Err(err) => {
                    warn!("{}", err);
                    return Err(InternalError::Token(TokenError::DataEncryption(OpenSSLError(err))).into())
                },
            };
            URL_SAFE_NO_PAD.encode(&encrypted_data)
        };
        let header_base64 = {
            let header_str = match serde_json::to_string(&Header::default()) {
                Ok(header_str) => header_str,
                Err(err) => {
                    warn!("{}", err);
                    return Err(InternalError::Token(TokenError::DataSerialisation(SerdeError(err))).into())
                },
            };
            URL_SAFE_NO_PAD.encode(&header_str)
        };
        let signature_base64 = {
            let mut signer = match Signer::new(MessageDigest::sha256(), private_key) {
                Ok(signer) => signer,
                Err(err) => {
                    warn!("{}", err);
                    return Err(InternalError::Token(TokenError::CreateSigner(OpenSSLError(err))).into())
                },
            };
            if let Err(err) = signer.update(header_base64.as_bytes()) {
                warn!("{}", err);
                return Err(InternalError::Token(TokenError::FeedSigner(OpenSSLError(err))).into())
            }
            if let Err(err) = signer.update(encrypted_data_base64.as_bytes()) {
                warn!("{}", err);
                return Err(InternalError::Token(TokenError::FeedSigner(OpenSSLError(err))).into())
            }
            let signature = match signer.sign_to_vec() {
                Ok(signature) => signature,
                Err(err) => {
                    warn!("{}", err);
                    return Err(InternalError::Token(TokenError::FinaliseSignature(OpenSSLError(err))).into())
                },
            };
            URL_SAFE_NO_PAD.encode(&signature)
        };
        Ok(format!("{}.{}.{}", header_base64, encrypted_data_base64, signature_base64))
    }

    fn verify_and_decrypt<T: for<'de> Deserialize<'de>>(token: &String, public_key: &PKey<Public>, symmetric_key: &[u8], iv: &[u8]) -> Result<T, Error> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(InternalError::Token(TokenError::InvalidFormatForDecoding).into());
        }

        {
            let header_str_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
                Ok(header_str_bytes) => header_str_bytes,
                Err(err) => return Err(InternalError::Token(TokenError::HeaderBase64Decode(Base64DecodeError(err))).into()),
            };
            let header: Header = match serde_json::from_slice(&header_str_bytes) {
                Ok(header) => header,
                Err(err) => return Err(InternalError::Token(TokenError::HeaderDeserialisation(SerdeError(err))).into()),
            };
            if header.alg != "RSA-SHA256" {
                println!("Header algorithm doesn't match expected RSA-SHA256");
                return Err(InternalError::Token(TokenError::HeadedUnexpectedAlgorithm).into());
            }
        }
        
        {
            let signature_bytes = match URL_SAFE_NO_PAD.decode(parts[2]) {
                Ok(signature_bytes) => signature_bytes,
                Err(err) => return Err(InternalError::Token(TokenError::SignatureBase64Decode(Base64DecodeError(err))).into()),
            };
        
            let mut verifier = match Verifier::new(MessageDigest::sha256(), public_key) {
                Ok(verifier) => verifier,
                Err(err
                ) => return Err(InternalError::Token(TokenError::CreateVerifier(OpenSSLError(err))).into()),
            };
        
            if let Err(err) = verifier.update(parts[0].as_bytes()) {
                return Err(InternalError::Token(TokenError::FeedVerifier(OpenSSLError(err))).into())
            }
            if let Err(err) = verifier.update(parts[1].as_bytes()) {
                return Err(InternalError::Token(TokenError::FeedVerifier(OpenSSLError(err))).into())
            }
            let verified = match verifier.verify(&signature_bytes) {
                Ok(verified) => verified,
                Err(err) => return Err(InternalError::Token(TokenError::FinaliseVerifier(OpenSSLError(err))).into()),
            };
            if !verified {
                return Err(InternalError::Token(TokenError::SignatureVerificationFailed).into());
            }
        }
    
        let encrypted_payload = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(encrypted_payload) => encrypted_payload,
            Err(err) => return Err(InternalError::Token(TokenError::PayloadBase64Decode(Base64DecodeError(err))).into()),
        };
    
        let cipher = Cipher::aes_256_cbc();
        let decrypted_data = match decrypt(cipher, symmetric_key, Some(iv), &encrypted_payload) {
            Ok(decrypted_data) => decrypted_data,
            Err(err) => return Err(InternalError::Token(TokenError::DataDecryption(OpenSSLError(err))).into()),
        };
    
        let decrypted_data_str = match String::from_utf8(decrypted_data) {
            Ok(decrypted_data_str) => decrypted_data_str,
            Err(err) => return Err(InternalError::Token(TokenError::DataBytesToString(FromUtf8Error(err))).into()),
        };
    
        let decrypted_data_struct = match serde_json::from_str(&decrypted_data_str) {
            Ok(decrypted_data_struct) => decrypted_data_struct,
            Err(err) => return Err(InternalError::Token(TokenError::DataDeserialisation(SerdeError(err))).into()),
        };
    
        Ok(decrypted_data_struct)
    }
}