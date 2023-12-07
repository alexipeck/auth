use std::fmt;

use axum::http::header::InvalidHeaderValue;
use email_address::EmailAddress;
use google_authenticator::GAError;
use thiserror::Error;

use crate::impl_error_wrapper;

#[derive(Error, Debug)]
pub enum AuthFlowError {
    #[error("Expired")]
    Expired,
    #[error("Invalid")]
    Invalid,
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("GoogleAuthenticator({0})")]
    GoogleAuthenticator(#[from] GAError),
    #[error("Incorrect2FACode")]
    Incorrect2FACode,
    #[error("IncorrectCredentials")]
    IncorrectCredentials,
    #[error("InvalidPasswordFormat({0})")]
    InvalidPasswordFormat(#[from] argon2::Error),
    #[error("UserUIDNotRegisteredToEmail({0})")]
    UserUIDNotRegisteredToEmail(EmailAddress),
    #[error("EmailNotRegistered({0})")]
    EmailNotRegistered(EmailAddress),
    /* #[error("")]
    ErrorGetting2FACodeFromSecret,
    #[error("Argon2ValidationError({0})")]
    Argon2ValidationError(String),
    #[error("")]
    Invalid2FASecret,
    #[error("")]
    InvalidInviteToken,
    #[error("AuthorisationProfileNotFound({0})")]
    AuthorisationProfileNotFound(Uuid),
    #[error("UserNotFound({0})")]
    UserNotFound(Uuid),
    #[error("AccessDenied({0})")]
    AccessDenied(Uuid),
    #[error("EmailAlreadyExists({0})")]
    EmailAlreadyExists(EmailAddress), */
}
impl_error_wrapper!(SerdeError, serde_json::error::Error);
impl_error_wrapper!(OpenSSLError, openssl::error::ErrorStack);
impl_error_wrapper!(Base64DecodeError, base64::DecodeError);
impl_error_wrapper!(FromUtf8Error, std::string::FromUtf8Error);

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("DataSerialisation({0})")]
    DataSerialisation(#[from] SerdeError),
    #[error("DataEncryption({0})")]
    DataEncryption(#[from] OpenSSLError),
    #[error("HeaderSerialisation({0})")]
    HeaderSerialisation(SerdeError),
    #[error("HeaderDeserialisation({0})")]
    HeaderDeserialisation(SerdeError),
    #[error("CreateSigner({0})")]
    CreateSigner(OpenSSLError),
    #[error("FeedSigner({0})")]
    FeedSigner(OpenSSLError),
    #[error("FinaliseSignature({0})")]
    FinaliseSignature(OpenSSLError),
    #[error("InvalidFormatForDecoding")]
    InvalidFormatForDecoding,
    #[error("HeaderBase64Decode({0})")]
    HeaderBase64Decode(Base64DecodeError),
    #[error("Feedverifier({0})")]
    FeedVerifier(OpenSSLError),
    #[error("HeaderUnexpectedAlgorithm")]
    HeadedUnexpectedAlgorithm,
    #[error("SignatureBase64Decode({0})")]
    SignatureBase64Decode(Base64DecodeError),
    #[error("CreateVerifier({0})")]
    CreateVerifier(OpenSSLError),
    #[error("FinaliseVerifier({0})")]
    FinaliseVerifier(OpenSSLError),
    #[error("SignatureVerificationFailed")]
    SignatureVerificationFailed,
    #[error("PayloadBase64Decode({0})")]
    PayloadBase64Decode(Base64DecodeError),
    #[error("DataDecryption({0})")]
    DataDecryption(OpenSSLError),
    #[error("DataBytesToString({0})")]
    DataBytesToString(FromUtf8Error),
    #[error("DataDeserialisation({0})")]
    DataDeserialisation(SerdeError),
    #[error("Expired")]
    Expired,
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("KeysDontMatch")]
    KeysDontMatch,
}

#[derive(Error, Debug)]
pub enum ClientPayloadError {
    #[error("UrlSafeBase64Decode({0})")]
    UrlSafeBase64Decode(Base64DecodeError),
    #[error("DataBytesToString({0})")]
    DataBytesToString(FromUtf8Error),
    #[error("DataDeserialisation({0})")]
    DataDeserialisation(SerdeError),
}

#[derive(Error, Debug)]
pub enum AccountSetupError {
    #[error("InvalidPassword")]
    InvalidPassword,
    #[error("Incorrect2FACode")]
    Incorrect2FACode,
    #[error("InvalidToken")]
    InvalidToken,
    #[error("Argon2({0})")]
    Argon2(#[from] argon2::Error),
}

#[derive(Error, Debug)]
pub enum StartupError {
    #[error("InvalidOrigin({0})")]
    InvalidOrigin(#[from] InvalidHeaderValue),
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("GeneratingRSABase({0})")]
    GeneratingRSABase(OpenSSLError),
    #[error("GeneratingRSAPrivate({0})")]
    GeneratingRSAPrivate(OpenSSLError),
    #[error("GeneratingRSAPublic({0})")]
    GeneratingRSAPublic(OpenSSLError),
    #[error("GeneratingRSAPublicPEM({0})")]
    GeneratingRSAPublicPEM(OpenSSLError),
    #[error("RSAPrivateConversion({0})")]
    RSAPrivateConversion(OpenSSLError),
    #[error("DataDecryption({0})")]
    DataDecryption(OpenSSLError),
}

#[derive(Error, Debug)]
pub enum InternalError {
    #[error("AuthFlow({0})")]
    AuthFlow(#[from] AuthFlowError),
    #[error("AccountSetupError({0})")]
    AccountSetup(#[from] AccountSetupError),
    #[error("Authentication({0})")]
    Authentication(#[from] AuthenticationError),
    #[error("Token({0})")]
    Token(#[from] TokenError),
    #[error("Startup({0})")]
    Startup(#[from] StartupError),
    #[error("Encryption({0})")]
    Encryption(#[from] EncryptionError),
    #[error("ClientPayload({0})")]
    ClientPayload(#[from] ClientPayloadError),
    #[error("Login({0})")]
    Login(#[from] LoginError),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal({0})")]
    Internal(#[from] InternalError),
}
