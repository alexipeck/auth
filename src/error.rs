use axum::http::header::InvalidHeaderValue;
use email_address::EmailAddress;
use google_authenticator::GAError;
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum AccountSetupError {
    #[error("InvalidPassword")]
    InvalidPassword,
    #[error("Incorrect2FACode")]
    Incorrect2FACode,
    #[error("InvalidToken")]
    InvalidToken,
    #[error("Argon2({0})")]
    Argon2(#[from] argon2::Error)
}

#[derive(Error, Debug)]
pub enum InternalError {
    #[error("AuthFlow({0})")]
    AuthFlow(#[from] AuthFlowError),
    #[error("AccountSetupError({0})")]
    AccountSetup(#[from] AccountSetupError),
    #[error("Authentication({0})")]
    Authentication(#[from] AuthenticationError),
    #[error("InvalidOrigin({0})")]
    InvalidOrigin(#[from] InvalidHeaderValue),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal({0})")]
    Internal(#[from] InternalError),
}
