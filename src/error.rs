use axum::http::header::InvalidHeaderValue;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthFlowError {
    #[error("Expired")]
    Expired,
    #[error("Invalid")]
    Invalid,
}

#[derive(Error, Debug)]
pub enum InternalError {
    #[error("AuthFlow({0})")]
    AuthFlow(#[from] AuthFlowError),
    #[error("InvalidOrigin({0})")]
    InvalidOrigin(#[from] InvalidHeaderValue),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal({0})")]
    Internal(#[from] InternalError),
}
