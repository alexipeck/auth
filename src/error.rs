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
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal({0})")]
    Internal(#[from] InternalError),
}
