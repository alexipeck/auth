use email_address::EmailAddress;
use serde::Deserialize;

use crate::user_login::LoginCredentials;

#[derive(Debug, Deserialize)]
pub struct TwoTokens {
    //add field which includes the same headers as during login,
    //minus IP address or values that prevent the user from roaming,
    //the server will store the hash of these in the login session
    cookie_token: String,
    header_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TwoTokensPlus2FA {
    //add field which includes the same headers as during login,
    //minus IP address or values that prevent the user from roaming,
    //the server will store the hash of these in the login session
    cookie_token: String,
    header_token: String,
    two_fa_code: [u8; 6],
}

pub enum AuthForm {
    LoginCredentials(LoginCredentials),
    TwoTokens(TwoTokens),
    TwoTokensPlus2FA(TwoTokensPlus2FA),
}
