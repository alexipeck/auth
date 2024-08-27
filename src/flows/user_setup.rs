use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInvite {
    email: EmailAddress,
    user_uid: Uuid,
}

impl UserInvite {
    pub fn new(email: EmailAddress, user_uid: Uuid) -> Self {
        Self { email, user_uid }
    }
    pub fn get_email(&self) -> &EmailAddress {
        &self.email
    }
    pub fn get_user_uid(&self) -> &Uuid {
        &self.user_uid
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInviteData {
    pub two_fa_client_secret: String,
}

#[derive(Serialize, Deserialize)]
pub struct InviteToken {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct SetupCredentials {
    pub display_name: String,
    pub password: String,
    pub two_fa_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSetup {
    pub two_fa_client_secret: String,
    pub seconds_until_expiry: u32,
}
