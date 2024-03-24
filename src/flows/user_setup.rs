use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use peck_lib::{
    auth::token_pair::TokenPair, crypto::generate_random_base32_string,
    datetime::serde::datetime_utc,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInvite {
    email: EmailAddress,
    user_id: Uuid,
}

impl UserInvite {
    pub fn get_email(&self) -> &EmailAddress {
        &self.email
    }
    pub fn get_user_id(&self) -> &Uuid {
        &self.user_id
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInviteInstance {
    email: EmailAddress,
    user_id: Uuid,
    two_fa_client_secret: String,
}

impl UserInviteInstance {
    pub fn from_user_invite(user_invite: UserInvite) -> Self {
        Self {
            email: user_invite.email,
            user_id: user_invite.user_id,
            two_fa_client_secret: generate_random_base32_string(64),
        }
    }
    pub fn get_email(&self) -> &EmailAddress {
        &self.email
    }
    pub fn get_user_id(&self) -> &Uuid {
        &self.user_id
    }
    pub fn get_two_fa_client_secret(&self) -> &String {
        &self.two_fa_client_secret
    }
}

impl UserInvite {
    pub fn new(email: EmailAddress, user_id: Uuid) -> Self {
        Self { email, user_id }
    }
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

#[derive(Debug, Deserialize)]
pub struct UserSetup {
    pub key: String,
    pub encrypted_credentials: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SetupResponse {
    Expired,
    Valid {
        email: EmailAddress,
        #[serde(with = "datetime_utc")]
        expiry: DateTime<Utc>,
        two_fa_secret: String,
        flow_key: String, //sets flow time limit
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSetupFlow {
    token_pair: TokenPair,
    email: EmailAddress,
    two_fa_client_secret: String,
    public_encryption_key: String,
}

impl UserSetupFlow {
    pub fn new(
        token_pair: TokenPair,
        email: EmailAddress,
        two_fa_client_secret: String,
        public_encryption_key: String,
    ) -> Self {
        Self {
            token_pair,
            email,
            two_fa_client_secret,
            public_encryption_key,
        }
    }
    pub fn get_two_fa_client_secret(&self) -> &String {
        &self.two_fa_client_secret
    }
    pub fn get_email(&self) -> &EmailAddress {
        &self.email
    }
}
