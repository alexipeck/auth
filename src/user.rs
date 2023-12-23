use email_address::EmailAddress;
use serde::Serialize;
use uuid::Uuid;

use crate::{
    cryptography::generate_token,
    error::{AccountSetupError, Error},
    model::UserModel,
    user_session::UserSession,
};

#[derive(Serialize, Debug, Clone)]
pub struct User {
    id: Uuid,
    display_name: String,
    email: EmailAddress,
    #[serde(skip)]
    hashed_and_salted_password: String,
    #[serde(skip)]
    two_fa_client_secret: String,
}

impl User {
    pub fn new(
        id: Uuid,
        display_name: String,
        email: EmailAddress,
        hashed_and_salted_password: String,
        two_fa_client_secret: String,
    ) -> Self {
        Self {
            id,
            display_name,
            email,
            hashed_and_salted_password,
            two_fa_client_secret,
        }
    }
    pub fn to_model(&self) -> UserModel {
        UserModel::new(
            self.id.to_string(),
            self.display_name.to_owned(),
            self.email.to_string(),
            self.hashed_and_salted_password.to_owned(),
            self.two_fa_client_secret.to_owned(),
        )
    }
    pub fn to_safe(&self) -> UserSafe {
        UserSafe {
            id: self.id,
            display_name: self.display_name.to_owned(),
            email: self.email.to_owned(),
        }
    }
    pub fn incomplete(&self) -> bool {
        self.display_name.is_empty()
            || self.hashed_and_salted_password.is_empty()
            || self.two_fa_client_secret.is_empty()
    }
    pub fn to_user_profile(&self) -> UserProfile {
        UserProfile {
            display_name: self.display_name.to_owned(),
            email: self.email.to_owned(),
            user_id: self.id.to_owned(),
        }
    }
    /// This function is only allowed to be called once.
    pub fn setup_user(
        &mut self,
        password: String,
        display_name: String,
        two_fa_client_secret: String,
    ) -> Result<(), Error> {
        if !self.incomplete() {
            return Err(Error::AccountSetup(AccountSetupError::AccountSetupAlreadyComplete).into());
        }
        let salt = generate_token(32);
        let hashed_and_salted_password = match argon2::hash_encoded(
            password.as_bytes(),
            salt.as_bytes(),
            &argon2::Config::default(),
        ) {
            Ok(hashed_and_salted_password) => hashed_and_salted_password,
            Err(err) => return Err(Error::AccountSetup(AccountSetupError::Argon2(err))),
        };
        self.hashed_and_salted_password = hashed_and_salted_password;
        self.two_fa_client_secret = two_fa_client_secret;
        self.display_name = display_name;
        Ok(())
    }
    pub fn get_id(&self) -> &Uuid {
        &self.id
    }
    pub fn get_display_name(&self) -> &String {
        &self.display_name
    }
    pub fn get_email(&self) -> &EmailAddress {
        &self.email
    }
    pub fn get_hashed_and_salted_password(&self) -> &String {
        &self.hashed_and_salted_password
    }
    pub fn get_two_fa_client_secret(&self) -> &String {
        &self.two_fa_client_secret
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct UserSafe {
    id: Uuid,
    display_name: String,
    email: EmailAddress,
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub display_name: String,
    pub email: EmailAddress,
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ClientState {
    pub user_session: UserSession,
    pub user_profile: UserProfile,
}
