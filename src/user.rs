use crate::{
    cryptography::generate_token,
    error::{AccountSetupError, AuthenticationError, Error},
    model::UserModel,
    user_session::UserSession,
};
use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use google_authenticator::GoogleAuthenticator;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct User {
    id: Uuid,
    display_name: String,
    email: EmailAddress,
    #[serde(skip)]
    hashed_and_salted_password: String,
    #[serde(skip)]
    two_fa_client_secret: String,
    disabled: bool,
}

impl User {
    pub fn new(
        id: Uuid,
        display_name: String,
        email: EmailAddress,
        hashed_and_salted_password: String,
        two_fa_client_secret: String,
        disabled: bool,
    ) -> Self {
        Self {
            id,
            display_name,
            email,
            hashed_and_salted_password,
            two_fa_client_secret,
            disabled,
        }
    }
    pub fn to_model(&self) -> UserModel {
        UserModel::new(
            self.id.to_string(),
            self.display_name.to_owned(),
            self.email.to_string(),
            self.hashed_and_salted_password.to_owned(),
            self.two_fa_client_secret.to_owned(),
            self.disabled,
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
    pub fn disabled(&self) -> bool {
        self.disabled
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
            return Err(Error::AccountSetup(
                AccountSetupError::AccountSetupAlreadyComplete,
            ));
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
        self.disabled = false;
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
    pub fn validate_two_fa_code(&self, two_fa_code: &[u8; 6]) -> Result<(), Error> {
        let auth = GoogleAuthenticator::new();
        match auth.get_code(&self.two_fa_client_secret, 0) {
            Ok(current_code) => {
                let two_fa_code: String = String::from_utf8(two_fa_code.to_vec()).unwrap();
                if two_fa_code == current_code {
                    Ok(())
                } else {
                    Err(Error::Authentication(AuthenticationError::Incorrect2FACode))
                }
            }
            Err(err) => Err(Error::Authentication(
                AuthenticationError::GoogleAuthenticator(err),
            )),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct UserSafe {
    pub id: Uuid,
    pub display_name: String,
    pub email: EmailAddress,
}

#[derive(Debug, Serialize)]
pub struct IdentityCookie {
    pub name: String,
    pub token: String,
    pub expiry: DateTime<Utc>,
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
    pub identity: Option<IdentityCookie>,
}
