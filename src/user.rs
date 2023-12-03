use email_address::EmailAddress;
use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize, Debug, Clone)]
pub struct User {
    id: Uuid,
    display_name: String,
    email: EmailAddress,
    #[serde(skip)]
    hashed_and_salted_password: String,
    /* #[serde(skip)]
    pub authorisation: Uuid, */
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
