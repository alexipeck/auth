use email_address::EmailAddress;
use serde::Serialize;
use uuid::Uuid;


#[derive(Serialize, Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub display_name: String,
    pub email: EmailAddress,
    #[serde(skip)]
    pub hashed_and_salted_password: String,
    /* #[serde(skip)]
    pub authorisation: Uuid, */
    #[serde(skip)]
    pub two_fa_client_secret: String,
}