use std::str::FromStr;

use diesel::{AsChangeset, Identifiable, Insertable, Queryable};
use email_address::EmailAddress;
use uuid::Uuid;

use crate::{
    error::{Error, UserFromModelError, UuidError},
    schema::user,
    user::User,
};

#[derive(Insertable, Queryable, AsChangeset, Identifiable)]
#[diesel(primary_key(id))]
#[diesel(table_name = user)]
pub struct UserModel {
    id: String,
    display_name: String,
    email: String,
    hashed_and_salted_password: String,
    two_fa_client_secret: String,
    disabled: bool,
}

impl UserModel {
    pub fn new(
        id: String,
        display_name: String,
        email: String,
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
    pub fn to_user(self) -> Result<User, Error> {
        let id: Uuid = match Uuid::parse_str(&self.id) {
            Ok(id) => id,
            Err(err) => {
                return Err(Error::UserFromModel(
                    UserFromModelError::ParseUuidFromString(UuidError(err)),
                ))
            }
        };
        let email_address: EmailAddress = match EmailAddress::from_str(&self.email) {
            Ok(email) => email,
            Err(err) => {
                return Err(Error::UserFromModel(
                    UserFromModelError::ParseEmailAddressFromString(err.to_string()),
                ))
            }
        };
        Ok(User::new(
            id,
            self.display_name,
            email_address,
            self.hashed_and_salted_password,
            self.two_fa_client_secret,
            self.disabled,
        ))
    }
}
