use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::serde::datetime_utc;

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

#[derive(Serialize, Deserialize)]
pub struct InviteToken {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct UserSetup {
    key: String,
    encrypted_credentials: String,
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
    token: String,
    email: EmailAddress,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
    two_fa_client_secret: String,
    public_encryption_key: String,
}

impl UserSetupFlow {
    pub fn new(
        token: String,
        email: EmailAddress,
        expiry: DateTime<Utc>,
        two_fa_client_secret: String,
        public_encryption_key: String,
    ) -> Self {
        Self {
            token,
            email,
            expiry,
            two_fa_client_secret,
            public_encryption_key,
        }
    }
}

/* pub async fn t(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(t): axum::response::Json<>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    /* println!("{:?}", cookie); */
    return match auth_manager.verify_flow(login_flow.get_key().to_string(), &headers) {
        Ok(_) => {
            FullResponseData::basic(ResponseData::PublicKey(PublicKey { public_key: from_utf8(&auth_manager.encryption_keys.get_public_encryption_key().public_key_to_pem().unwrap()).unwrap().to_string() }))//TODO: Add error handling
        },
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::Unauthorised)
        }
    };
} */
