use crate::serde::datetime_utc;
use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize /* Deserialize */)]
pub struct LoginFlow {
    token: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>, //only needed for the client, actual expiry is handled within token and verify_and_decrypt()
    public_encryption_key: String,
}

impl LoginFlow {
    pub fn new(token: String, expiry: DateTime<Utc>, public_encryption_key: String) -> Self {
        Self {
            token,
            expiry,
            public_encryption_key,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginCredentials {
    pub email: EmailAddress,
    pub password: String,
    pub two_fa_code: String,
}

#[derive(Debug, Deserialize)]
pub struct UserLogin {
    pub key: String,
    pub encrypted_credentials: String,
}

/* pub async fn verify_login_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(login_flow): axum::response::Json<LoginFlow>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    /* println!("{:?}", cookie); */
    return match auth_manager.verify_flow::<LoginFlow>(login_flow.get_key().to_string(), &headers) {
        Ok(_) => {
            FullResponseData::basic(ResponseData::PublicKey(PublicKey { public_key: from_utf8(&auth_manager.encryption_keys.get_public_encryption_key().public_key_to_pem().unwrap()).unwrap().to_string() }))//TODO: Add error handling
        },
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::Unauthorised)
        }
    };
} */
