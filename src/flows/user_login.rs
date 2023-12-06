use crate::{
    auth_manager::AuthManager,
    r#trait::Expired,
    response::{FullResponseData, ResponseData, PublicKey},
    serde::datetime_utc,
};
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension,
};
use chrono::{DateTime, Utc};
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc, str::from_utf8};
use tracing::warn;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFlow {
    key: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,//only needed for the client, actual expiry is handled within token and verify_and_decrypt()
}

impl LoginFlow {
    pub fn new(key: String, expiry: DateTime<Utc>) -> Self {
        Self {
            key,
            expiry,
        }
    }

    pub fn get_key(&self) -> &String {
        &self.key
    }

    pub fn expired(&self) -> bool {
        self.expiry.expired()
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginCredentials {
    email: EmailAddress,
    password: String,
    two_fa_code: [u8; 6],
}

#[derive(Debug, Deserialize)]
pub struct UserLogin {
    key: String,
    encrypted_credentials: String,
}

pub async fn init_login_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    /* TypedHeader(cookie): TypedHeader<Cookie>, */
    /* TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>, */
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    //println!("{:?}", headers);
    //println!("{:?}", addr);
    let login_flow: LoginFlow = match auth_manager.setup_login_flow(&headers) {
        Ok(token) => token,
        Err(err) => {
            warn!("{}", err);
            return FullResponseData::basic(ResponseData::InternalServerError);
        }
    };
    FullResponseData::basic(ResponseData::InitLoginFlow(login_flow))
}

pub async fn verify_login_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(login_flow): axum::response::Json<LoginFlow>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    /* println!("{:?}", cookie); */
    return match auth_manager.verify_login_flow(login_flow.get_key().to_string(), &headers) {
        Ok(_) => {
            FullResponseData::basic(ResponseData::PublicKey(PublicKey { public_key: from_utf8(&auth_manager.encryption_keys.get_public_encryption_key().public_key_to_pem().unwrap()).unwrap().to_string() }))//TODO: Add error handling
        },
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::Unauthorised)
        }
    };
}

pub async fn login_with_credentials(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    /* println!("{:?}", cookie); */
    return match auth_manager.verify_login_flow(user_login.key, &headers) {
        Ok(_) => {
            //TODO: Decrypt credentials
            StatusCode::OK.into_response()
        },
        Err(err) => {
            warn!("{}", err);
            /* FullResponseData::basic(ResponseData::Unauthorised) */
            StatusCode::UNAUTHORIZED.into_response()
        }
    };
}
