use crate::{
    auth_manager::AuthManager,
    r#trait::Expired,
    response::{FullResponseData, ResponseData},
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
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginFlow {
    key: String, //either token or encrypted Self depending on usage
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
    _salt: Uuid,
}

impl LoginFlow {
    pub fn new(key: String, expiry: DateTime<Utc>) -> Self {
        Self {
            key,
            expiry,
            _salt: Uuid::new_v4(),
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
    key: String,
    email: EmailAddress,
    password: String,
    two_fa_code: [u8; 6],
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
    let login_flow = match auth_manager.setup_login_flow(&headers) {
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
    //asdf;
    return match auth_manager.verify_login_flow(login_flow.get_key().to_string(), &headers) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(err) => {
            warn!("{}", err);
            StatusCode::UNAUTHORIZED.into_response()
        }
    };
}
