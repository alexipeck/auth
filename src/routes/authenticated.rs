use crate::auth_manager::AuthManager;
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct WrappedToken {
    token: String,
}

pub async fn refresh_read_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(wrapped_token): axum::response::Json<WrappedToken>,
) -> impl IntoResponse {
    match auth_manager.refresh_read_token(&wrapped_token.token, &headers) {
        Ok(token_pair) => (StatusCode::OK, Json(token_pair)).into_response(),
        Err(err) => {
            //TODO: Split out into actual correct errors
            warn!("{}", err);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/* pub fn get_new_write_token() -> Result<(), Error> {}

pub fn get_new_write_token_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    let (token, expiry) = auth_manager.setup_flow::<Option<bool>>(
        &headers,
        FlowType::Write,
        Duration::minutes(5),
        None,
    )?;
    match  {
        Ok() => {
            FullResponseData::basic(ResponseData::).into_response()
        }
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::Unauthorised).into_response()
            //TODO: Split out into actual correct errors
        }
    }
} */
