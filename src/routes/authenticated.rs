use crate::{
    auth_manager::AuthManager,
    error::{AuthenticationError, Error},
    flows::user_login::SixDigitString,
};
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, Cookie},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

pub async fn refresh_read_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    match auth_manager.refresh_read_token(authorisation.token(), &headers) {
        Ok(token_pair) => (StatusCode::OK, Json(token_pair)).into_response(),
        Err(err) => {
            //TODO: Split out into actual correct errors
            warn!("{}", err);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct GetWriteTokenData {
    two_fa_code: SixDigitString,
}

pub async fn get_user_profile_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    TypedHeader(cookies): TypedHeader<Cookie>,
) -> impl IntoResponse {
    let read_token = cookies.get(&format!(
        "{base}_read",
        base = auth_manager.config.get_cookie_name_base()
    ));
    let read_token = if let Some(read_token) = read_token {
        read_token
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let user_profile = match auth_manager
        .validate_read_token_for_user_profile(read_token)
        .await
    {
        Ok(user_profile) => user_profile,
        Err(err) => {
            warn!("{err}");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    (StatusCode::OK, Json(user_profile)).into_response()
}

pub async fn get_write_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
    axum::response::Json(data): axum::response::Json<GetWriteTokenData>,
) -> impl IntoResponse {
    match auth_manager
        .generate_write_token(authorisation.token(), &data.two_fa_code, &headers)
        .await
    {
        Ok(token_pair) => (StatusCode::OK, Json(token_pair)).into_response(),
        Err(err) => {
            //TODO: Split out into actual correct errors
            warn!("{}", err);
            match err {
                Error::Authentication(AuthenticationError::Incorrect2FACode) => {
                    StatusCode::NOT_ACCEPTABLE.into_response()
                }
                _ => StatusCode::UNAUTHORIZED.into_response(),
            }
        }
    }
}
