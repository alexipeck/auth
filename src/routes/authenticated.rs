use crate::{
    auth_manager::AuthManager,
    error::{AuthenticationError, Error},
};
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
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
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
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
    two_fa_code: [u8; 6],
}

pub async fn get_write_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
    axum::response::Json(data): axum::response::Json<GetWriteTokenData>,
) -> impl IntoResponse {
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
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
