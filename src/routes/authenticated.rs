use crate::{
    auth_manager::AuthManager,
    error::{AuthenticationError, Error},
    flows::user_login::SixDigitString,
};
use axum::{
    body::Body,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::{headers::Cookie, TypedHeader};
use cookie::{CookieBuilder, SameSite};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;

pub async fn refresh_read_token_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let read_token = cookies.get(&format!(
        "{base}_read",
        base = auth_manager.config.get_cookie_name_base()
    ));

    if read_token.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match auth_manager.refresh_read_token(read_token.unwrap(), &headers) {
        Ok((read, seconds_until_expiry)) => {
            let mut builder = Response::builder().status(StatusCode::OK);

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_read",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    read.token,
                )
                .http_only(true)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .max_age(cookie::time::Duration::seconds(seconds_until_expiry))
                .build()
                .to_string(),
            );

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_read_expiry",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    read.expiry.to_rfc3339(),
                )
                .http_only(false)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .max_age(cookie::time::Duration::seconds(seconds_until_expiry))
                .build()
                .to_string(),
            );

            match builder.body(Body::empty()) {
                Ok(response) => response,
                Err(err) => {
                    warn!("{err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
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
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    (StatusCode::OK, Json(user_profile)).into_response()
}

pub async fn get_write_token_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    headers: HeaderMap,
    axum::response::Json(data): axum::response::Json<GetWriteTokenData>,
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
    match auth_manager
        .generate_write_token(read_token, &data.two_fa_code, &headers)
        .await
    {
        Ok(write) => {
            let mut builder = Response::builder().status(StatusCode::OK);

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_write",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    write.token,
                )
                .http_only(true)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .max_age(cookie::time::Duration::seconds(
                    auth_manager.config.write_lifetime_seconds - 5,
                ))
                .build()
                .to_string(),
            );

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_write_expiry",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    write.expiry.to_rfc3339(),
                )
                .http_only(false)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .max_age(cookie::time::Duration::seconds(
                    auth_manager.config.write_lifetime_seconds - 5,
                ))
                .build()
                .to_string(),
            );

            match builder.body(Body::empty()) {
                Ok(response) => response,
                Err(err) => {
                    warn!("{err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
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
