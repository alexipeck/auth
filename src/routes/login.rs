use crate::{
    auth_manager::{AuthManager, FlowType},
    error::{AuthenticationError, Error},
    flows::{user_login::LoginCredentials, Lifetime},
    user::UserProfile,
};
use axum::{
    extract::ConnectInfo,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{headers::Cookie, TypedHeader};
use chrono::Duration;
use cookie::{time::OffsetDateTime, CookieBuilder, SameSite};
use peck_lib::auth::token_pair::TokenPair;
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

fn init_login_flow(headers: HeaderMap, auth_manager: Arc<AuthManager>) -> Result<String, Error> {
    let token_pair: TokenPair = auth_manager.setup_flow_with_lifetime::<Option<bool>>(
        &headers,
        FlowType::Login,
        Duration::seconds(auth_manager.config.login_flow_lifetime_seconds),
        true,
        None,
    )?;
    Ok(token_pair.token)
}

pub async fn init_login_flow_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match init_login_flow(headers, auth_manager.to_owned()) {
        Ok(token) => {
            //reduced lifetime to provide leeway for latency, preventing attempted use of expired tokens and to be
            //system time agnostic, client's clock tick rate still needs to be correct
            let client_cookie_lifetime_seconds =
                auth_manager.config.login_flow_lifetime_seconds - 5;

            (
                StatusCode::OK,
                [(
                    SET_COOKIE,
                    CookieBuilder::new(
                        format!(
                            "{base}_login_flow",
                            base = auth_manager.config.get_cookie_name_base()
                        ),
                        token,
                    )
                    .http_only(true)
                    .secure(true)
                    .domain(&auth_manager.cookie_domain)
                    .path("/")
                    .same_site(SameSite::Strict)
                    .max_age(cookie::time::Duration::seconds(
                        client_cookie_lifetime_seconds,
                    ))
                    .build()
                    .to_string(),
                )],
                Json(Lifetime {
                    lifetime_seconds: client_cookie_lifetime_seconds,
                }),
            )
                .into_response()
        }
        Err(err) => {
            warn!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn login_with_credentials(
    login_credentials: LoginCredentials,
    login_flow_key: &str,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<((TokenPair, TokenPair), UserProfile), Error> {
    auth_manager.verify_flow::<Option<bool>>(login_flow_key, &headers, &FlowType::Login, true)?;
    let user_profile = auth_manager
        .validate_user_credentials(
            &login_credentials.email,
            &login_credentials.password,
            &login_credentials.two_fa_code,
        )
        .await?;
    let (tokens, _latest_expiry) = auth_manager
        .create_read_write_from_user_uid(user_profile.user_uid, &headers)
        .await?;

    info!(
        "User authenticated: ({}, {}, {})",
        user_profile.display_name, user_profile.email, user_profile.user_uid
    );
    Ok((tokens, user_profile))
}

pub async fn login_with_credentials_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    headers: HeaderMap,
    axum::response::Json(login_credentials): axum::response::Json<LoginCredentials>,
) -> impl IntoResponse {
    let login_flow_key = cookies.get(&format!(
        "{base}_login_flow",
        base = auth_manager.config.get_cookie_name_base()
    ));
    let login_flow_key = if let Some(login_flow_key) = login_flow_key {
        login_flow_key
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match login_with_credentials(
        login_credentials,
        login_flow_key,
        headers,
        auth_manager.to_owned(),
    )
    .await
    {
        Ok(((read, write), user_profile)) => (
            StatusCode::OK,
            [
                (
                    SET_COOKIE,
                    CookieBuilder::new(
                        format!(
                            "{base}_login_flow",
                            base = auth_manager.config.get_cookie_name_base()
                        ),
                        "",
                    )
                    .http_only(true)
                    .secure(true)
                    .domain(&auth_manager.cookie_domain)
                    .path("/")
                    .same_site(SameSite::Strict)
                    .expires(OffsetDateTime::UNIX_EPOCH)
                    .build()
                    .to_string(),
                ),
                (
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
                    .max_age(cookie::time::Duration::seconds(
                        auth_manager.config.read_lifetime_seconds - 5,
                    ))
                    .build()
                    .to_string(),
                ),
                (
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
                    .max_age(cookie::time::Duration::seconds(
                        auth_manager.config.read_lifetime_seconds - 5,
                    ))
                    .build()
                    .to_string(),
                ),
                (
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
                ),
                (
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
                ),
            ],
            Json(user_profile),
        )
            .into_response(),
        Err(err) => {
            warn!("{}", err);
            match err {
                Error::Authentication(
                    AuthenticationError::IncorrectCredentials
                    | AuthenticationError::Incorrect2FACode,
                ) => StatusCode::UNAUTHORIZED.into_response(),
                _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
    }
}

pub async fn logout_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_write",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    "",
                )
                .http_only(true)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .build()
                .to_string(),
            ),
            (
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_read",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    "",
                )
                .http_only(true)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .build()
                .to_string(),
            ),
            (
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_login_flow",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    "",
                )
                .http_only(true)
                .secure(true)
                .domain(&auth_manager.cookie_domain)
                .path("/")
                .same_site(SameSite::Strict)
                .expires(OffsetDateTime::UNIX_EPOCH)
                .build()
                .to_string(),
            ),
        ],
    )
        .into_response()
}
