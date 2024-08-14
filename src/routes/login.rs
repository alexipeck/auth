use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::decrypt_url_safe_base64_with_private_key,
    error::{AuthenticationError, Error},
    flows::{
        user_login::{LoginCredentials, UserLogin},
        Lifetime,
    },
    user::ClientState,
    user_session::{TokenPair, UserSession},
};
use axum::{
    extract::ConnectInfo,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, CookieBuilder, SameSite};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

fn init_login_flow(
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<(String, DateTime<Utc>), Error> {
    let token_pair: TokenPair = auth_manager.setup_flow_with_lifetime::<Option<bool>>(
        &headers,
        FlowType::Login,
        Duration::seconds(auth_manager.config.login_flow_lifetime_seconds),
        None,
    )?;
    Ok((token_pair.token, token_pair.expiry))
}

pub async fn init_login_flow_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match init_login_flow(headers, auth_manager.to_owned()) {
        Ok((token, _expiry)) => {
            //reduced lifetime for leeway, preventing attempted use of expired tokens and accounting for latency
            //system time agnostic, client's tick rate still needs to be correct
            let client_cookie_lifetime_seconds =
                auth_manager.config.login_flow_lifetime_seconds - 5;
            let cookie: Cookie = CookieBuilder::new(
                format!(
                    "{base}_login_flow",
                    base = auth_manager.config.get_cookie_name_base()
                ),
                token,
            )
            .http_only(true)
            .secure(true)
            .path("/")
            .same_site(SameSite::Strict)
            .max_age(cookie::time::Duration::seconds(
                client_cookie_lifetime_seconds,
            ))
            .build();

            (
                StatusCode::OK,
                [(SET_COOKIE, cookie.to_string())],
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

fn login_with_credentials(
    user_login: UserLogin,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<ClientState, Error> {
    auth_manager.verify_flow::<Option<bool>>(&user_login.key, &headers)?;
    let credentials: LoginCredentials = decrypt_url_safe_base64_with_private_key::<LoginCredentials>(
        user_login.encrypted_credentials,
        &auth_manager.encryption_keys.get_private_decryption_key(),
    )?;
    let user_profile = auth_manager.validate_user_credentials(
        &credentials.email,
        &credentials.password,
        credentials.two_fa_code,
    )?;
    let user_session =
        UserSession::create_from_user_id(user_profile.user_id, headers, auth_manager)?;
    info!(
        "User authenticated: ({}, {}, {})",
        user_profile.display_name, user_profile.email, user_profile.user_id
    );
    Ok(ClientState {
        user_session,
        user_profile,
    })
}

pub async fn login_with_credentials_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    match login_with_credentials(user_login, headers, auth_manager) {
        Ok(client_state) => (StatusCode::OK, Json(client_state)).into_response(),
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
