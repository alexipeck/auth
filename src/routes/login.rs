use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::decrypt_with_private_key,
    error::{AuthenticationError, Error, TokenError},
    flows::user_login::{LoginCredentials, LoginFlow, UserLogin},
    user::ClientState,
    user_session::UserSession,
};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use peck_lib::auth::token_pair::TokenPair;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

fn init_restricted_flow(
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
    lifetime: chrono::Duration,
    r#type: FlowType,
) -> Result<LoginFlow, Error> {
    let token_pair: TokenPair = auth_manager
        .setup_flow_with_lifetime::<Option<bool>>(&headers, r#type, lifetime, true, None)?;
    Ok(LoginFlow::new(
        token_pair,
        auth_manager
            .encryption_keys
            .get_public_encryption_key()
            .to_owned(),
    ))
}

pub async fn init_login_flow_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
    match init_restricted_flow(
        headers,
        auth_manager,
        chrono::Duration::minutes(5),
        FlowType::Login,
    ) {
        Ok(login_flow) => (StatusCode::OK, Json(login_flow)).into_response(),
        Err(err) => {
            warn!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn init_identity_login_flow_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
    match init_restricted_flow(
        headers,
        auth_manager,
        chrono::Duration::seconds(10),
        FlowType::Login,
    ) {
        Ok(login_flow) => (StatusCode::OK, Json(login_flow)).into_response(),
        Err(err) => {
            warn!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn login_with_identity(
    identity: &str,
    key: &str,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<ClientState, Error> {
    let (user_profile, expiry) = auth_manager
        .validate_identity(identity, key, &headers)
        .await?;
    let user_session = UserSession::create_aligned_read_from_user_id(
        user_profile.user_id,
        &headers,
        auth_manager.to_owned(),
        expiry,
    )
    .await?;
    info!(
        "User authenticated from identity (read-only): ({}, {}, {})",
        user_profile.display_name, user_profile.email, user_profile.user_id
    );
    Ok(ClientState {
        user_session,
        user_profile,
        identity: None,
    })
}

async fn login_with_credentials(
    user_login: UserLogin,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<ClientState, Error> {
    auth_manager.verify_flow::<Option<bool>>(&user_login.key, &headers, &FlowType::Login)?;
    let credentials: LoginCredentials = decrypt_with_private_key::<LoginCredentials>(
        user_login.encrypted_credentials,
        auth_manager.encryption_keys.get_private_decryption_key(),
    )?;
    let user_profile = auth_manager
        .validate_user_credentials(
            &credentials.email,
            &credentials.password,
            &credentials.two_fa_code,
        )
        .await?;
    let (user_session, latest_expiry) = UserSession::create_read_write_from_user_id(
        user_profile.user_id,
        &headers,
        auth_manager.to_owned(),
    )
    .await?;
    info!(
        "User authenticated: ({}, {}, {})",
        user_profile.display_name, user_profile.email, user_profile.user_id
    );
    let identity =
        auth_manager.generate_identity(&headers, &user_profile.user_id, latest_expiry)?;
    Ok(ClientState {
        user_session,
        user_profile,
        identity: Some(identity),
    })
}

pub async fn login_with_credentials_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
    match login_with_credentials(user_login, headers, auth_manager.to_owned()).await {
        Ok(client_state) => {
            /* let cookie = CookieBuilder::new(auth_manager.config.get_cookie_name(), identity_cookie)
            .path("/")
            .http_only(true) //Set to true for production
            .secure(true) //Set to true for production
            .domain(&auth_manager.cookie_domain)
            .same_site(SameSite::Lax)
            .max_age(lifetime)
            .expires(Some((SystemTime::now() + lifetime).into()))
            .build(); */
            match Response::builder()
                .status(StatusCode::OK)
                /* .header(SET_COOKIE, cookie.to_string()) */
                .body(Body::from(match serde_json::to_string(&client_state) {
                    Ok(t) => t,
                    Err(err) => {
                        warn!("{err}");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                })) {
                Ok(response) => response,
                Err(err) => {
                    warn!("{err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
            /* (StatusCode::OK, Json(client_state)).into_response() */
        }
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity(String);

pub async fn login_with_identity_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
    /* TypedHeader(identity): TypedHeader<Identity>, */
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(identity): axum::response::Json<Identity>,
) -> impl IntoResponse {
    #[cfg(feature = "debug-logging")]
    tracing::debug!("{:?}", headers);
    match login_with_identity(
        &identity.0,
        authorisation.token(),
        headers,
        auth_manager.to_owned(),
    )
    .await
    {
        Ok(client_state) => {
            /* let cookie = CookieBuilder::new(auth_manager.config.get_cookie_name(), identity_cookie)
            .path("/")
            .http_only(true) //Set to true for production
            .secure(true) //Set to true for production
            .domain(&auth_manager.cookie_domain)
            .same_site(SameSite::Lax)
            .max_age(lifetime)
            .expires(Some((SystemTime::now() + lifetime).into()))
            .build(); */
            match Response::builder().status(StatusCode::OK).body(Body::from(
                match serde_json::to_string(&client_state) {
                    Ok(t) => t,
                    Err(err) => {
                        warn!("{err}");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                },
            )) {
                Ok(response) => response,
                Err(err) => {
                    warn!("{err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(err) => {
            warn!("{}", err);
            match err {
                Error::Authentication(
                    AuthenticationError::IncorrectCredentials
                    | AuthenticationError::Incorrect2FACode,
                ) => StatusCode::UNAUTHORIZED.into_response(),
                _ => StatusCode::BAD_REQUEST.into_response(),
            }
        }
    }
}
