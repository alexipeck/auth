use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::decrypt_url_safe_base64_with_private_key,
    error::{AuthenticationError, Error},
    flows::user_login::{LoginCredentials, LoginFlow, UserLogin},
    user::ClientState,
    user_session::UserSession,
};
use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::Duration;
use peck_lib::auth::token_pair::TokenPair;
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

fn init_login_flow(headers: HeaderMap, auth_manager: Arc<AuthManager>) -> Result<LoginFlow, Error> {
    let token_pair: TokenPair = auth_manager.setup_flow_with_lifetime::<Option<bool>>(
        &headers,
        FlowType::Login,
        Duration::minutes(5),
        None,
    )?;
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
    match init_login_flow(headers, auth_manager) {
        Ok(login_flow) => (StatusCode::OK, Json(login_flow)).into_response(),
        Err(err) => {
            warn!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn login_with_credentials(
    user_login: UserLogin,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<ClientState, Error> {
    auth_manager.verify_flow::<Option<bool>>(&user_login.key, &headers)?;
    let credentials: LoginCredentials = decrypt_url_safe_base64_with_private_key::<LoginCredentials>(
        user_login.encrypted_credentials,
        &auth_manager.encryption_keys.get_private_decryption_key(),
    )?;
    let user_profile = auth_manager
        .validate_user_credentials(
            &credentials.email,
            &credentials.password,
            credentials.two_fa_code,
        )
        .await?;
    let user_session =
        UserSession::create_from_user_id(user_profile.user_id, headers, auth_manager.to_owned())
            .await?;
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
    match login_with_credentials(user_login, headers, auth_manager).await {
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
