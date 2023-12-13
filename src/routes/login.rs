use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::decrypt_url_safe_base64_with_private_key,
    error::Error,
    flows::user_login::{LoginCredentials, LoginFlow, UserLogin},
    response::{FullResponseData, ResponseData},
    user::{ClientState, UserProfile},
    user_session::UserSession,
};
use axum::{extract::ConnectInfo, http::HeaderMap, response::IntoResponse, Extension};
use chrono::Duration;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

fn init_login_flow(headers: HeaderMap, auth_manager: Arc<AuthManager>) -> Result<LoginFlow, Error> {
    let (token, expiry) = auth_manager.setup_flow::<Option<bool>>(
        &headers,
        FlowType::Login,
        Duration::minutes(5),
        None,
    )?;
    let public_encryption_key = auth_manager
        .encryption_keys
        .get_public_encryption_key_string()?;
    Ok(LoginFlow::new(token, expiry, public_encryption_key))
}

pub async fn init_login_flow_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    //println!("{:?}", headers);
    //println!("{:?}", addr);
    match init_login_flow(headers, auth_manager) {
        Ok(login_flow) => {
            FullResponseData::basic(ResponseData::InitLoginFlow(login_flow)).into_response()
        }
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::InternalServerError).into_response()
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
    let user_session = UserSession::create_from_user_id(
        user_profile.user_id,
        auth_manager.encryption_keys.get_private_signing_key(),
        auth_manager.encryption_keys.get_symmetric_key(),
        auth_manager.encryption_keys.get_iv(),
    )?;
    println!(
        "User authenticated: ({}, {}, {})",
        user_profile.display_name, user_profile.email, user_profile.user_id
    );
    Ok(ClientState {
        user_session,
        user_profile,
    })
}

pub async fn login_with_credentials_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    //println!("{:?}", cookie);
    match login_with_credentials(user_login, headers, auth_manager) {
        Ok(client_state) => {
            FullResponseData::basic(ResponseData::ClientState(client_state)).into_response()
        }
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::InternalServerError).into_response()
            //TODO: Split out into actual correct errors
        }
    }
}
