use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::generate_random_base32_string,
    error::Error,
    flows::user_setup::{InviteToken, UserSetupFlow},
    response::{FullResponseData, ResponseData},
};
use axum::{extract::ConnectInfo, http::HeaderMap, response::IntoResponse, Extension};
use chrono::Duration;
use std::{net::SocketAddr, sync::Arc};

fn validate_invite_token(
    invite_token: String,
    headers: HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<UserSetupFlow, Error> {
    let (user_invite, expiry) = auth_manager.validate_invite_token(invite_token)?;
    //TODO: Check expiry, if less than 5 minutes, make it the setup flow duration
    let two_fa_client_secret: String = generate_random_base32_string(64);
    let (token, expiry) = auth_manager.setup_flow(
        &headers,
        FlowType::Setup,
        Duration::minutes(5),
        two_fa_client_secret.to_owned(),
    )?;
    let public_encryption_key = auth_manager
        .encryption_keys
        .get_public_encryption_key_string()?;
    Ok(UserSetupFlow::new(
        token,
        user_invite.get_email().to_owned(),
        expiry,
        two_fa_client_secret,
        public_encryption_key,
    ))
}

pub async fn validate_invite_token_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(invite_token): axum::response::Json<InviteToken>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    //println!("{:?}", headers);
    /* println!("{:?}", cookie); */
    match validate_invite_token(invite_token.token, headers, auth_manager) {
        Ok(user_setup_flow) => {
            FullResponseData::basic(ResponseData::InitSetupFlow(user_setup_flow)).into_response()
        }
        Err(err) => {
            println!("{}", err);
            FullResponseData::basic(ResponseData::InternalServerError).into_response()
        }
    }
}
