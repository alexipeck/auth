use crate::{
    auth_manager::{AuthManager, FlowType},
    cryptography::decrypt_url_safe_base64_with_private_key,
    error::{AccountSetupError, Error, InternalError},
    flows::user_setup::{
        InviteToken, SetupCredentials, UserInvite, UserInviteInstance, UserSetup, UserSetupFlow,
    },
    r#trait::Expired,
    response::{FullResponseData, ResponseData},
    user_session::TokenPair,
};
use axum::{extract::ConnectInfo, http::HeaderMap, response::IntoResponse, Extension};
use chrono::{DateTime, Duration, Utc};
use email_address::EmailAddress;
use google_authenticator::GoogleAuthenticator;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

fn validate_invite_token(
    invite_token: &String,
    headers: &HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<UserSetupFlow, Error> {
    let (user_invite_instance, expiry) = {
        let (user_invite, expiry) = auth_manager.verify_and_decrypt::<UserInvite>(invite_token)?;
        let user_setup_incomplete: Option<bool> =
            auth_manager.user_setup_incomplete(user_invite.get_user_id());
        if user_setup_incomplete.is_none() {
            return Err(InternalError::AccountSetup(AccountSetupError::InvalidInvite).into());
        } else if user_setup_incomplete.unwrap() == false {
            return Err(
                InternalError::AccountSetup(AccountSetupError::AccountSetupNotIncomplete).into(),
            );
        }
        (UserInviteInstance::from_user_invite(user_invite), expiry)
    };
    let email: EmailAddress = user_invite_instance.get_email().to_owned();
    let two_fa_client_secret: String = user_invite_instance.get_two_fa_client_secret().to_owned();
    //TODO: Check expiry, if less than 5 minutes, make it the setup flow duration
    let token_pair: TokenPair;
    if (expiry + Duration::minutes(5)).expired() {
        token_pair = auth_manager.setup_flow_with_expiry(
            headers,
            FlowType::Setup,
            expiry,
            user_invite_instance,
        )?;
    } else {
        token_pair = auth_manager.setup_flow_with_lifetime(
            headers,
            FlowType::Setup,
            Duration::minutes(5),
            user_invite_instance,
        )?;
    };

    let public_encryption_key = auth_manager
        .encryption_keys
        .get_public_encryption_key_string()?;
    Ok(UserSetupFlow::new(
        token_pair,
        email,
        two_fa_client_secret,
        public_encryption_key,
    ))
}

pub async fn validate_invite_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(invite_token): axum::response::Json<InviteToken>,
) -> impl IntoResponse {
    match validate_invite_token(&invite_token.token, &headers, auth_manager) {
        Ok(user_setup_flow) => {
            FullResponseData::basic(ResponseData::InitSetupFlow(user_setup_flow)).into_response()
        }
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::InternalServerError).into_response()
        }
    }
}

fn setup_user_account(
    user_setup: UserSetup,
    headers: &HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<(), Error> {
    let (user_invite_instance, _): (UserInviteInstance, DateTime<Utc>) =
        auth_manager.verify_flow::<UserInviteInstance>(&user_setup.key, headers)?;
    let user_setup_incomplete: Option<bool> =
        auth_manager.user_setup_incomplete(user_invite_instance.get_user_id());
    if user_setup_incomplete.is_none() {
        return Err(InternalError::AccountSetup(AccountSetupError::InvalidInvite).into());
    } else if user_setup_incomplete.unwrap() == false {
        return Err(
            InternalError::AccountSetup(AccountSetupError::AccountSetupNotIncomplete).into(),
        );
    }
    let credentials: SetupCredentials = decrypt_url_safe_base64_with_private_key::<SetupCredentials>(
        user_setup.encrypted_credentials,
        &auth_manager.encryption_keys.get_private_decryption_key(),
    )?;

    //2FA
    let auth = GoogleAuthenticator::new();
    match auth.get_code(&user_invite_instance.get_two_fa_client_secret(), 0) {
        Ok(current_code) => {
            if credentials.two_fa_code != current_code {
                return Err(
                    InternalError::AccountSetup(AccountSetupError::Incorrect2FACode).into(),
                );
            }
        }
        Err(err) => {
            return Err(
                InternalError::AccountSetup(AccountSetupError::GoogleAuthenticator(err)).into(),
            )
        }
    }

    //Password complexity checks
    //TODO: Add all the ones from the UI
    if credentials.password.len() < 16 {
        return Err(InternalError::AccountSetup(AccountSetupError::InvalidPassword).into());
    }

    auth_manager.setup_user(
        user_invite_instance.get_email(),
        credentials.password,
        credentials.display_name,
        user_invite_instance.get_two_fa_client_secret().to_owned(),
    )?;

    Ok(())
}

pub async fn setup_user_account_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_setup): axum::response::Json<UserSetup>,
) -> impl IntoResponse {
    match setup_user_account(user_setup, &headers, auth_manager) {
        Ok(_) => FullResponseData::basic(ResponseData::SetupComplete).into_response(),
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::InternalServerError).into_response()
        }
    }
}
