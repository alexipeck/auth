use crate::{
    auth_manager::{AuthManager, FlowType},
    error::{AccountSetupError, Error, TokenError},
    flows::user_setup::{InviteToken, SetupCredentials, UserInvite, UserSetup},
};
use axum::{
    body::Body,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension,
};
use axum_extra::{headers::Cookie, TypedHeader};
use chrono::{Duration, Utc};
use cookie::{time::OffsetDateTime, CookieBuilder, SameSite};
use google_authenticator::GoogleAuthenticator;
use peck_lib::{crypto::generate_random_base32_string, datetime::r#trait::Expired};
use std::sync::Arc;
use tracing::warn;

async fn validate_invite_token(
    invite_token: &str,
    headers: &HeaderMap,
    auth_manager: Arc<AuthManager>,
) -> Result<(String, String, i64, String), Error> {
    let (user_invite, expiry) = auth_manager.verify_and_decrypt::<UserInvite>(invite_token)?;
    let expiry = match expiry {
        Some(expiry) => expiry,
        None => return Err(Error::Token(TokenError::MissingExpiry)),
    };
    let user_setup_incomplete: Option<bool> = auth_manager
        .user_setup_incomplete(user_invite.get_user_uid())
        .await;
    match user_setup_incomplete {
        Some(false) => {
            return Err(Error::AccountSetup(
                AccountSetupError::AccountSetupAlreadyComplete,
            ))
        }
        None => return Err(Error::AccountSetup(AccountSetupError::InvalidInvite)),
        _ => {}
    }
    let two_fa_client_secret: String = generate_random_base32_string(64);
    let (tokenized_two_fa_client_secret, seconds_until_expiry) =
        if (expiry + Duration::seconds(auth_manager.config.invite_flow_lifetime_seconds)).expired()
        {
            (
                auth_manager
                    .setup_flow_with_expiry(
                        headers,
                        FlowType::Setup,
                        expiry,
                        true,
                        two_fa_client_secret.to_owned(),
                    )?
                    .token,
                (expiry - Utc::now()).num_seconds() - 5,
            )
        } else {
            (
                auth_manager
                    .setup_flow_with_lifetime(
                        headers,
                        FlowType::Setup,
                        Duration::seconds(auth_manager.config.invite_flow_lifetime_seconds),
                        true,
                        two_fa_client_secret.to_owned(),
                    )?
                    .token,
                auth_manager.config.invite_flow_lifetime_seconds - 5,
            )
        };
    if seconds_until_expiry.is_negative() {
        return Err(Error::AccountSetup(
            AccountSetupError::GracePeriodExpiryIsNegative,
        ));
    }
    //give client num_seconds until expiry, cookie including invite token and encrypted cookie containing 2FA secret to guarantee server generated secret
    Ok((
        two_fa_client_secret,
        tokenized_two_fa_client_secret,
        seconds_until_expiry,
        invite_token.to_string(),
    ))
}

pub async fn validate_invite_token_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(invite_token): axum::response::Json<InviteToken>,
) -> impl IntoResponse {
    match validate_invite_token(&invite_token.token, &headers, auth_manager.to_owned()).await {
        Ok((
            two_fa_client_secret,
            tokenized_two_fa_client_secret,
            seconds_until_expiry,
            invite_token,
        )) => {
            let mut builder = Response::builder().status(StatusCode::OK);

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_setup",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    tokenized_two_fa_client_secret,
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
                        "{base}_invite",
                        base = auth_manager.config.get_cookie_name_base()
                    ),
                    invite_token,
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

            match builder.body(Body::from(
                match serde_json::to_string(&UserSetup {
                    two_fa_client_secret,
                }) {
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
                Error::AccountSetup(
                    AccountSetupError::InvalidInvite
                    | AccountSetupError::AccountSetupAlreadyComplete,
                ) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
            .into_response()
        }
    }
}

async fn setup_user_account(
    user_invite: UserInvite,
    credentials: SetupCredentials,
    two_fa_client_secret: String,
    auth_manager: Arc<AuthManager>,
) -> Result<(), Error> {
    let user_setup_incomplete: Option<bool> = auth_manager
        .user_setup_incomplete(user_invite.get_user_uid())
        .await;
    if user_setup_incomplete.is_none() {
        return Err(Error::AccountSetup(AccountSetupError::InvalidInvite));
    } else if !user_setup_incomplete.unwrap() {
        return Err(Error::AccountSetup(
            AccountSetupError::AccountSetupAlreadyComplete,
        ));
    }

    //2FA
    let auth = GoogleAuthenticator::new();
    match auth.get_code(&two_fa_client_secret, 0) {
        Ok(current_code) => {
            if credentials.two_fa_code != current_code {
                return Err(Error::AccountSetup(AccountSetupError::Incorrect2FACode));
            }
        }
        Err(err) => {
            return Err(Error::AccountSetup(AccountSetupError::GoogleAuthenticator(
                err,
            )))
        }
    }

    //Password complexity checks
    //TODO: Add all the ones from the UI
    if credentials.password.len() < 16 {
        return Err(Error::AccountSetup(AccountSetupError::InvalidPassword));
    }

    auth_manager
        .setup_user(
            user_invite.get_email(),
            credentials.password,
            credentials.display_name,
            two_fa_client_secret,
        )
        .await?;

    Ok(())
}

pub async fn setup_user_account_route(
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    headers: HeaderMap,
    axum::response::Json(setup_credentials): axum::response::Json<SetupCredentials>,
) -> impl IntoResponse {
    let invite_token = match cookies.get(&format!(
        "{base}_invite",
        base = auth_manager.config.get_cookie_name_base()
    )) {
        Some(invite_token) => invite_token,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let tokenized_two_fa_client_secret = match cookies.get(&format!(
        "{base}_setup",
        base = auth_manager.config.get_cookie_name_base()
    )) {
        Some(tokenized_two_fa_client_secret) => tokenized_two_fa_client_secret,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let two_fa_client_secret = match auth_manager.verify_flow::<String>(
        tokenized_two_fa_client_secret,
        &headers,
        &FlowType::Setup,
        true,
    ) {
        Ok((two_fa_client_secret, _)) => two_fa_client_secret,
        Err(err) => {
            warn!("{err}");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let (user_invite, _expiry) = match auth_manager.verify_and_decrypt::<UserInvite>(invite_token) {
        Ok(user_invite) => user_invite,
        Err(err) => {
            warn!("{err}");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    match setup_user_account(
        user_invite,
        setup_credentials,
        two_fa_client_secret,
        auth_manager.to_owned(),
    )
    .await
    {
        Ok(_) => {
            let mut builder = Response::builder().status(StatusCode::OK);

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_setup",
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
            );

            builder = builder.header(
                SET_COOKIE,
                CookieBuilder::new(
                    format!(
                        "{base}_invite",
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
            );

            match builder.body(Body::empty()) {
                Ok(response) => response,
                Err(err) => {
                    warn!("{err}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        Err(err) => match err {
            Error::AccountSetup(AccountSetupError::InvalidPassword) => {
                (StatusCode::BAD_REQUEST, "InvalidPassword").into_response()
            }
            Error::AccountSetup(AccountSetupError::Incorrect2FACode) => {
                (StatusCode::BAD_REQUEST, "Incorrect2FACode").into_response()
            }
            Error::AccountSetup(
                AccountSetupError::InvalidInvite | AccountSetupError::AccountSetupAlreadyComplete,
            ) => (StatusCode::CONFLICT, "InvalidInvite").into_response(),
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
    }
}
