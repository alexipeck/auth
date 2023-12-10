use crate::{
    flows::{user_login::LoginFlow, user_setup::UserSetupFlow},
    serde::datetime_utc,
    user_session::UserSession,
};
use axum::{
    body::Body,
    http::{header::CONTENT_SECURITY_POLICY, response::Builder, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use cookie::{
    time::{Duration, OffsetDateTime},
    CookieBuilder, Expiration, SameSite,
};
use serde::Serialize;

fn create_baseline_response() -> Builder {
    let csp_data: String = format!(
        //https://clouduam.com
        "default-src 'self'; \
        script-src 'self' https://api.clouduam.com; \
        img-src 'self' http://dev.clouduam.com:81; \
        media-src 'self'; \
        object-src 'none'; \
        manifest-src 'self'; \
        frame-ancestors 'self'; \
        form-action 'self'; \
        base-uri 'self'"
    );
    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(CONTENT_SECURITY_POLICY, csp_data)
}

#[derive(Debug, Serialize)]
pub struct UserAuthenticated {
    token: String, //will use different type
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub enum ResponseData {
    InitLoginFlow(LoginFlow),
    UserAuthenticated(UserAuthenticated),
    UserSession(UserSession),
    InitSetupFlow(UserSetupFlow),
    SetupComplete,
    CredentialsRejected,
    InternalServerError,
    Unauthorised,
}

pub struct FullResponseData {
    response_data: ResponseData,
    cookie: Option<(String, String, Duration)>,
}

impl FullResponseData {
    pub fn basic(response_data: ResponseData) -> Self {
        Self {
            response_data,
            cookie: None,
        }
    }

    pub fn with_cookie(
        response_data: ResponseData,
        cookie_name: String,
        cookie: String,
        lifetime: Duration,
    ) -> Self {
        Self {
            response_data,
            cookie: Some((cookie_name, cookie, lifetime)),
        }
    }
}

impl IntoResponse for FullResponseData {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self.response_data {
            ResponseData::InitLoginFlow(_)
            | ResponseData::UserAuthenticated(_)
            | ResponseData::UserSession(_)
            | ResponseData::InitSetupFlow(_)
            | ResponseData::SetupComplete => StatusCode::OK,
            ResponseData::CredentialsRejected | ResponseData::Unauthorised => {
                StatusCode::UNAUTHORIZED
            }
            ResponseData::InternalServerError => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json("Internal server error"),
                )
                    .into_response()
            }
        };

        let json_body = match serde_json::to_string(&self.response_data) {
            Ok(json) => json,
            Err(err) => {
                println!("{}", err);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json("Internal server error"),
                )
                    .into_response();
            }
        };

        let mut response_builder = create_baseline_response().status(status_code);
        if let Some((cookie_name, cookie, lifetime)) = self.cookie {
            let cookie = CookieBuilder::new(cookie_name, cookie)
                .http_only(true)
                .secure(true)
                .path("/")
                .domain("clouduam.com")
                .same_site(SameSite::Strict)
                .max_age(lifetime)
                .expires(Expiration::DateTime(OffsetDateTime::now_utc() + lifetime))
                .build();
            response_builder = response_builder.header("Set-Cookie", cookie.to_string());
        }

        match response_builder.body(Body::from(json_body)) {
            Ok(response_body) => response_body,
            Err(err) => {
                println!("{}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json("Internal server error"),
                )
                    .into_response()
            }
        }
    }
}
