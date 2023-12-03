use crate::{bidirectional::LoginFlow, serde::datetime_utc};
use axum::{
    body::Body,
    http::{header::CONTENT_SECURITY_POLICY, response::Builder, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use cookie::{time, CookieBuilder};
use serde::Serialize;

fn create_baseline_response() -> Builder {
    let csp_data: String = format!(
        "default-src 'self'; \
        script-src 'self' https://api.clouduam.com; \
        img-src 'self' https://clouduam.com http://dev.clouduam.com:81; \
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
    /* AccountSetup() */
    CredentialsRejected,
}

pub struct FullResponseData {
    response_data: ResponseData,
    cookie_name: Option<String>,
    cookie_token: Option<String>,
}

impl FullResponseData {
    pub fn basic(response_data: ResponseData) -> Self {
        Self {
            response_data,
            cookie_name: None,
            cookie_token: None,
        }
    }

    pub fn with_cookie(response_data: ResponseData, cookie_name: String, cookie: String) -> Self {
        Self {
            response_data,
            cookie_name: Some(cookie_name),
            cookie_token: Some(cookie),
        }
    }
}

impl IntoResponse for FullResponseData {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self.response_data {
            ResponseData::InitLoginFlow(_) | ResponseData::UserAuthenticated(_) => StatusCode::OK,
            ResponseData::CredentialsRejected => StatusCode::UNAUTHORIZED,
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

        match self.response_data {
            ResponseData::UserAuthenticated(_) => {
                let mut success: bool = false;
                if let Some(cookie_name) = self.cookie_name {
                    if let Some(cookie_token) = self.cookie_token {
                        let cookie = CookieBuilder::new(cookie_name, cookie_token)
                            .http_only(true)
                            .secure(true)
                            .path("/")
                            .max_age(time::Duration::hours(1))
                            .build();
                        response_builder =
                            response_builder.header("Set-Cookie", cookie.to_string());
                        success = true;
                    }
                }
                if !success {
                    println!("UserAuthenticated should have contained a cookie token and cookie name to send to the client, returning http code 500 to client.");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json("Internal server error"),
                    )
                        .into_response();
                }
            }
            _ => {}
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
