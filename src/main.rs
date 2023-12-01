use auth::error::AuthFlowError;
use auth::serde_implementations::datetime_utc;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE};
use axum::http::response::Builder;
use axum::http::{HeaderMap, HeaderName, Method, Response, StatusCode};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Cookie};
use axum_extra::TypedHeader;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake3::Hasher;
use chrono::{DateTime, Duration, Utc};
use cookie::{time, CookieBuilder};
use email_address::EmailAddress;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use tokio::net::TcpListener;
use tower_http::body::Full;

use axum::extract::ConnectInfo;
use axum::routing::{get, post};
use axum::{
    extract::Extension,
    response::{IntoResponse, Json},
    Router,
};
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

const COOKIE_NAME: &str = "uamtoken";

pub struct DummySecurityManager {}

impl Default for DummySecurityManager {
    fn default() -> Self {
        Self {}
    }
}

impl DummySecurityManager {}

pub trait Expired {
    fn expired(&self) -> bool;
}

impl Expired for DateTime<Utc> {
    fn expired(&self) -> bool {
        (self.timestamp() - Utc::now().timestamp()).is_negative()
    }
}

pub struct LoginManager {
    auth_flows: Arc<RwLock<HashMap<String, (Uuid, DateTime<Utc>)>>>,
    auth_lifetime: Duration,
}

impl Default for LoginManager {
    fn default() -> Self {
        Self {
            auth_flows: Arc::new(RwLock::new(HashMap::new())),
            auth_lifetime: Duration::minutes(5),
        }
    }
}

impl LoginManager {
    pub fn setup_auth_flow(&self, headers: &HeaderMap) -> (String, DateTime<Utc>) {
        let salt: Uuid = Uuid::new_v4();
        let key: String = headers.hash_debug(salt);
        let expiry = Utc::now() + self.auth_lifetime;
        self.auth_flows
            .write()
            .insert(key.to_owned(), (salt, expiry.to_owned()));
        (key, expiry)
    }
    pub fn verify_auth_flow(
        &self,
        key: &String,
        headers: &HeaderMap,
    ) -> Result<bool, AuthFlowError> {
        if let Some((salt, expiry)) = self.auth_flows.read().get(key) {
            if expiry.expired() {
                return Err(AuthFlowError::Expired);
            }
            return Ok(&headers.hash_debug(*salt) == key);
        }
        Err(AuthFlowError::Invalid)
    }
    pub fn remove_expired_auth_flows(&self) {
        let mut keys = Vec::new();
        {
            for (key, (_, expiry)) in self.auth_flows.read().iter() {
                if expiry.expired() {
                    keys.push(key.to_owned());
                }
            }
        }
        let mut auth_flows_write_lock = self.auth_flows.write();
        for key in keys.iter() {
            let _ = auth_flows_write_lock.remove(key);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthFlowInit {
    key: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct UserAuthenticated {
    token: String, //will use different type
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct TwoFAVerified {
    jwt: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct LoginCredentials {
    key: String,
    email: EmailAddress,
    password: String,
    two_fa_code: [u8; 6],
}

#[derive(Debug, Deserialize)]
struct AccountSetup {
    invite_key: String,
    password: String,
    two_fa_code: [u8; 6],
}

#[derive(Debug, Deserialize)]
enum Payload {
    Credentials(LoginCredentials),
}

#[derive(Debug, Serialize)]
enum ResponseData {
    AuthFlowInit(AuthFlowInit),
    UserAuthenticated(UserAuthenticated),
    /* AccountSetup() */
    CredentialsRejected,
}

//struct TK((ResponseData, Option<String>));
struct FullResponseData {
    response_data: ResponseData,
    cookie_token: Option<String>,
}

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

impl IntoResponse for FullResponseData {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self.response_data {
            ResponseData::AuthFlowInit(_) | ResponseData::UserAuthenticated(_) => StatusCode::OK,
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
                if let Some(cookie_token) = self.cookie_token {
                    let cookie = CookieBuilder::new(COOKIE_NAME, cookie_token)
                        .http_only(true)
                        .secure(true)
                        .path("/")
                        .max_age(time::Duration::hours(1))
                        .build();
                    response_builder = response_builder.header("Set-Cookie", cookie.to_string());
                } else {
                    println!("UserAuthenticated should have contained a cookie token to send to the client, returning http code 500 to client.");
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

pub fn hash_string(data: &str) -> String {
    let mut hasher = Hasher::new();
    let _ = hasher.update(data.as_bytes());
    hasher.finalize().to_string()
}

pub trait HashDebug {
    fn hash_debug(&self, salt: Uuid) -> String;
}

impl<T: std::fmt::Debug> HashDebug for T {
    fn hash_debug(&self, salt: Uuid) -> String {
        let mut hasher = Hasher::new();
        let _ = hasher.update(format!("{}{:?}", salt, self).as_bytes());
        hasher.finalize().to_string()
    }
}

async fn start_auth_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    /* TypedHeader(cookie): TypedHeader<Cookie>, */
    /* TypedHeader(authorization): TypedHeader<Authorization<Bearer>>, */
    /* Extension(client): Extension<reqwest::Client>, */
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<LoginManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    //println!("{:?}", headers);
    //println!("{:?}", addr);
    let (key, expiry) = login_manager.setup_auth_flow(&headers);
    FullResponseData {
        response_data: ResponseData::AuthFlowInit(AuthFlowInit { key, expiry }),
        cookie_token: None,
    }
}

async fn verify_auth_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    /* TypedHeader(cookie): TypedHeader<Cookie>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>, */
    /* Extension(client): Extension<reqwest::Client>, */
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<LoginManager>>,
    headers: HeaderMap,
    Json(payload): Json<AuthFlowInit>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    /* println!("{:?}", cookie);
    println!("{:?}", authorization); */
    return match login_manager.verify_auth_flow(&payload.key, &headers) {
        Ok(valid) => {
            if valid {
                StatusCode::OK.into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        },
        Err(err) => StatusCode::UNAUTHORIZED.into_response(),
    }
    
}

async fn verify_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    /* Extension(client): Extension<reqwest::Client>, */
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<LoginManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    println!("{:?}", cookie);
    println!("{:?}", authorization);
    StatusCode::OK.into_response()
}

pub async fn run_rest_server(
    login_manager: Arc<LoginManager>,
    security_manager: Arc<DummySecurityManager>,
    _stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
) {
    let client = reqwest::Client::new();
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, COOKIE])
        /* .allow_origin(AllowOrigin::exact("https://clouduam.com".parse().unwrap())) */
        .allow_origin(AllowOrigin::exact(
            "http://dev.clouduam.com:81".parse().unwrap(),
        ))
        .allow_credentials(true);

    let app = Router::new()
        .route("/start-auth-flow", get(start_auth_flow))
        .route("/verify-auth", post(verify_auth))
        .route("/verify-auth-flow", post(verify_auth_flow))
        .layer(cors)
        .layer(Extension(client))
        .layer(Extension(security_manager))
        .layer(Extension(login_manager));

    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8886));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("REST endpoint listening on {}", addr);

    tokio::select! {
        result = async { axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await } => {
            if let Err(err) = result {
                println!("{}", err);
            }
        }
        _ = stop_notify.notified() => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let stop_notify = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let security_manager = Arc::new(DummySecurityManager::default());
    let login_manager = Arc::new(LoginManager::default());

    run_rest_server(login_manager, security_manager, stop, stop_notify).await;

    Ok(())
}
