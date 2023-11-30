use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake3::Hasher;
use chrono::{DateTime, Utc, Duration};
use email_address::EmailAddress;
use parking_lot::RwLock;
use auth::error::AuthFlowError;
use auth::serde_implementations::datetime_utc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::error::Error;



use axum::extract::ConnectInfo;
use axum::headers::authorization::Bearer;
use axum::headers::{Authorization, Cookie};
use axum::routing::get;
use axum::{
    extract::{Extension, TypedHeader},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, ACCESS_CONTROL_ALLOW_CREDENTIALS, COOKIE};
use reqwest::{Method};
use std::net::SocketAddr;
use std::str::from_utf8;
use std::sync::{atomic::AtomicBool, Arc};
use std::time::Instant;
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

pub struct DummySecurityManager {

}

impl Default for DummySecurityManager {
    fn default() -> Self {
        Self {
            
        }
    }
}

impl DummySecurityManager {
    
}

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
        self.auth_flows.write().insert(key.to_owned(), (salt, expiry.to_owned()));
        (key, expiry)
    }
    pub fn verify_auth_flow(&self, key: &String, headers: &HeaderMap) -> Result<bool, AuthFlowError> {
        if let Some((salt, expiry)) = self.auth_flows.read().get(key) {
            if expiry.expired() {
                return Err(AuthFlowError::Expired)
            }
            return Ok(&headers.hash_debug(*salt) == key)
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

#[derive(Debug, Serialize)]
struct authFlowInit {
    key: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct UserAuthenticated {
    token: String,//will use different type
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
enum Response {
    AuthFlowInit(authFlowInit),
    UserAuthenticated(UserAuthenticated),
    /* AccountSetup() */
    CredentialsRejected,
}

impl IntoResponse for Response {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self {
            Self::AuthFlowInit(_) | Self::UserAuthenticated(_) => StatusCode::OK,
            Self::CredentialsRejected => StatusCode::UNAUTHORIZED,
        };
        (status_code, Json(self)).into_response()
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
    let (key, expiry) = login_manager.setup_auth_flow(&headers);
    Response::AuthFlowInit(authFlowInit { key, expiry })
}

pub async fn run_rest_server(
    login_manager: Arc<LoginManager>,
    security_manager: Arc<DummySecurityManager>,
    _stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
) {
    let client = reqwest::Client::new();
    let cors = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, COOKIE])
        /* .allow_origin(AllowOrigin::exact("https://clouduam.com".parse().unwrap())) */
        .allow_origin(AllowOrigin::exact("http://dev.clouduam.com:81".parse().unwrap()))
        .allow_credentials(true);

    let app = Router::new()
        .route("/start-auth-flow", get(start_auth_flow))
        .layer(cors)
        .layer(Extension(client))
        .layer(Extension(security_manager))
        .layer(Extension(login_manager));

    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8886));
    println!("REST endpoint listening on {}", addr);
    tokio::select! {
        _ = axum::Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>()) => {},
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
