use auth::auth_manager::AuthManager;
use auth::bidirectional::LoginFlow;
use auth::credentials::LoginCredentials;
use auth::response::{FullResponseData, ResponseData};
use auth::serde::datetime_utc;
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::{get, post};
use axum::{
    extract::Extension,
    response::{IntoResponse, Json},
    Router,
};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Cookie};
use axum_extra::TypedHeader;
use chrono::{DateTime, Utc};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};
use std::env;
use std::io::stdout;
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub struct DummySecurityManager {}

impl Default for DummySecurityManager {
    fn default() -> Self {
        Self {}
    }
}

impl DummySecurityManager {}

#[derive(Debug, Serialize)]
struct TwoFAVerified {
    jwt: String,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
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

async fn init_login_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    /* TypedHeader(cookie): TypedHeader<Cookie>, */
    /* TypedHeader(authorization): TypedHeader<Authorization<Bearer>>, */
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", headers);
    //println!("{:?}", addr);
    let (key, expiry) = login_manager.setup_login_flow(&headers);
    FullResponseData::basic(ResponseData::InitLoginFlow(LoginFlow::new(key, expiry)))
}

async fn verify_login_flow(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(login_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(login_flow): axum::response::Json<LoginFlow>,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    /* println!("{:?}", cookie);
    println!("{:?}", authorization); */
    return match login_manager.verify_login_flow(&login_flow, &headers) {
        Ok(valid) => {
            if valid {
                StatusCode::OK.into_response()
            } else {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
        Err(err) => StatusCode::UNAUTHORIZED.into_response(),
    };
}

async fn verify_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    println!("{:?}", cookie);
    println!("{:?}", authorization);
    StatusCode::OK.into_response()
}

async fn invite_user(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    Extension(login_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    println!("{:?}", cookie);
    println!("{:?}", authorization);
    StatusCode::OK.into_response()
}

pub async fn run_rest_server(
    login_manager: Arc<AuthManager>,
    security_manager: Arc<DummySecurityManager>,
    _stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
) {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, COOKIE])
        /* .allow_origin(AllowOrigin::exact("https://clouduam.com".parse().unwrap())) */
        .allow_origin(AllowOrigin::exact(
            "http://dev.clouduam.com:81".parse().unwrap(),
        ))
        .allow_credentials(true);

    let app = Router::new()
        .route("/init-login-flow", get(init_login_flow))
        .route("/verify-auth", post(verify_auth))
        .route("/verify-login-flow", post(verify_login_flow))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_dirs = BaseDirs::new().unwrap();
    let log_path = base_dirs.config_dir().join("auth/logs/");

    let file = tracing_appender::rolling::daily(log_path, "auth_server");
    let (stdout_writer, _guard) = tracing_appender::non_blocking(stdout());
    let (file_writer, _guard) = tracing_appender::non_blocking(file);

    let level_filter = LevelFilter::from_level({
        let display_level = Level::TRACE;
        display_level
    });

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_writer(stdout_writer)
        .with_filter(level_filter);
    let logfile_layer = tracing_subscriber::fmt::layer().with_line_number(true).with_writer(file_writer);
    let subscriber = Registry::default().with(stdout_layer).with(logfile_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let stop_notify = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let security_manager = Arc::new(DummySecurityManager::default());
    let login_manager = Arc::new(AuthManager::default());

    run_rest_server(login_manager, security_manager, stop, stop_notify).await;

    Ok(())
}
