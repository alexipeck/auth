use auth::auth_manager::AuthManager;
use auth::base::debug_route;
use auth::flows::user_setup::UserInvite;
use auth::routes::login::{init_login_flow_route, login_with_credentials_route};
use auth::routes::setup::{setup_user_account_route, validate_invite_token_route};
use auth::serde::datetime_utc;
use auth::token::Token;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::Method;
use axum::routing::{get, post};
use axum::{extract::Extension, Router};
use chrono::{DateTime, Duration, Utc};
use directories::BaseDirs;
use email_address::EmailAddress;
use serde::{Deserialize, Serialize};
use std::io::stdout;
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};

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

pub async fn run_rest_server(
    auth_manager: Arc<AuthManager>,
    security_manager: Arc<DummySecurityManager>,
    _stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
) {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, COOKIE])
        /* .allow_origin(AllowOrigin::exact("https://clouduam.com".parse().unwrap())) */
        .allow_origin(AllowOrigin::exact(
            auth_manager.config.get_allowed_origin().to_owned(),
        ))
        .allow_credentials(true);

    let app = Router::new()
        .route("/login/init-login-flow", get(init_login_flow_route))
        .route("/debug", post(debug_route))
        .route("/login/credentials", post(login_with_credentials_route))
        .route("/setup/init-setup-flow", post(validate_invite_token_route))
        .route("/setup/credentials", post(setup_user_account_route))
        /* .route("/logout", post(logout)) */
        /* .layer(TraceLayer::new_for_http()) */
        .layer(cors)
        .layer(Extension(security_manager))
        .layer(Extension(auth_manager));

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
    let cookie_name: String = "uamtoken".to_string(); //This won't exist and will be passed down from AuthManager
    let allowed_origin: String = "http://dev.clouduam.com:81".to_owned(); //https://clouduam.com

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
    let logfile_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_writer(file_writer);
    let subscriber = Registry::default().with(stdout_layer).with(logfile_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let stop_notify = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));
    let security_manager = Arc::new(DummySecurityManager::default());
    let auth_manager = match AuthManager::new(cookie_name, allowed_origin) {
        Ok(auth_manager) => auth_manager,
        Err(err) => {
            panic!("{}", err);
        }
    };
    {
        //debug
        if let Ok(invite_link) =
            auth_manager.invite_user(EmailAddress::new_unchecked("alexinicolaspeck@gmail.com"))
        {
            println!("{}", invite_link);
        }
        //auth_manager.setup_user(&EmailAddress::new_unchecked("alexinicolaspeck@gmail.com"), "vK9AzpihNTCvH%YTmfx8uaMDDZ3^L%79DJDXdZCpKXYgrjN4p3Ff$qf3v4kRN&AN@Lve4z#Bf&pv^Ra@f@kKKEpW^WCra&PK^Gq@dcg@gRwVAUUfvE*@ZwpU^TVHKw35".to_string(), "Alexi Peck".to_string(), "HX4IXEYSPJMHEG36YNEOQDPTKAUDF6YMFBDRCO3Z5LWXQGVO25KOTVWB2UOYWJFH".to_string()).unwrap();
    }

    let auth_manager = Arc::new(auth_manager);

    run_rest_server(auth_manager, security_manager, stop, stop_notify).await;

    Ok(())
}
