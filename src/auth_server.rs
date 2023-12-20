use core::fmt;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use axum::{
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE},
        Method,
    },
    routing::{get, post},
    Extension, Router,
};
use tokio::{net::TcpListener, sync::Notify};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, error};

use crate::{
    auth_manager::AuthManager,
    base::debug_route,
    error::{AuthServerBuildError, Error, InternalError},
    routes::{
        authenticated::refresh_read_token_route,
        login::{init_login_flow_route, login_with_credentials_route},
        setup::{setup_user_account_route, validate_invite_token_route},
    },
};

pub struct Signals {
    pub stop: Arc<AtomicBool>,
    pub stop_notify: Arc<Notify>,
}

impl Signals {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.stop_notify.notify_waiters();
    }

    pub fn clone_stop(&self) -> Arc<AtomicBool> {
        self.stop.to_owned()
    }

    pub fn clone_stop_notify(&self) -> Arc<Notify> {
        self.stop_notify.to_owned()
    }
}

#[derive(Debug)]
pub enum RequiredProperties {
    CookieName,
    AllowedOrigin,
    SMTPServer,
    SMTPSenderAddress,
    SMTPUsername,
    SMTPPassword,
    DatabaseUrl,
}

impl fmt::Display for RequiredProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::CookieName => "CookieName",
                Self::AllowedOrigin => "AllowedOrigin",
                Self::SMTPServer => "SMTPServer",
                Self::SMTPSenderAddress => "SMTPSenderAddress",
                Self::SMTPUsername => "SMTPUsername",
                Self::SMTPPassword => "SMTPPassword",
                Self::DatabaseUrl => "DatabaseUrl",
            }
        )
    }
}

async fn start_server(auth_server: Arc<AuthServer>) {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, COOKIE])
        /* .allow_origin(AllowOrigin::exact("https://clouduam.com".parse().unwrap())) */
        .allow_origin(AllowOrigin::exact(
            auth_server
                .auth_manager
                .config
                .get_allowed_origin()
                .to_owned(),
        ))
        .allow_credentials(true);

    let app = Router::new()
        .route("/login/init-login-flow", get(init_login_flow_route))
        .route("/debug", post(debug_route))
        .route("/login/credentials", post(login_with_credentials_route))
        .route("/setup/init-setup-flow", post(validate_invite_token_route))
        .route("/setup/credentials", post(setup_user_account_route))
        .route(
            "/authenticated/refresh-read-token",
            post(refresh_read_token_route),
        )
        /* .route(
            "/authenticated/twofa-for-write-token",
            post(get_new_write_token_route),
        ) */
        /* .route("/logout", post(logout)) */
        /* .layer(TraceLayer::new_for_http()) */
        .layer(cors)
        .layer(Extension(auth_server.auth_manager.to_owned()));

    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 8886));
    let listener = TcpListener::bind(addr).await.unwrap();
    info!("REST endpoint listening on {}", addr);

    tokio::select! {
        result = async { axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await } => {
            if let Err(err) = result {
                panic!("{}", err);
            }
        }
        _ = auth_server.signals.stop_notify.notified() => {},
    }
}

#[derive(Default)]
pub struct Builder {
    //required
    cookie_name: Option<String>,
    allowed_origin: Option<String>,
    smtp_server: Option<String>,
    smtp_sender_address: Option<String>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,

    //optional
    stop: Option<Arc<AtomicBool>>,
    stop_notify: Option<Arc<Notify>>,
    database_url: Option<String>,
}

impl Builder {
    pub fn cookie_name(mut self, cookie_name: String) -> Self {
        self.cookie_name = Some(cookie_name);
        self
    }

    pub fn allowed_origin(mut self, allowed_origin: String) -> Self {
        self.allowed_origin = Some(allowed_origin);
        self
    }

    pub fn smtp_server(mut self, smtp_server: String) -> Self {
        self.smtp_server = Some(smtp_server);
        self
    }

    pub fn smtp_sender_address(mut self, smtp_sender_address: String) -> Self {
        self.smtp_sender_address = Some(smtp_sender_address);
        self
    }

    pub fn smtp_username(mut self, smtp_username: String) -> Self {
        self.smtp_username = Some(smtp_username);
        self
    }

    pub fn smtp_password(mut self, smtp_password: String) -> Self {
        self.smtp_password = Some(smtp_password);
        self
    }

    pub fn stop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }

    pub fn stop_notify(mut self, stop_notify: Arc<Notify>) -> Self {
        self.stop_notify = Some(stop_notify);
        self
    }

    pub fn database_url(mut self, database_url: String) -> Self {
        self.database_url = Some(database_url);
        self
    }

    pub async fn start_server(self) -> Result<Arc<AuthServer>, Error> {
        let mut missing_properties: Vec<RequiredProperties> = Vec::new();
        if self.cookie_name.is_none() {
            missing_properties.push(RequiredProperties::CookieName);
        }
        if self.allowed_origin.is_none() {
            missing_properties.push(RequiredProperties::AllowedOrigin);
        }
        if self.smtp_server.is_none() {
            missing_properties.push(RequiredProperties::SMTPServer);
        }
        if self.smtp_sender_address.is_none() {
            missing_properties.push(RequiredProperties::SMTPSenderAddress);
        }
        if self.smtp_username.is_none() {
            missing_properties.push(RequiredProperties::SMTPUsername);
        }
        if self.smtp_password.is_none() {
            missing_properties.push(RequiredProperties::SMTPPassword);
        }
        if self.database_url.is_none() {
            missing_properties.push(RequiredProperties::DatabaseUrl);
        }
        if !missing_properties.is_empty() {
            return Err(
                InternalError::AuthServerBuild(AuthServerBuildError::MissingProperties(format!(
                    "{:?}",
                    missing_properties
                )))
                .into(),
            );
        }
        let auth_manager: AuthManager = AuthManager::new(
            self.cookie_name.unwrap(),
            self.allowed_origin.unwrap(),
            self.smtp_server.unwrap(),
            self.smtp_sender_address.unwrap(),
            self.smtp_username.unwrap(),
            self.smtp_password.unwrap(),
            self.database_url.unwrap(),
        )?;
        let signals = Signals {
            stop: self.stop.unwrap_or(Arc::new(AtomicBool::new(false))),
            stop_notify: self.stop_notify.unwrap_or(Arc::new(Notify::new())),
        };

        let auth_server: Arc<AuthServer> = Arc::new(AuthServer {
            auth_manager: Arc::new(auth_manager),
            signals,
        });

        let auth_server_ = auth_server.to_owned();
        tokio::spawn(async move { start_server(auth_server_).await });

        Ok(auth_server)
    }
}

pub struct AuthServer {
    pub auth_manager: Arc<AuthManager>,
    pub signals: Signals,
}

impl AuthServer {
    pub fn builder() -> Builder {
        Builder::default()
    }
}
