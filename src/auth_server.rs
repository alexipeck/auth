use crate::{
    auth_manager::AuthManager,
    error::{AuthServerBuildError, Error},
    routes::{
        authenticated::{get_user_profile_route, get_write_token_route, refresh_read_token_route},
        debug_route, keep_alive_route,
        login::{init_login_flow_route, login_with_credentials_route, logout_route},
        setup::{setup_user_account_route, validate_invite_token_route},
    },
    DEFAULT_INVITE_FLOW_LIFETIME_SECONDS, DEFAULT_INVITE_LIFETIME_SECONDS,
    DEFAULT_LOGIN_FLOW_LIFETIME_SECONDS, DEFAULT_MAX_SESSION_LIFETIME_SECONDS,
    DEFAULT_READ_LIFETIME_SECONDS, DEFAULT_REFRESH_IN_LAST_X_SECONDS,
    DEFAULT_WRITE_LIFETIME_SECONDS,
};
use axum::{
    http::{
        header::{ACCESS_CONTROL_ALLOW_ORIGIN, AUTHORIZATION, CONTENT_TYPE, COOKIE, ORIGIN},
        Method,
    },
    routing::{get, post},
    Extension, Router,
};
use core::fmt;
use peck_lib::uid::authority::UIDAuthority;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{net::TcpListener, sync::Notify};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;

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
    Port,
    CookieDomain,
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
                Self::Port => "Port",
                Self::CookieDomain => "CookieDomain",
            }
        )
    }
}

async fn start_server(auth_server: Arc<AuthServer>) {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(vec![
            CONTENT_TYPE,
            AUTHORIZATION,
            COOKIE,
            ACCESS_CONTROL_ALLOW_ORIGIN,
            ORIGIN,
        ])
        .allow_origin(AllowOrigin::list(
            auth_server
                .auth_manager
                .config
                .get_allowed_origin()
                .to_owned(),
        ))
        .allow_credentials(true);

    let app = Router::new()
        .nest(
            "/auth",
            Router::new()
                .route("/login/init-flow", get(init_login_flow_route))
                .route("/logout", get(logout_route))
                .route("/debug", post(debug_route))
                .route("/login/credentials", post(login_with_credentials_route))
                .route("/setup/init-setup-flow", post(validate_invite_token_route))
                .route("/setup/credentials", post(setup_user_account_route))
                .route(
                    "/authenticated/refresh-read-token",
                    get(refresh_read_token_route),
                )
                .route(
                    "/authenticated/get-write-token",
                    post(get_write_token_route),
                )
                .route("/authenticated/user-profile", get(get_user_profile_route))
                .route("/keep-alive", get(keep_alive_route))
                .layer(cors.to_owned())
                .layer(Extension(auth_server.auth_manager.to_owned())),
        )
        .layer(cors)
        .layer(Extension(auth_server.auth_manager.to_owned()))
        /* .layer(TraceLayer::new_for_http()) */;

    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], auth_server.auth_manager.port));
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

pub struct Builder {
    //required
    cookie_name_base: Option<String>,
    allowed_origins: Vec<String>,
    smtp_server: Option<String>,
    smtp_sender_address: Option<String>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    port: Option<u16>,
    cookie_domain: Option<String>,
    database_url: Option<String>,

    //optional
    stop: Option<Arc<AtomicBool>>,
    stop_notify: Option<Arc<Notify>>,
    uid_authority: Option<Arc<UIDAuthority>>,
    persistent_encryption_keys_path: Option<String>,

    //defaulted
    read_lifetime_seconds: i64,
    write_lifetime_seconds: i64,
    refresh_in_last_x_seconds: i64,
    max_session_lifetime_seconds: i64,
    invite_lifetime_seconds: i64,
    login_flow_lifetime_seconds: i64,
    invite_flow_lifetime_seconds: i64,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            cookie_name_base: None,
            allowed_origins: Vec::new(),
            smtp_server: None,
            smtp_sender_address: None,
            smtp_username: None,
            smtp_password: None,
            port: None,
            cookie_domain: None,
            database_url: None,
            stop: None,
            stop_notify: None,
            uid_authority: None,
            persistent_encryption_keys_path: None,
            read_lifetime_seconds: DEFAULT_READ_LIFETIME_SECONDS,
            write_lifetime_seconds: DEFAULT_WRITE_LIFETIME_SECONDS,
            refresh_in_last_x_seconds: DEFAULT_REFRESH_IN_LAST_X_SECONDS,
            max_session_lifetime_seconds: DEFAULT_MAX_SESSION_LIFETIME_SECONDS,
            invite_lifetime_seconds: DEFAULT_INVITE_LIFETIME_SECONDS,
            login_flow_lifetime_seconds: DEFAULT_LOGIN_FLOW_LIFETIME_SECONDS,
            invite_flow_lifetime_seconds: DEFAULT_INVITE_FLOW_LIFETIME_SECONDS,
        }
    }
}

impl Builder {
    pub fn persistent_encryption_keys_path(mut self, path: String) -> Self {
        self.persistent_encryption_keys_path = Some(path);
        self
    }
    pub fn cookie_name_base(mut self, cookie_name_base: String) -> Self {
        self.cookie_name_base = Some(cookie_name_base);
        self
    }

    pub fn uid_authority(mut self, uid_authority: Arc<UIDAuthority>) -> Self {
        self.uid_authority = Some(uid_authority);
        self
    }

    pub fn allowed_origin(mut self, allowed_origin: String) -> Self {
        self.allowed_origins.push(allowed_origin);
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

    pub fn serve_on_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn cookie_domain(mut self, cookie_domain: String) -> Self {
        self.cookie_domain = Some(cookie_domain);
        self
    }

    pub fn read_lifetime_seconds(mut self, lifetime: i64) -> Self {
        self.read_lifetime_seconds = lifetime;
        self
    }

    pub fn write_lifetime_seconds(mut self, lifetime: i64) -> Self {
        self.write_lifetime_seconds = lifetime;
        self
    }

    pub fn max_session_lifetime_seconds(mut self, lifetime: i64) -> Self {
        self.max_session_lifetime_seconds = lifetime;
        self
    }

    pub fn invite_lifetime_seconds(mut self, lifetime: i64) -> Self {
        self.invite_lifetime_seconds = lifetime;
        self
    }

    pub async fn start_server(self) -> Result<Arc<AuthServer>, Error> {
        let mut missing_properties: Vec<RequiredProperties> = Vec::new();
        if self.cookie_name_base.is_none() {
            missing_properties.push(RequiredProperties::CookieName);
        }
        if self.allowed_origins.is_empty() {
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
        if self.port.is_none() {
            missing_properties.push(RequiredProperties::Port);
        }
        if self.cookie_domain.is_none() {
            missing_properties.push(RequiredProperties::CookieDomain);
        }
        if !missing_properties.is_empty() {
            return Err(Error::AuthServerBuild(
                AuthServerBuildError::MissingProperties(format!("{:?}", missing_properties)),
            ));
        }

        let auth_manager: AuthManager = AuthManager::new(
            self.cookie_name_base.unwrap(),
            self.allowed_origins,
            self.smtp_server.unwrap(),
            self.smtp_sender_address.unwrap(),
            self.smtp_username.unwrap(),
            self.smtp_password.unwrap(),
            self.database_url.unwrap(),
            self.port.unwrap(),
            self.cookie_domain.unwrap(),
            self.uid_authority,
            self.persistent_encryption_keys_path,
            self.read_lifetime_seconds,
            self.write_lifetime_seconds,
            self.refresh_in_last_x_seconds,
            self.max_session_lifetime_seconds,
            self.login_flow_lifetime_seconds,
            self.invite_flow_lifetime_seconds,
            self.invite_lifetime_seconds,
        )
        .await?;
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
