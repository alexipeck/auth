use core::fmt;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use tokio::sync::Notify;

use crate::{error::{Error, InternalError, AuthServerBuildError}, auth_manager::AuthManager};


pub struct Signals {
    stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
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
            }
        )
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
    database_path: Option<String>,
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

    pub fn database_path(mut self, database_path: String) -> Self {
        self.database_path = Some(database_path);
        self
    }

    pub fn build(self) -> Result<AuthServer, Error> {
        let mut missing_properties: Vec<RequiredProperties> = Vec::new();
        if self.cookie_name.is_none() {
            missing_properties.push(RequiredProperties::CookieName)
        }
        if self.allowed_origin.is_none() {
            missing_properties.push(RequiredProperties::AllowedOrigin)
        }
        if self.smtp_server.is_none() {
            missing_properties.push(RequiredProperties::SMTPServer)
        }
        if self.smtp_sender_address.is_none() {
            missing_properties.push(RequiredProperties::SMTPSenderAddress)
        }
        if self.smtp_username.is_none() {
            missing_properties.push(RequiredProperties::SMTPUsername)
        }
        if self.smtp_password.is_none() {
            missing_properties.push(RequiredProperties::SMTPPassword)
        }
        if !missing_properties.is_empty() {
            return Err(InternalError::AuthServerBuild(AuthServerBuildError::MissingProperties(format!("{:?}", missing_properties))).into())
        }
        let auth_manager: AuthManager = AuthManager::new(
            self.cookie_name.unwrap(),
            self.allowed_origin.unwrap(),
            self.smtp_server.unwrap(),
            self.smtp_sender_address.unwrap(),
            self.smtp_username.unwrap(),
            self.smtp_password.unwrap(),
        )?;
        let signals = Signals {
            stop: self.stop.unwrap_or(Arc::new(AtomicBool::new(false))),
            stop_notify: self.stop_notify.unwrap_or(Arc::new(Notify::new()))
        };
        Ok(AuthServer { auth_manager: Arc::new(auth_manager), signals })
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