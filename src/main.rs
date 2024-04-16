use auth::auth_server::AuthServer;
use directories::BaseDirs;
use email_address::EmailAddress;
use std::env;
use std::io::stdout;
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::signal;
use tokio::sync::Notify;
use tracing::level_filters::LevelFilter;
use tracing::{error, warn, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{Layer, Registry};

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
    let logfile_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_writer(file_writer);
    let subscriber = Registry::default().with(stdout_layer).with(logfile_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let stop_notify = Arc::new(Notify::new());
    let stop = Arc::new(AtomicBool::new(false));

    let auth_server: Arc<AuthServer> = match AuthServer::builder()
        .cookie_name("uamtoken".to_string())
        .allowed_origin("http://dev.clouduam.com:81".into())
        .smtp_server("mail.smtp2go.com".to_string())
        .smtp_sender_address(env::var("SMTP_SENDER_ADDRESS").unwrap())
        .smtp_username(env::var("SMTP_USER").unwrap())
        .smtp_password(env::var("SMTP_PASSWORD").unwrap())
        .stop(stop.to_owned())
        .stop_notify(stop_notify.to_owned())
        .start_server()
        .await
    {
        Ok(auth_server) => auth_server,
        Err(err) => panic!("{}", err),
    };
    //testing
    if let Err(err) = auth_server
        .auth_manager
        .invite_user(EmailAddress::new_unchecked("alexinicolaspeck@gmail.com"))
        .await
    {
        warn!("{}", err);
    }

    match signal::ctrl_c().await {
        Ok(_) => {
            stop.store(true, Ordering::SeqCst);
            stop_notify.notify_waiters();
        }
        Err(err) => error!("{}", err),
    }

    Ok(())
}
