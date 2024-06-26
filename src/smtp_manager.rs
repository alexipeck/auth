use crate::error::{Error, LettreError, SmtpAddressError, SmtpError, SmtpTransportError};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::{authentication::Credentials, response::Response, SmtpTransportBuilder},
    Message, SmtpTransport, Transport,
};

pub struct SmtpManager {
    sender_address: Mailbox,
    mailer: SmtpTransport,
}

impl SmtpManager {
    pub fn new(
        server: String,
        sender_address: String,
        username: String,
        password: String,
    ) -> Result<Self, Error> {
        let sender_address: Mailbox = match sender_address.parse() {
            Ok(sender_address) => sender_address,
            Err(err) => {
                return Err(Error::Smtp(SmtpError::ServerAddressParse(
                    SmtpAddressError(err),
                )))
            }
        };
        let smtp_transport_builder: SmtpTransportBuilder = match SmtpTransport::relay(&server) {
            Ok(smtp_transport_builder) => smtp_transport_builder,
            Err(err) => {
                return Err(Error::Smtp(SmtpError::SmtpTransportRelayBuild(
                    SmtpTransportError(err),
                )))
            }
        };
        let mailer: SmtpTransport = smtp_transport_builder
            .credentials(Credentials::new(username, password))
            .build();
        Ok(Self {
            sender_address,
            mailer,
        })
    }

    pub fn send_email_to_recipient(
        &self,
        recipient: String,
        subject: String,
        content: String,
    ) -> Result<Response, Error> {
        let recipient: Mailbox = match recipient.parse() {
            Ok(recipient) => recipient,
            Err(err) => {
                return Err(Error::Smtp(SmtpError::RecipientAddressParse(
                    SmtpAddressError(err),
                )))
            }
        };
        let message = match Message::builder()
            .from(self.sender_address.to_owned())
            .to(recipient)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(content)
        {
            Ok(message) => message,
            Err(err) => return Err(Error::Smtp(SmtpError::MessageBuilder(LettreError(err)))),
        };

        match self.mailer.send(&message) {
            Ok(response) => Ok(response),
            Err(err) => Err(Error::Smtp(SmtpError::MessageSend(SmtpTransportError(err)))),
        }
    }
}
