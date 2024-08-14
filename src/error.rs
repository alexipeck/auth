use email_address::EmailAddress;
use google_authenticator::GAError;
use peck_lib::{
    auth::error::{RSAError, SerdeError},
    impl_error_wrapper,
    uid::error::UIDAuthorityError,
};
use thiserror::Error;
use uuid::Uuid;

impl_error_wrapper!(Base64DecodeError, base64::DecodeError);
impl_error_wrapper!(FromUtf8Error, std::string::FromUtf8Error);
impl_error_wrapper!(Utf8Error, core::str::Utf8Error);
impl_error_wrapper!(SmtpAddressError, lettre::address::AddressError);
impl_error_wrapper!(SmtpTransportError, lettre::transport::smtp::Error);
impl_error_wrapper!(LettreError, lettre::error::Error);
impl_error_wrapper!(UuidError, uuid::Error);
impl_error_wrapper!(DieselResultError, diesel::result::Error);
impl_error_wrapper!(TomlSerError, toml::ser::Error);
impl_error_wrapper!(TomlDeError, toml::de::Error);
impl_error_wrapper!(StdIoError, std::io::Error);
impl_error_wrapper!(PKCS1Error, pkcs1::Error);
impl_error_wrapper!(SignatureError, signature::Error);
impl_error_wrapper!(DecodeError, base64::DecodeError);
impl_error_wrapper!(InvalidHeaderValue, axum::http::header::InvalidHeaderValue);

//impl_error_wrapper!(AeadError, aead::Error);

//impl_error_wrapper!(EmailAddressError, email_address::EmailAddress);

#[derive(Error, Debug)]
pub enum AuthFlowError {
    #[error("Expired")]
    Expired,
    #[error("Invalid")]
    Invalid,
    #[error("IncorrectType")]
    IncorrectType,
}

#[derive(Error, Debug)]
pub enum AuthenticationError {
    #[error("GoogleAuthenticator({0})")]
    GoogleAuthenticator(#[from] GAError),
    #[error("Incorrect2FACode")]
    Incorrect2FACode,
    #[error("IncorrectCredentials")]
    IncorrectCredentials,
    #[error("InvalidPasswordFormat({0})")]
    InvalidPasswordFormat(#[from] argon2::Error),
    #[error("UserUIDNotRegisteredToEmail({0})")]
    UserUIDNotRegisteredToEmail(EmailAddress),
    #[error("EmailNotRegistered({0})")]
    EmailNotRegistered(EmailAddress),
    #[error("AccountSetupIncomplete")]
    AccountSetupIncomplete,
    #[error("UserNotFound({0})")]
    UserNotFound(Uuid),
    #[error("SerialisingLoginCredentials({0})")]
    SerialisingLoginCredentials(SerdeError),
    #[error("EncryptLoginCredentials({0})")]
    EncryptLoginCredentials(RSAError),
    #[error("Disabled")]
    Disabled,
    /* #[error("")]
    ErrorGetting2FACodeFromSecret,
    #[error("Argon2Validation({0})")]
    Argon2Validation(String),
    #[error("")]
    Invalid2FASecret,
    #[error("")]
    InvalidInviteToken,
    #[error("AccessDenied({0})")]
    AccessDenied(Uuid),
    #[error("EmailAlreadyExists({0})")]
    EmailAlreadyExists(EmailAddress), */
}

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("DataSerialisation({0})")]
    DataSerialisation(#[from] SerdeError),
    #[error("DataEncryption({0})")]
    DataEncryption(String),
    #[error("EncryptLoginCredentials({0})")]
    EncryptLoginCredentials(RSAError),
    #[error("HeaderSerialisation({0})")]
    HeaderSerialisation(SerdeError),
    #[error("HeaderDeserialisation({0})")]
    HeaderDeserialisation(SerdeError),
    #[error("ConvertingBytesToSignature({0})")]
    ConvertingBytesToSignature(SignatureError),
    #[error("DecodeURLSafeBase64({0})")]
    DecodeURLSafeBase64(DecodeError),
    /* #[error("SerialiseLoginCredentials({0})")]
    SerialiseLoginCredentials(SerdeError), */

    /* #[error("CreateSigner({0})")]
    CreateSigner(OpenSSLError),
    #[error("FeedSigner({0})")]
    FeedSigner(OpenSSLError),
    #[error("FinaliseSignature({0})")]
    FinaliseSignature(OpenSSLError), */
    #[error("InvalidFormatForDecoding")]
    InvalidFormatForDecoding,
    #[error("Base64Decode({0})")]
    Base64Decode(Base64DecodeError),
    #[error("HeaderBase64Decode({0})")]
    HeaderBase64Decode(Base64DecodeError),
    /* #[error("Feedverifier({0})")]
    FeedVerifier(OpenSSLError), */
    #[error("HeaderUnexpectedAlgorithm")]
    HeadedUnexpectedAlgorithm,
    #[error("SignatureBase64Decode({0})")]
    SignatureBase64Decode(Base64DecodeError),
    /* #[error("CreateVerifier({0})")]
    CreateVerifier(OpenSSLError), */
    /* #[error("FinaliseVerifier({0})")]
    FinaliseVerifier(RSAError), */
    #[error("SignatureVerificationFailed({0})")]
    SignatureVerificationFailed(SignatureError),
    #[error("PayloadBase64Decode({0})")]
    PayloadBase64Decode(Base64DecodeError),
    #[error("DataDecryption({0})")]
    DataDecryption(String),
    #[error("DataBytesToString({0})")]
    DataBytesToString(FromUtf8Error),
    #[error("DataDeserialisation({0})")]
    DataDeserialisation(SerdeError),
    #[error("Expired")]
    Expired,
    #[error("MissingExpiry")]
    MissingExpiry,
}

#[derive(Error, Debug)]
pub enum LoginError {
    #[error("HeaderKeysDontMatch")]
    HeaderKeysDontMatch,
}

#[derive(Error, Debug)]
pub enum ClientPayloadError {
    #[error("UrlSafeBase64Decode({0})")]
    UrlSafeBase64Decode(Base64DecodeError),
    #[error("DataBytesToString({0})")]
    DataBytesToString(FromUtf8Error),
    #[error("DataDeserialisation({0})")]
    DataDeserialisation(SerdeError),
}

#[derive(Error, Debug)]
pub enum AccountSetupError {
    #[error("InvalidPassword")]
    InvalidPassword,
    #[error("Incorrect2FACode")]
    Incorrect2FACode,
    #[error("Argon2({0})")]
    Argon2(#[from] argon2::Error),
    #[error("GoogleAuthenticator({0})")]
    GoogleAuthenticator(#[from] GAError),
    #[error("AccountSetupAlreadyComplete")]
    AccountSetupAlreadyComplete,
    #[error("UserNotFound({0})")]
    UserNotFound(Uuid),
    #[error("CouldntGetUserIDFromEmail")]
    CouldntGetUserIDFromEmail,
    #[error("InvalidInvite")]
    InvalidInvite,
}

#[derive(Error, Debug)]
pub enum StartupError {
    #[error("InvalidOrigin({0}: {1})")]
    InvalidOrigin(InvalidHeaderValue, String),
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    /* #[error("GeneratingRSABase({0})")]
    GeneratingRSABase(OpenSSLError), */
    #[error("GeneratingRSAPrivate({0})")]
    GeneratingRSAPrivate(RSAError),
    /* #[error("GeneratingRSAPublic({0})")]
    GeneratingRSAPublic(RSAError), */
    /* #[error("GeneratingRSAPublicPEM({0})")]
    GeneratingRSAPublicPEM(OpenSSLError), */
    #[error("RSAPrivateConversion({0})")]
    RSAPrivateConversion(RSAError),
    /* #[error("DataDecryption({0})")]
    DataDecryption(OpenSSLError), */
    #[error("PublicToPEMConversion({0})")]
    PublicToPEMConversion(PKCS1Error),
    #[error("PublicPEMBytesToString({0})")]
    PublicPEMBytesToString(Utf8Error),
    #[error("ConvertSigningPrivateKeyToPEMPKCS1({0})")]
    ConvertSigningPrivateKeyToPEMPKCS1(PKCS1Error),
    #[error("ConvertPrivateKeyToPEMPKCS1({0})")]
    ConvertPrivateKeyToPEMPKCS1(PKCS1Error),
    #[error("ConvertSigningPublicKeyToPEMPKCS1({0})")]
    ConvertSigningPublicKeyToPEMPKCS1(PKCS1Error),
    #[error("ConvertPublicKeyToPEMPKCS1({0})")]
    ConvertPublicKeyToPEMPKCS1(PKCS1Error),
    #[error("ConvertModelToTOML({0})")]
    ConvertModelToTOML(TomlSerError),
    #[error("WriteTOMLToFile({0})")]
    WriteTOMLToFile(StdIoError),
    #[error("ReadTOMLFromFile({0})")]
    ReadTOMLFromFile(StdIoError),
    #[error("ConvertTOMLToModel({0})")]
    ConvertTOMLToModel(TomlDeError),
    #[error("SigningPrivateKeyFromPEMPKCS1({0})")]
    SigningPrivateKeyFromPEMPKCS1(PKCS1Error),
    #[error("SigningPublicKeyFromPEMPKCS1({0})")]
    SigningPublicKeyFromPEMPKCS1(PKCS1Error),
    #[error("PrivateKeyFromPEMPKCS1({0})")]
    PrivateKeyFromPEMPKCS1(PKCS1Error),
    #[error("PublicKeyFromPEMPKCS1({0})")]
    PublicKeyFromPEMPKCS1(PKCS1Error),
}

#[derive(Error, Debug)]
pub enum SmtpError {
    #[error("ServerAddressParse({0})")]
    ServerAddressParse(SmtpAddressError),
    #[error("SmtpTransportRelayBuild({0})")]
    SmtpTransportRelayBuild(SmtpTransportError),
    #[error("MessageBuilder({0})")]
    MessageBuilder(LettreError),
    #[error("MessageSend({0})")]
    MessageSend(SmtpTransportError),
    #[error("RecipientAddressParse({0})")]
    RecipientAddressParse(SmtpAddressError),
}

#[derive(Error, Debug)]
pub enum ReadTokenAsRefreshTokenError {
    #[error("InvalidHeaders")]
    InvalidHeaders,
    #[error("NotReadToken")]
    NotReadToken,
    #[error("Expired")]
    Expired,
    #[error("NotUsedWithinValidRefreshPeriod")]
    NotUsedWithinValidRefreshPeriod,
    #[error("HasHitIterationLimit")]
    HasHitIterationLimit,
}

#[derive(Error, Debug)]
pub enum AuthServerBuildError {
    #[error("MissingProperties({0})")]
    MissingProperties(String),
}

#[derive(Error, Debug)]
pub enum UserFromModelError {
    #[error("ParseUuidFromString({0})")]
    ParseUuidFromString(UuidError),
    #[error("ParseEmailAddressFromString({0})")]
    ParseEmailAddressFromString(String), //can't use proper error translation for email_address::Error as it doesn't satisfy AsDynError<'_> and StdError
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("DatabaseInsertUser{0})")]
    DatabaseInsertUser(DieselResultError),
    #[error("DatabaseUpdateUser{0})")]
    DatabaseUpdateUser(DieselResultError),
    #[error("LoadingUserModelsFromDatabase{0})")]
    LoadingUserModelsFromDatabase(DieselResultError),
}

#[derive(Error, Debug)]
pub enum ReadTokenValidationError {
    #[error("InvalidHeaders")]
    InvalidHeaders,
    #[error("NotReadToken")]
    NotReadToken,
}

#[derive(Error, Debug)]
pub enum WriteTokenGenerationError {}

#[derive(Error, Debug)]
pub enum WriteTokenValidationError {
    #[error("InvalidHeaders")]
    InvalidHeaders,
    #[error("NotWriteToken")]
    NotWriteToken,
    #[error("UserIDNotMatchCorrespondingReadToken")]
    UserIDNotMatchCorrespondingRead,
    #[error("WriteUIDNotMatchReadUID")]
    WriteUIDNotMatchReadUID,
}

impl From<UIDAuthorityError> for Error {
    fn from(value: UIDAuthorityError) -> Self {
        Error::UIDAuthority(value)
    }
}

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("MissingExpiry")]
    MissingExpiry,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("BearerTokenPairInvalidFormat")]
    BearerTokenPairInvalidFormat,
    #[error("AuthFlow({0})")]
    AuthFlow(#[from] AuthFlowError),
    #[error("AccountSetupError({0})")]
    AccountSetup(#[from] AccountSetupError),
    #[error("Authentication({0})")]
    Authentication(#[from] AuthenticationError),
    #[error("Token({0})")]
    Token(#[from] TokenError),
    #[error("Startup({0})")]
    Startup(#[from] StartupError),
    #[error("Encryption({0})")]
    Encryption(#[from] EncryptionError),
    #[error("ClientPayload({0})")]
    ClientPayload(#[from] ClientPayloadError),
    #[error("Login({0})")]
    Login(#[from] LoginError),
    #[error("Smtp({0})")]
    Smtp(SmtpError),
    #[error("AuthServerBuild({0})")]
    AuthServerBuild(AuthServerBuildError),
    #[error("ReadTokenValidation({0})")]
    ReadTokenValidation(ReadTokenValidationError),
    #[error("WriteTokenValidation({0})")]
    WriteTokenValidation(WriteTokenValidationError),
    #[error("WriteTokenGeneration({0})")]
    WriteTokenGeneration(WriteTokenGenerationError),
    #[error("ReadTokenAsRefreshToken({0})")]
    ReadTokenAsRefreshToken(ReadTokenAsRefreshTokenError),
    #[error("UserFromModel({0})")]
    UserFromModel(UserFromModelError),
    #[error("Database({0})")]
    Database(DatabaseError),
    #[error("UIDAuthority({0})")]
    UIDAuthority(UIDAuthorityError),
    #[error("Identity({0})")]
    Identity(IdentityError),
}
