
#[derive(Serialize, Deserialize)]
struct UserInvite {
    email: EmailAddress,
    #[serde(with = "datetime_utc")]
    expiry: DateTime<Utc>,
    _salt: Uuid,
}
