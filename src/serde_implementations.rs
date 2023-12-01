pub mod datetime_utc {
    use chrono::{DateTime, Utc};
    use serde::{Serialize, Serializer, Deserializer, Deserialize};

    pub fn serialize<S>(datetime: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime.to_rfc3339().serialize(serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Ok(DateTime::parse_from_rfc3339(&s)
                .map_err(serde::de::Error::custom)?.with_timezone(&Utc))
        }
}
