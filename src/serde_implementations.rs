pub mod datetime_utc {
    use chrono::{DateTime, Utc};
    use serde::{Serializer, Serialize};

    pub fn serialize<S>(datetime: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime.to_rfc3339().serialize(serializer)
    }
}