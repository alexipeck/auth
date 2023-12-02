use blake3::Hasher;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub trait HashDebug {
    fn hash_debug(&self, salt: Uuid) -> String;
}

impl<T: std::fmt::Debug> HashDebug for T {
    fn hash_debug(&self, salt: Uuid) -> String {
        let mut hasher = Hasher::new();
        let _ = hasher.update(format!("{}{:?}", salt, self).as_bytes());
        hasher.finalize().to_string()
    }
}

pub trait Expired {
    fn expired(&self) -> bool;
}

impl Expired for DateTime<Utc> {
    fn expired(&self) -> bool {
        (self.timestamp() - Utc::now().timestamp()).is_negative()
    }
}
