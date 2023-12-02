use blake3::Hasher;

pub mod auth_manager;
#[path = "./transmission/bidirectional.rs"]
pub mod bidirectional;
pub mod credentials;
pub mod error;
#[path = "./transmission/request.rs"]
pub mod request;
#[path = "./transmission/response.rs"]
pub mod response;
pub mod serde;
pub mod r#trait;

pub const COOKIE_NAME: &str = "uamtoken"; //This won't exist and will be passed down from AuthManager

///hashes with blake3
pub fn hash_string(data: &str) -> String {
    let mut hasher = Hasher::new();
    let _ = hasher.update(data.as_bytes());
    hasher.finalize().to_string()
}
