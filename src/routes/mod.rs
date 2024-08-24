pub mod authenticated;
pub mod login;
pub mod logout;
pub mod setup;

use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::{headers::Cookie, TypedHeader};

pub async fn debug_route(
    TypedHeader(cookie): TypedHeader<Cookie>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", headers);
    println!("{:?}", cookie);
    StatusCode::OK.into_response()
}

pub async fn keep_alive_route() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
