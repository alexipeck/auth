pub mod authenticated;
pub mod login;
pub mod logout;
pub mod setup;

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::{
    headers::{/* authorization::Bearer, Authorization, */ Cookie},
    TypedHeader,
};
use std::net::SocketAddr;

pub async fn debug_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    println!("{:?}", cookie);
    StatusCode::OK.into_response()
}
