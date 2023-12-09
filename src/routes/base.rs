use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization, Cookie},
    TypedHeader,
};
use std::net::SocketAddr;

pub async fn debug_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(cookie): TypedHeader<Cookie>,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
    /* Extension(security_manager): Extension<Arc<SecurityManager>>, */
    /* Extension(auth_manager): Extension<Arc<AuthManager>>, */
    headers: HeaderMap,
) -> impl IntoResponse {
    println!("{:?}", addr);
    println!("{:?}", headers);
    println!("{:?}", cookie);
    println!("{:?}", authorisation);
    StatusCode::OK.into_response()
}
