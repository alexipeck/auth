use crate::{auth_manager::AuthManager, str_to_two_fa};
use axum::{
    extract::{ConnectInfo, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, net::SocketAddr, sync::Arc};
use tracing::warn;

pub async fn refresh_read_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
) -> impl IntoResponse {
    match auth_manager.refresh_read_token(authorisation.token(), &headers) {
        Ok(token_pair) => (StatusCode::OK, Json(token_pair)).into_response(),
        Err(err) => {
            //TODO: Split out into actual correct errors
            warn!("{}", err);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

pub struct GetWriteTokenQueryParams {
    two_fa_code: [u8; 6],
}

impl Serialize for GetWriteTokenQueryParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let two_fa_code_str =
            std::str::from_utf8(&self.two_fa_code).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(two_fa_code_str)
    }
}

impl<'de> Deserialize<'de> for GetWriteTokenQueryParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GetWriteTokenQueryParamsVisitor;

        impl<'de> Visitor<'de> for GetWriteTokenQueryParamsVisitor {
            type Value = GetWriteTokenQueryParams;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a 6-character 2FA code")
            }

            fn visit_str<E>(self, value: &str) -> Result<GetWriteTokenQueryParams, E>
            where
                E: de::Error,
            {
                let two_fa_code =
                    str_to_two_fa(value).ok_or_else(|| de::Error::custom("invalid two_fa_code"))?;
                Ok(GetWriteTokenQueryParams { two_fa_code })
            }
        }

        deserializer.deserialize_str(GetWriteTokenQueryParamsVisitor)
    }
}

pub async fn get_write_token_route(
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    TypedHeader(authorisation): TypedHeader<Authorization<Bearer>>,
    Query(query_params): Query<GetWriteTokenQueryParams>,
) -> impl IntoResponse {
    match auth_manager
        .generate_write_token(authorisation.token(), &query_params.two_fa_code, &headers)
        .await
    {
        Ok(token_pair) => (StatusCode::OK, Json(token_pair)).into_response(),
        Err(err) => {
            //TODO: Split out into actual correct errors
            warn!("{}", err);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

/* pub fn get_new_write_token() -> Result<(), Error> {}

pub fn get_new_write_token_route(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(auth_manager): Extension<Arc<AuthManager>>,
    headers: HeaderMap,
    axum::response::Json(user_login): axum::response::Json<UserLogin>,
) -> impl IntoResponse {
    let (token, expiry) = auth_manager.setup_flow::<Option<bool>>(
        &headers,
        FlowType::Write,
        Duration::minutes(5),
        None,
    )?;
    match  {
        Ok() => {
            FullResponseData::basic(ResponseData::).into_response()
        }
        Err(err) => {
            warn!("{}", err);
            FullResponseData::basic(ResponseData::Unauthorised).into_response()
            //TODO: Split out into actual correct errors
        }
    }
} */
