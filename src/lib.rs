use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{header, request::Parts, HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use libdeflater::{CompressionLvl, Compressor};

pub mod error;
pub mod static_opti;

pub use base64;
pub use libdeflater;

use static_opti::FileService;
use tokio::signal;

/// Get str header value
pub fn str_header<'a>(map: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    map.get(&HeaderName::from_static(name))
        .and_then(|h| h.to_str().ok())
}

/// Get first str header value
pub fn str_header_first<'a>(map: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    str_header(map, name).and_then(|h| h.split(',').next().map(|it| it.trim()))
}

/// Resolve client ip from headers
pub fn client_ip(map: &HeaderMap) -> Option<&str> {
    // fly-client-ip first as client can spoof x-forwarded-for
    str_header(map, "fly-client-ip").or_else(|| str_header_first(map, "x-forwarded-for"))
}

/// Parse request scheme
pub fn parse_scheme<'a>(map: &'a HeaderMap, uri: &'a Uri) -> &'a str {
    str_header_first(map, "x-forwarded-proto")
        .or_else(|| uri.scheme_str())
        .unwrap_or("http")
}

/// Parse request host
pub fn parse_host<'a>(map: &'a HeaderMap, uri: &'a Uri) -> &'a str {
    str_header_first(map, "x-forwarded-host")
        .or_else(|| str_header(map, "host"))
        .or_else(|| uri.authority().map(|a| a.host()))
        .unwrap_or("localhost")
}

/// Resolve client base url
pub fn parse_base_url(map: &HeaderMap, uri: &Uri) -> String {
    format!("{}://{}", parse_scheme(map, uri), parse_host(map, uri))
}

/// Create a redirect response if the base scheme is http and we are not in localhost
pub fn redirect_https(map: &HeaderMap, uri: &Uri) -> Option<Response> {
    let scheme = parse_scheme(map, uri);
    let host = parse_host(map, uri);

    (scheme == "http" && !host.starts_with("127.0.0.1") && !host.starts_with("localhost")).then(
        || {
            (
                StatusCode::PERMANENT_REDIRECT,
                [(header::LOCATION, &format!("https://{}{}", host, uri))],
            )
                .into_response()
        },
    )
}

/// Create a redirect response if the base scheme is http and we are not in localhost
pub async fn redirect_https_middle_ware(request: Request, next: Next) -> Response {
    if let Some(redirect) = redirect_https(request.headers(), request.uri()) {
        redirect
    } else {
        next.run(request).await
    }
}

/// Fast in memory gzip compression
pub fn compress(in_data: &[u8]) -> Vec<u8> {
    let mut compressor = Compressor::new(CompressionLvl::default());
    let max_size = compressor.gzip_compress_bound(in_data.len());
    let mut gzip = vec![0; max_size];
    let gzip_size = compressor.gzip_compress(in_data, &mut gzip).unwrap();
    gzip.resize(gzip_size, 0);
    gzip
}

/// Generate strong etag from bytes
fn etag(bytes: &[u8]) -> String {
    let mut buf = [b'"'; 24];
    let hash = xxhash_rust::xxh3::xxh3_128(bytes);
    assert_eq!(
        BASE64_URL_SAFE_NO_PAD.encode_slice(hash.to_le_bytes(), &mut buf[1..24]),
        Ok(22)
    );
    std::str::from_utf8(&buf).unwrap().to_string()
}

/// Generate an etag from body content and handle etag match
pub fn etag_auto(map: &HeaderMap, mut response: Response<Bytes>) -> impl IntoResponse {
    let etag = etag(response.body());
    response
        .headers_mut()
        .insert(header::ETAG, HeaderValue::from_str(&etag).unwrap());
    if map
        .get(header::IF_NONE_MATCH)
        .is_some_and(|h| h.as_bytes() == etag.as_bytes())
    {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        (response.into_parts().0, Body::empty())
    } else {
        let (a, b) = response.into_parts();
        (a, Body::from(b))
    }
}

/// Shutdown signal listener
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    println!("signal received, starting graceful shutdown");
}

pub fn static_files(
    headers: &HeaderMap,
    path: &str,
    files: &'static FileService,
    fallback: Option<&str>,
) -> Response {
    let accept_encoding = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if let Some(it) = files.find(accept_encoding, path, fallback) {
        if headers
            .get(header::IF_NONE_MATCH)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|old_tag| old_tag.trim_matches('"') == it.etag)
        {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .body(Body::empty())
                .unwrap();
        }

        let mime = mime_guess::from_path(it.path);
        let body = Body::from(Bytes::from_static(it.content));

        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.first_or_text_plain().as_ref())
            .header(header::CACHE_CONTROL, "public, max-age=0, must-revalidate")
            .header(header::ETAG, it.etag)
            .header(header::VARY, header::ACCEPT_ENCODING);
        if let Some(encoding) = it.encoding {
            builder = builder.header(header::CONTENT_ENCODING, encoding);
        }
        builder.body(body).unwrap()
    } else {
        (StatusCode::NOT_FOUND).into_response()
    }
}

pub struct ClientIp(pub IpAddr);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = axum::extract::rejection::ExtensionRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await?;
        Ok(ClientIp(
            client_ip(&parts.headers)
                .and_then(|s| IpAddr::from_str(s).ok())
                .unwrap_or_else(|| addr.ip()),
        ))
    }
}
