//implemented from RFC 8484
//POST /dns-query with Content-Type: application/dns-message
//DNS responds with Content-Type: application/dns-message

use std::sync::{Arc};
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use crate::blocklist::Blocklist;
use crate::stats::DnsStats;
use crate::{CacheEntry, handle_request};
use axum::extract::ConnectInfo;



use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use crate::threat::ThreatDetector;

#[derive(Clone)]
pub struct DoHState {
    pub stats: Arc<DnsStats>,
    pub blocklist: Arc<Blocklist>,
    pub cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

//body should be raw DNS wire format query
//and should return raw DNS wire format response
pub async fn doh_query_handler(
    State(state): State<DoHState>,
    ConnectInfo(src): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    //Validation

    //the content type must be application/dns-message
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with("application/dns-message") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/dns-message",
        ).into_response();
    }

    //can't be empty
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty DNS query").into_response();
    }

    let mut cache = state.cache.lock().await;
    let mut threat_detector = ThreatDetector::new();


    match handle_request(&body, src, &mut cache, &state.stats, &state.blocklist,&mut threat_detector).await {
        Ok(response_bytes) => {
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/dns-message"),
                    //5.1 - no cache  because TTL is inside the DNS response itself
                    (header::CACHE_CONTROL, "no-cache, no-store"),
                ],
                response_bytes,
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("DoH: handle_request error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DNS resolution failed").into_response()
        }
    }
}