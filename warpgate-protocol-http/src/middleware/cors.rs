use std::sync::Arc;

use poem::web::Data;
use poem::{Endpoint, FromRequest, IntoResponse, Request, Response};
use warpgate_common::{TargetHTTPOptions, TargetOptions};
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_core::ConfigProvider;

use crate::client_cache::HttpClientCache;
use crate::proxy::proxy_cors_preflight;

fn is_cors_preflight(req: &Request) -> bool {
    req.method() == http::Method::OPTIONS
        && req.headers().contains_key(http::header::ORIGIN)
        && req
            .headers()
            .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn target_allows_preflight(options: &TargetHTTPOptions, hostname: &str) -> bool {
    options.forward_cors_preflight
        && options
            .external_host
            .as_deref()
            .is_some_and(|bound| bound.eq_ignore_ascii_case(hostname))
}

/// Forward an opted-in target's genuine CORS preflight before page
/// authentication. All other requests continue through the original endpoint.
pub(crate) async fn forward<E: Endpoint>(ep: Arc<E>, req: Request) -> poem::Result<Response> {
    if !is_cors_preflight(&req) {
        return ep.call(req).await.map(IntoResponse::into_response);
    }

    let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;
    let client_cache = Data::<&HttpClientCache>::from_request_without_body(&req).await?;
    let Some(hostname) = ctx.trusted_hostname(&req) else {
        return ep.call(req).await.map(IntoResponse::into_response);
    };
    let Some(target) = ctx
        .services()
        .config_provider
        .get_target_by_hostname(&hostname)
        .await?
    else {
        return ep.call(req).await.map(IntoResponse::into_response);
    };
    let TargetOptions::Http(options) = &target.options else {
        return ep.call(req).await.map(IntoResponse::into_response);
    };

    // Recheck the binding after deserialization instead of relying solely on
    // the database lookup, and require explicit opt-in on the resolved target.
    if !target_allows_preflight(options, &hostname) {
        return ep.call(req).await.map(IntoResponse::into_response);
    }

    proxy_cors_preflight(&req, &ctx, &client_cache, &target.name, options).await
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn request(method: http::Method) -> Request {
        Request::builder().method(method).finish()
    }

    #[test]
    fn recognizes_only_genuine_preflights() {
        let mut req = request(http::Method::OPTIONS);
        assert!(!is_cors_preflight(&req));

        req.headers_mut().insert(
            http::header::ORIGIN,
            HeaderValue::from_static("https://app.example"),
        );
        assert!(!is_cors_preflight(&req));

        req.headers_mut().insert(
            http::header::ACCESS_CONTROL_REQUEST_METHOD,
            HeaderValue::from_static("POST"),
        );
        assert!(is_cors_preflight(&req));

        let req = Request::builder()
            .method(http::Method::GET)
            .header(http::header::ORIGIN, "https://app.example")
            .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .finish();
        assert!(!is_cors_preflight(&req));
    }

    #[test]
    fn target_must_opt_in_with_a_matching_domain_binding() {
        let mut options: TargetHTTPOptions =
            serde_json::from_str(r#"{"url":"http://target","external_host":"API.example.com"}"#)
                .unwrap();

        assert!(!target_allows_preflight(&options, "api.example.com"));
        options.forward_cors_preflight = true;
        assert!(target_allows_preflight(&options, "api.example.com"));
        assert!(!target_allows_preflight(&options, "other.example.com"));
        options.external_host = None;
        assert!(!target_allows_preflight(&options, "api.example.com"));
    }
}
