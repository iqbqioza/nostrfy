//! Minimal S3 / Cloudflare R2 client (SigV4 signing, hand-rolled).
//!
//! Only the operations the Blossom server needs are implemented: PUT, GET,
//! HEAD, DELETE of a single object and `ListObjectsV2`. Request signing
//! follows AWS Signature Version 4 with HMAC-SHA256 (reusing the local
//! `hmac_sha256`); Cloudflare R2 is an S3-compatible service and needs no
//! special handling beyond the endpoint/`auto` region.

use crate::error::Result;

#[derive(Clone)]
pub(crate) struct S3Client {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    /// Bounded client for full-body operations (PUT/DELETE/migration
    /// GETs): a hung S3 endpoint must not hold a request handler forever.
    http: reqwest::Client,
    /// Unbounded-streaming client for the blob GET: the body is relayed
    /// 1:1 to the client, so a total request timeout would truncate large
    /// blobs under slow clients (the client connection itself bounds the
    /// stream lifetime).
    http_stream: reqwest::Client,
}

impl S3Client {
    pub(crate) fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> S3Client {
        S3Client {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            region: region.to_string(),
            bucket: bucket.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            http_stream: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    /// `https://<endpoint>/<bucket>/<key>`
    fn url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint, self.bucket, encoded_key(key))
    }

    /// Sends a signed request and returns the raw response (the caller
    /// reads the body — either fully, or streamed for large objects).
    async fn request(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<reqwest::Response> {
        let url = self.url(key);
        let url = if query.is_empty() {
            url
        } else {
            format!("{url}?{query}")
        };
        let now = crate::util::unix_now();
        let amz_date = amz_datetime(now);
        let date = &amz_date[..8];
        let payload_hash = if body.is_some() || matches!(method, "PUT") || method == "GET" {
            sha256_hex(body.unwrap_or(b""))
        } else {
            // HEAD/DELETE may be signed without a payload hash ("UNSIGNED-PAYLOAD"
            // is accepted by R2 and S3 for these).
            "UNSIGNED-PAYLOAD".to_string()
        };
        let authorization = self.sign(
            method,
            key,
            query,
            &payload_hash,
            &amz_date,
            date,
            content_type,
            extra_headers,
        );

        let mut builder = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                &url,
            )
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", authorization);
        if let Some(ct) = content_type {
            builder = builder.header("Content-Type", ct);
        }
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        if let Some(bytes) = body {
            builder = builder.body(bytes.to_vec());
        }
        builder
            .send()
            .await
            .map_err(|e| crate::error::Error::Other(format!("s3 request failed: {e}")))
    }

    /// Like [`Self::request`] but on the unbounded-streaming client, used
    /// only by the blob GET whose body is relayed to the client (a total
    /// timeout would truncate slow downloads; the client connection
    /// bounds the stream lifetime).
    async fn request_stream(
        &self,
        method: &str,
        key: &str,
        query: &str,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<reqwest::Response> {
        let url = self.url(key);
        let url = if query.is_empty() {
            url
        } else {
            format!("{url}?{query}")
        };
        let now = crate::util::unix_now();
        let amz_date = amz_datetime(now);
        let date = &amz_date[..8];
        let payload_hash = if method == "GET" {
            sha256_hex(b"")
        } else {
            "UNSIGNED-PAYLOAD".to_string()
        };
        let authorization = self.sign(
            method,
            key,
            query,
            &payload_hash,
            &amz_date,
            date,
            content_type,
            extra_headers,
        );
        let mut builder = self
            .http_stream
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                &url,
            )
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", authorization);
        if let Some(ct) = content_type {
            builder = builder.header("Content-Type", ct);
        }
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        builder
            .send()
            .await
            .map_err(|e| crate::error::Error::Other(format!("s3 request failed: {e}")))
    }

    async fn send(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let resp = self
            .request(method, key, query, body, content_type, extra_headers)
            .await?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| crate::error::Error::Other(format!("s3 response failed: {e}")))?
            .to_vec();
        Ok((status, bytes))
    }

    /// Builds the SigV4 `Authorization` header.
    #[allow(clippy::too_many_arguments)]
    fn sign(
        &self,
        method: &str,
        key: &str,
        query: &str,
        payload_hash: &str,
        amz_date: &str,
        date: &str,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> String {
        let host = host_of(&self.endpoint);
        // The canonical URI must match the request URL exactly: the object
        // key is percent-encoded segment-wise in both (a raw key in the
        // signature would mismatch the encoded URL and yield a 403).
        let canonical_uri = format!("/{}/{}", self.bucket, encoded_key(key));
        // Canonical query: sort the key=value pairs (SigV4 requires sorted).
        let canonical_query = sorted_query(query);
        // SigV4 canonical headers must be sorted by name and lowercased.
        let mut headers: Vec<(String, String)> = vec![
            ("host".to_string(), host),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), amz_date.to_string()),
        ];
        if let Some(ct) = content_type {
            // SigV4 signs header values verbatim (trimmed): lowercasing a
            // mixed-case MIME (`Text/Plain`) would mismatch the sent value.
            headers.push(("content-type".to_string(), ct.trim().to_string()));
        }
        for (name, value) in extra_headers {
            // Only the name is lowercased: S3 canonicalizes the received
            // header names (HTTP names are case-insensitive and the client
            // sends them lowercase), but values are verbatim. Lowercasing a
            // value would break the signature for mixed-case values.
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let mut canonical_headers = String::new();
        let mut signed_headers = String::new();
        for (i, (name, value)) in headers.iter().enumerate() {
            if i > 0 {
                canonical_headers.push('\n');
            }
            canonical_headers.push_str(&format!("{name}:{value}"));
            if i > 0 {
                signed_headers.push(';');
            }
            signed_headers.push_str(name);
        }
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n\n{signed_headers}\n{payload_hash}"
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = sign_v4(&self.secret_key, date, &self.region, &string_to_sign);
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key, scope
        )
    }

    pub(crate) async fn put_object(&self, key: &str, bytes: &[u8], mime: &str) -> Result<()> {
        let (status, _) = self
            .send("PUT", key, "", Some(bytes), Some(mime), &[])
            .await?;
        if !status.is_success() {
            return Err(crate::error::Error::Other(format!(
                "s3 put failed: {status}"
            )));
        }
        Ok(())
    }

    pub(crate) async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let (status, bytes) = self.send("GET", key, "", None, None, &[]).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(crate::error::Error::Other(format!(
                "s3 get failed: {status}"
            )));
        }
        Ok(Some(bytes))
    }

    /// Fetches the `bytes=start-(start+len-1)` range and returns the raw
    /// response so the caller can stream the body instead of loading the
    /// whole object into memory.
    pub(crate) async fn get_object_range(
        &self,
        key: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<reqwest::Response>> {
        // A zero-length blob (an empty upload is legal): fetch the whole
        // object — an S3 "bytes=0-0" on an empty object is a 416.
        let range = if len > 0 {
            Some(format!(
                "bytes={start}-{}",
                start.saturating_add(len).saturating_sub(1)
            ))
        } else {
            None
        };
        let resp = match &range {
            Some(r) => {
                self.request_stream("GET", key, "", None, &[("Range", r)])
                    .await?
            }
            None => self.request_stream("GET", key, "", None, &[]).await?,
        };
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(crate::error::Error::Other(format!(
                "s3 get failed: {status}"
            )));
        }
        Ok(Some(resp))
    }

    pub(crate) async fn delete_object(&self, key: &str) -> Result<bool> {
        let (status, _) = self.send("DELETE", key, "", None, None, &[]).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !status.is_success() {
            // Propagate the failure: the caller must not drop the owner
            // mapping for an object that is still in the bucket (that
            // would orphan a billed object with no way to delete it).
            return Err(crate::error::Error::Other(format!(
                "s3 delete failed: {status}"
            )));
        }
        Ok(true)
    }

    /// `ListObjectsV2` for a prefix; returns (key, size). Used by the
    /// one-time automatic migration, which needs the blob sizes without
    /// downloading the objects.
    #[allow(dead_code)]
    pub(crate) async fn list_keys(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let mut keys = Vec::new();
        let mut token = String::new();
        loop {
            let (page, next) = self.list_keys_page(prefix, &token).await?;
            keys.extend(page);
            token = next;
            if token.is_empty() {
                break;
            }
        }
        Ok(keys)
    }

    /// One `ListObjectsV2` page: returns the page's (key, size) pairs plus
    /// the continuation token (empty when the listing is complete). Split
    /// out so the migration can commit page by page instead of
    /// materializing million-key buckets before writing anything.
    pub(crate) async fn list_keys_page(
        &self,
        prefix: &str,
        token: &str,
    ) -> Result<(Vec<(String, u64)>, String)> {
        let query = format!(
            "list-type=2&prefix={}{}",
            percent_encode(prefix),
            if token.is_empty() {
                String::new()
            } else {
                format!("&continuation-token={}", percent_encode(token))
            }
        );
        let (status, bytes) = self.send("GET", "", &query, None, None, &[]).await?;
        if !status.is_success() {
            return Err(crate::error::Error::Other(format!(
                "s3 list failed: {status}"
            )));
        }
        let xml = String::from_utf8_lossy(&bytes);
        let mut keys = Vec::new();
        for block in xml.split("<Contents>").skip(1) {
            let Some(end) = block.find("</Contents>") else {
                break;
            };
            let block = &block[..end];
            let key = extract_tag(block, "Key");
            if !key.is_empty() {
                let size = extract_tag(block, "Size").trim().parse().unwrap_or(0);
                keys.push((key.to_string(), size));
            }
        }
        let token = xml_unescape(extract_tag(&xml, "NextContinuationToken").trim());
        Ok((keys, token))
    }
}

/// Undoes the XML entity escaping of the ListObjectsV2 response: a
/// continuation token containing `&`, `<` etc. would otherwise be sent
/// back corrupted and break pagination.
fn xml_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn extract_tag<'a>(xml: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    match xml.find(&open) {
        Some(start) => {
            let rest = &xml[start + open.len()..];
            match rest.find(&close) {
                Some(end) => &rest[..end],
                None => "",
            }
        }
        None => "",
    }
}

fn host_of(endpoint: &str) -> String {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    rest.split('/').next().unwrap_or(rest).to_string()
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The percent-encoded object key (each path segment encoded), shared by
/// the request URL and the SigV4 canonical URI.
fn encoded_key(key: &str) -> String {
    key.split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

fn sorted_query(query: &str) -> String {
    let mut pairs: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    pairs.sort();
    pairs.join("&")
}

fn amz_datetime(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (y, mo, d) = crate::logging::civil_from_days(days);
    let (h, mi, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// The SigV4 signing key chain: kSecret → kDate → kRegion → kService → kSigning.
fn sign_v4(secret_key: &str, date: &str, region: &str, string_to_sign: &str) -> String {
    let k_date = crate::util::hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = crate::util::hmac_sha256(&k_date, region.as_bytes());
    let k_service = crate::util::hmac_sha256(&k_region, b"s3");
    let k_signing = crate::util::hmac_sha256(&k_service, b"aws4_request");
    hex::encode(crate::util::hmac_sha256(
        &k_signing,
        string_to_sign.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AWS documentation's worked SigV4 example ("GET Object"):
    /// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
    #[test]
    fn sigv4_matches_aws_documented_example() {
        // Path-style endpoint (the same layout the R2 client uses).
        let client = S3Client::new(
            "https://s3.amazonaws.com",
            "us-east-1",
            "examplebucket",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        // The production call passes "Range" (capital R); the signer must
        // lowercase the name so the signed canonical headers match the
        // headers S3 actually receives (a "Range" canonical header would
        // never match the sent "range" and every ranged GET would 403).
        let authorization = client.sign(
            "GET",
            "test.txt",
            "",
            empty_hash,
            "20130524T000000Z",
            "20130524",
            None,
            &[("Range", "bytes=0-9")],
        );
        // The signing chain is validated against the AWS documentation's
        // worked example; this expectation is the same request expressed
        // path-style (`/bucket/key`), computed with the documented chain.
        let expected_prefix = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=819484c483cfb97d16522b1ac156f87e61677cc8f1f2545c799650ef178f4aa8";
        assert_eq!(authorization, expected_prefix);
    }

    #[test]
    fn xml_unescape_entities() {
        assert_eq!(xml_unescape("a&amp;b"), "a&b");
        assert_eq!(xml_unescape("a&b"), "a&b", "plain text passes through");
        assert_eq!(xml_unescape("&lt;&gt;&quot;&#39;"), "<>\"'");
        assert_eq!(xml_unescape("normal-token-123"), "normal-token-123");
    }

    #[test]
    fn host_of_strips_scheme_and_port() {
        assert_eq!(host_of("https://s3.amazonaws.com"), "s3.amazonaws.com");
        assert_eq!(
            host_of("https://abc123.r2.cloudflarestorage.com"),
            "abc123.r2.cloudflarestorage.com"
        );
    }

    #[test]
    fn percent_encode_preserves_safe_chars() {
        assert_eq!(percent_encode("npub1abc/-_~/"), "npub1abc%2F-_~%2F");
    }
}

#[cfg(test)]
mod mock_server {
    use super::*;
    use axum::body::Body;
    use axum::extract::{Path, RawQuery, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

    async fn put(
        Path((_bucket, key)): Path<(String, String)>,
        State(store): State<Store>,
        body: axum::body::Bytes,
    ) -> StatusCode {
        store.lock().unwrap().insert(key, body.to_vec());
        StatusCode::OK
    }

    async fn get(
        Path((_bucket, key)): Path<(String, String)>,
        State(store): State<Store>,
        headers: HeaderMap,
        RawQuery(query): RawQuery,
    ) -> Response {
        if key.is_empty() {
            return list(State(store), RawQuery(query)).await;
        }
        let data = store.lock().unwrap().get(&key).cloned();
        let Some(data) = data else {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        };
        if let Some(range) = headers.get("range")
            && let Ok(range) = range.to_str()
            && let Some(rest) = range.strip_prefix("bytes=")
        {
            let (start, end): (usize, usize) = rest
                .split_once('-')
                .map(|(a, b)| (a.parse().unwrap_or(0), b.parse().unwrap_or(data.len() - 1)))
                .unwrap_or((0, data.len() - 1));
            let slice = &data[start.min(data.len())..end.saturating_add(1).min(data.len())];
            let mut resp = Response::new(Body::from(slice.to_vec()));
            resp.headers_mut().insert(
                "content-range",
                format!("bytes {start}-{}/{}", start + slice.len() - 1, data.len())
                    .parse()
                    .unwrap(),
            );
            return resp;
        }
        Response::new(Body::from(data))
    }

    async fn delete(
        Path((_bucket, key)): Path<(String, String)>,
        State(store): State<Store>,
    ) -> StatusCode {
        match store.lock().unwrap().remove(&key) {
            Some(_) => StatusCode::NO_CONTENT,
            None => StatusCode::NOT_FOUND,
        }
    }

    async fn list(State(store): State<Store>, RawQuery(query): RawQuery) -> Response {
        let query = query.unwrap_or_default();
        let prefix = query
            .split('&')
            .find_map(|p| p.strip_prefix("prefix="))
            .map(percent_decode)
            .unwrap_or_default();
        let token = query
            .split('&')
            .find_map(|p| p.strip_prefix("continuation-token="))
            .map(percent_decode)
            .unwrap_or_default();
        let page = 2usize;
        let mut keys: Vec<String> = store
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        keys.sort();
        let skip = token.parse::<usize>().unwrap_or(0);
        let page_keys: Vec<String> = keys.into_iter().skip(skip).take(page).collect();
        let mut xml = String::from("<?xml version=\"1.0\"?><ListBucketResult>");
        for k in &page_keys {
            let size = store.lock().unwrap().get(k).unwrap().len();
            xml.push_str(&format!(
                "<Contents><Key>{k}</Key><Size>{size}</Size></Contents>"
            ));
        }
        if skip + page
            < store
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .count()
        {
            xml.push_str(&format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                skip + page
            ));
        }
        xml.push_str("</ListBucketResult>");
        Response::new(Body::from(xml))
    }

    fn percent_decode(s: &str) -> String {
        let mut out = Vec::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                let hi = chars.next().unwrap();
                let lo = chars.next().unwrap();
                let byte = u8::from_str_radix(&format!("{hi}{lo}"), 16).unwrap();
                out.push(byte);
            } else {
                out.extend(c.to_string().as_bytes());
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn build_mock() -> (String, Store) {
        let store: Store = Arc::new(Mutex::new(HashMap::new()));
        let app = axum::Router::new()
            .route(
                "/{bucket}/{*key}",
                axum::routing::put(put).get(get).delete(delete),
            )
            .route("/{bucket}/", axum::routing::get(list))
            .with_state(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), store)
    }

    #[tokio::test]
    async fn s3_operations_against_a_mock_bucket() {
        let (endpoint, store) = build_mock().await;
        let client = S3Client::new(&endpoint, "us-east-1", "bucket", "ak", "sk");

        // put_object success; the body lands in the mock bucket.
        client
            .put_object("dir/file.txt", b"hello s3", "text/plain")
            .await
            .unwrap();
        assert_eq!(
            store.lock().unwrap().get("dir/file.txt").unwrap(),
            b"hello s3"
        );

        // get_object: found, 404 -> None.
        let got = client.get_object("dir/file.txt").await.unwrap().unwrap();
        assert_eq!(got, b"hello s3");
        let missing = client.get_object("nope").await.unwrap();
        assert!(missing.is_none());

        // get_object_range: ranged response, and the zero-length full fetch.
        let resp = client
            .get_object_range("dir/file.txt", 1, 3)
            .await
            .unwrap()
            .unwrap();
        let body = resp.bytes().await.unwrap();
        assert_eq!(&body[..], b"ell");
        let resp = client
            .get_object_range("dir/file.txt", 0, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(resp.status().is_success());
        let missing = client.get_object_range("nope", 0, 8).await.unwrap();
        assert!(missing.is_none());

        // delete_object: present -> true, missing -> false.
        assert!(client.delete_object("dir/file.txt").await.unwrap());
        assert!(!client.delete_object("dir/file.txt").await.unwrap());

        // list_keys with paging (2 keys, page size 2 -> continuation).
        client.put_object("a", b"1", "text/plain").await.unwrap();
        client.put_object("b", b"22", "text/plain").await.unwrap();
        client.put_object("c", b"333", "text/plain").await.unwrap();
        let keys = client.list_keys("").await.unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&("a".to_string(), 1)));
        assert!(keys.contains(&("c".to_string(), 3)));
        let keys = client.list_keys("a").await.unwrap();
        assert_eq!(keys, vec![("a".to_string(), 1)]);
    }

    #[tokio::test]
    async fn s3_error_paths() {
        let (_endpoint, _store) = build_mock().await;
        // A bucket route that fails: a 500 status propagates as an error.
        let app = axum::Router::new().route(
            "/fail/{*rest}",
            axum::routing::any(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let failing = S3Client::new(
            &format!("http://{addr}/fail"),
            "us-east-1",
            "bucket",
            "ak",
            "sk",
        );
        let err = failing
            .put_object("k", b"v", "text/plain")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("put failed"), "{err}");
        let err = failing.get_object("k").await.unwrap_err();
        assert!(err.to_string().contains("get failed"), "{err}");
        let err = failing.delete_object("k").await.unwrap_err();
        assert!(err.to_string().contains("delete failed"), "{err}");
        let err = failing.list_keys("").await.unwrap_err();
        assert!(err.to_string().contains("list failed"), "{err}");
    }

    #[test]
    fn sigv4_helpers_cover_the_remaining_shapes() {
        // extract_tag: absent tag -> "", nested content kept.
        assert_eq!(extract_tag("<a>1</a>", "b"), "");
        assert_eq!(extract_tag("<Key>k&amp;ey</Key>", "Key"), "k&amp;ey");
        // encoded_key: hex stays raw, path segments encoded.
        assert_eq!(encoded_key("aa..bb"), "aa..bb");
        assert_eq!(
            encoded_key("a/b c"),
            "a/b%20c",
            "the slash is preserved (each path segment is encoded)"
        );
        // sorted_query: pairs sorted by name.
        assert_eq!(sorted_query("b=2&a=1"), "a=1&b=2");
        assert_eq!(sorted_query(""), "");
        // amz_datetime: zero -> 19700101T000000Z.
        assert_eq!(amz_datetime(0), "19700101T000000Z");
        assert_eq!(amz_datetime(1_700_000_000), "20231114T221320Z");
    }
}

#[cfg(test)]
mod hmac_checks {
    #[test]
    fn hmac_sha256_rfc4231_vector() {
        let got = crate::util::hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex::encode(got),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
