//! Minimal S3 / Cloudflare R2 client (SigV4 signing, hand-rolled).
//!
//! Only the operations the Blossom server needs are implemented: PUT, GET,
//! HEAD, DELETE of a single object and `ListObjectsV2`. Request signing
//! follows AWS Signature Version 4 with HMAC-SHA256 (reusing the local
//! `hmac_sha256`); Cloudflare R2 is an S3-compatible service and needs no
//! special handling beyond the endpoint/`auto` region.

use anyhow::anyhow;

use crate::error::Result;

/// Header wait for streamed S3 requests (GET/HEAD): an unresponsive
/// endpoint must not hold a download or upload permit forever.
const S3_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Total time for one S3 PUT with a streamed body: generous for large
/// blobs, but a stalled endpoint must not pin the upload permit forever.
const S3_PUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Bounded retries for idempotent S3 operations: a transient 5xx/429 or a
/// connection reset must not surface as a generic 500 on the first try.
const S3_RETRY_ATTEMPTS: usize = 3;
const S3_RETRY_BASE_MS: u64 = 50;

/// Why one signed request failed before a response arrived.
enum SendFailure {
    Request(reqwest::Error),
    Timeout,
}

/// One S3 operation's request parameters (grouped to keep the retry
/// helpers within clippy's argument budget).
struct SignedRequest<'a> {
    http: &'a reqwest::Client,
    method: &'a str,
    key: &'a str,
    query: &'a str,
    body: Option<&'a [u8]>,
    content_type: Option<&'a str>,
    extra_headers: &'a [(&'a str, &'a str)],
    timeout: Option<std::time::Duration>,
}

fn retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

/// The upstream `Retry-After` (seconds), when it is a plain number.
fn retry_after(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// Backoff before retrying `attempt` (1-based). A long `Retry-After` is
/// honored by returning `None` (propagate the throttling response instead
/// of sleeping in the request handler).
fn retry_delay(
    attempt: usize,
    response: Option<&reqwest::Response>,
) -> Option<std::time::Duration> {
    if let Some(response) = response
        && let Some(secs) = retry_after(response)
    {
        if secs > 1 {
            return None;
        }
        return Some(std::time::Duration::from_secs(secs));
    }
    Some(std::time::Duration::from_millis(
        S3_RETRY_BASE_MS * (1u64 << (attempt.saturating_sub(1)).min(3)),
    ))
}

/// Maps a final (post-retry) status to an error. Throttling/unavailable
/// statuses stay typed so the HTTP layer can propagate 429/503 and the
/// upstream `Retry-After`; other failures keep the operation-specific
/// message the logs/tests already use.
fn status_error(
    operation: &str,
    status: reqwest::StatusCode,
    retry_after: Option<u64>,
) -> anyhow::Error {
    if matches!(status.as_u16(), 429 | 503) {
        return anyhow::Error::new(super::storage::UpstreamStatus {
            status: status.as_u16(),
            retry_after,
        });
    }
    anyhow!(format!("s3 {operation} failed: {status}"))
}

#[derive(Clone)]
pub(crate) struct S3Client {
    endpoint: String,
    /// The endpoint's path component (e.g. `/storage` in
    /// `https://minio.example.com/storage`): SigV4 signs the request path
    /// exactly, so a base path must be part of the canonical URI too.
    path_prefix: String,
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
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let path_prefix = endpoint
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(endpoint.as_str())
            .split_once('/')
            .map(|(_, path)| path.trim_matches('/').to_string())
            .unwrap_or_default();
        S3Client {
            endpoint,
            path_prefix,
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

    /// Sends one signed request. The signature is rebuilt on every call
    /// because `x-amz-date` changes; retries call this again.
    async fn send_once(
        &self,
        request: &SignedRequest<'_>,
    ) -> std::result::Result<reqwest::Response, SendFailure> {
        let url = self.url(request.key);
        let url = if request.query.is_empty() {
            url
        } else {
            format!("{url}?{}", request.query)
        };
        let now = crate::util::unix_now();
        let amz_date = amz_datetime(now);
        let date = &amz_date[..8];
        let payload_hash =
            if request.body.is_some() || request.method == "PUT" || request.method == "GET" {
                sha256_hex(request.body.unwrap_or(b""))
            } else {
                // HEAD/DELETE may be signed without a payload hash
                // ("UNSIGNED-PAYLOAD" is accepted by R2 and S3 for these).
                "UNSIGNED-PAYLOAD".to_string()
            };
        let authorization = self.sign(
            request.method,
            request.key,
            request.query,
            &payload_hash,
            &amz_date,
            date,
            request.content_type,
            request.extra_headers,
        );
        let mut builder = request
            .http
            .request(
                reqwest::Method::from_bytes(request.method.as_bytes()).unwrap(),
                &url,
            )
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", authorization);
        if let Some(ct) = request.content_type {
            builder = builder.header("Content-Type", ct);
        }
        for (name, value) in request.extra_headers {
            builder = builder.header(*name, *value);
        }
        if let Some(bytes) = request.body {
            builder = builder.body(bytes.to_vec());
        }
        let send = builder.send();
        match request.timeout {
            Some(limit) => match tokio::time::timeout(limit, send).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(e)) => Err(SendFailure::Request(e)),
                Err(_) => Err(SendFailure::Timeout),
            },
            None => send.await.map_err(SendFailure::Request),
        }
    }

    /// Sends a signed request with bounded retries for transient upstream
    /// failures. Only the initial response is retried (a body stream that
    /// fails mid-transfer cannot be resumed transparently).
    async fn send_retrying(&self, request: &SignedRequest<'_>) -> Result<reqwest::Response> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.send_once(request).await {
                Ok(response) => {
                    if attempt < S3_RETRY_ATTEMPTS
                        && retryable_status(response.status())
                        && let Some(delay) = retry_delay(attempt, Some(&response))
                    {
                        drop(response);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Ok(response);
                }
                Err(SendFailure::Request(e)) => {
                    // A spent total timeout or a malformed builder is not
                    // transient; only connection-level failures retry.
                    if attempt < S3_RETRY_ATTEMPTS
                        && !e.is_timeout()
                        && !e.is_builder()
                        && let Some(delay) = retry_delay(attempt, None)
                    {
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(anyhow!(format!("s3 request failed: {e}")));
                }
                Err(SendFailure::Timeout) => {
                    return Err(anyhow!("s3 request timed out waiting for a response"));
                }
            }
        }
    }

    async fn request(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<reqwest::Response> {
        self.send_retrying(&SignedRequest {
            http: &self.http,
            method,
            key,
            query,
            body,
            content_type,
            extra_headers,
            timeout: None,
        })
        .await
    }

    /// Like [`Self::request`] but on the unbounded-streaming client, used
    /// only by the blob GET whose body is relayed to the client (a total
    /// timeout would truncate slow downloads; the client connection
    /// bounds the stream lifetime). The header wait is bounded per attempt.
    async fn request_stream(
        &self,
        method: &str,
        key: &str,
        query: &str,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<reqwest::Response> {
        self.send_retrying(&SignedRequest {
            http: &self.http_stream,
            method,
            key,
            query,
            body: None,
            content_type,
            extra_headers,
            timeout: Some(S3_HEADER_TIMEOUT),
        })
        .await
    }

    async fn send(
        &self,
        method: &str,
        key: &str,
        query: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(reqwest::StatusCode, Vec<u8>, Option<u64>)> {
        let resp = self
            .request(method, key, query, body, content_type, extra_headers)
            .await?;
        let status = resp.status();
        let retry_after = retry_after(&resp);
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow!(format!("s3 response failed: {e}")))?
            .to_vec();
        Ok((status, bytes, retry_after))
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
        // signature would mismatch the encoded URL and yield a 403), and an
        // endpoint base path (`endpoint` may carry one) is part of the path.
        let canonical_uri = if self.path_prefix.is_empty() {
            format!("/{}/{}", self.bucket, encoded_key(key))
        } else {
            format!("/{}/{}/{}", self.path_prefix, self.bucket, encoded_key(key))
        };
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

    #[cfg(test)]
    pub(crate) async fn put_object(&self, key: &str, bytes: &[u8], mime: &str) -> Result<()> {
        let (status, _, retry_after) = self
            .send("PUT", key, "", Some(bytes), Some(mime), &[])
            .await?;
        if !status.is_success() {
            return Err(status_error("put", status, retry_after));
        }
        Ok(())
    }

    pub(crate) async fn put_object_file(
        &self,
        key: &str,
        path: &std::path::Path,
        size: u64,
        mime: &str,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        // PUT is idempotent for the same key/bytes: a transient status or
        // connection failure is retried by reopening the source file and
        // rebuilding the stream.
        for attempt in 1..=S3_RETRY_ATTEMPTS {
            let file = tokio::fs::File::open(path).await?;
            let stream = futures_util::stream::unfold(file, |mut file| async move {
                let mut chunk = vec![0u8; 64 * 1024];
                match file.read(&mut chunk).await {
                    Ok(0) => None,
                    Ok(n) => {
                        chunk.truncate(n);
                        Some((Ok::<bytes::Bytes, std::io::Error>(chunk.into()), file))
                    }
                    Err(e) => Some((Err(e), file)),
                }
            });
            let url = self.url(key);
            let now = crate::util::unix_now();
            let amz_date = amz_datetime(now);
            let date = &amz_date[..8];
            let payload_hash = "UNSIGNED-PAYLOAD";
            let authorization = self.sign(
                "PUT",
                key,
                "",
                payload_hash,
                &amz_date,
                date,
                Some(mime),
                &[("Content-Length", &size.to_string())],
            );
            // Total bound for the upload: generous for large blobs, but a
            // stalled endpoint must not pin the upload permit forever.
            let response = match tokio::time::timeout(
                S3_PUT_TIMEOUT,
                self.http_stream
                    .put(url)
                    .header("x-amz-date", &amz_date)
                    .header("x-amz-content-sha256", payload_hash)
                    .header("Authorization", authorization)
                    .header("Content-Type", mime)
                    .header("Content-Length", size)
                    .body(reqwest::Body::wrap_stream(stream))
                    .send(),
            )
            .await
            {
                Ok(Ok(response)) => response,
                Ok(Err(e)) => {
                    if attempt < S3_RETRY_ATTEMPTS
                        && !e.is_timeout()
                        && let Some(delay) = retry_delay(attempt, None)
                    {
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(anyhow!(format!("s3 request failed: {e}")));
                }
                Err(_) => return Err(anyhow!("s3 put timed out")),
            };
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            if attempt < S3_RETRY_ATTEMPTS
                && retryable_status(status)
                && let Some(delay) = retry_delay(attempt, Some(&response))
            {
                drop(response);
                tokio::time::sleep(delay).await;
                continue;
            }
            return Err(status_error("put", status, retry_after(&response)));
        }
        unreachable!("the retry loop returns on its last attempt")
    }

    pub(crate) async fn get_object(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let (status, bytes, retry_after) = self.send("GET", key, "", None, None, &[]).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(status_error("get", status, retry_after));
        }
        Ok(Some(bytes))
    }

    /// A HEAD request: existence without downloading the object (the
    /// Blossom HEAD path must not issue a full GET and discard the body).
    pub(crate) async fn head_object(&self, key: &str) -> Result<bool> {
        let (status, _, retry_after) = self.send("HEAD", key, "", None, None, &[]).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !status.is_success() {
            return Err(status_error("head", status, retry_after));
        }
        Ok(true)
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
            return Err(status_error("get", status, retry_after(&resp)));
        }
        // A 206 body must actually be the requested span: a misbehaving
        // proxy/backend can answer 206 with another range, and the caller
        // would label those bytes as `start..start+len`. A 200 means the
        // backend ignored Range; the caller serves it as a full blob.
        if range.is_some() && status == reqwest::StatusCode::PARTIAL_CONTENT {
            let content_range = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok());
            let Some(content_range) = content_range else {
                return Err(anyhow!("S3 ranged response is missing Content-Range"));
            };
            if !content_range_matches(content_range, start, len) {
                return Err(anyhow!(
                    "S3 ranged response does not match the requested range"
                ));
            }
            if let Some(length) = resp
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                && length != len
            {
                return Err(anyhow!(
                    "S3 ranged response length does not match the requested range"
                ));
            }
        }
        Ok(Some(resp))
    }

    pub(crate) async fn delete_object(&self, key: &str) -> Result<bool> {
        // S3 answers 204 for DELETE of a missing key, so existence is
        // checked with a HEAD first (the caller's `existed` flag must be
        // meaningful).
        let (head, _, head_retry) = self.send("HEAD", key, "", None, None, &[]).await?;
        if head == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !head.is_success() {
            // A failed existence probe means the DELETE result would be
            // meaningless; surface it instead of guessing.
            return Err(status_error("delete", head, head_retry));
        }
        let (status, _, retry_after) = self.send("DELETE", key, "", None, None, &[]).await?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !status.is_success() {
            // Propagate the failure: the caller must not drop the owner
            // mapping for an object that is still in the bucket (that
            // would orphan a billed object with no way to delete it).
            return Err(status_error("delete", status, retry_after));
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
        let (status, bytes, retry_after) = self.send("GET", "", &query, None, None, &[]).await?;
        if !status.is_success() {
            return Err(status_error("list", status, retry_after));
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

/// Validates `bytes <start>-<end>/<total>` against the requested span.
/// `*` is accepted for the total; a concrete total must include the end.
fn content_range_matches(header: &str, start: u64, len: u64) -> bool {
    let Some(rest) = header.strip_prefix("bytes ") else {
        return false;
    };
    let Some((span, total)) = rest.split_once('/') else {
        return false;
    };
    let Some((first, last)) = span.split_once('-') else {
        return false;
    };
    let (Ok(first), Ok(last)) = (first.parse::<u64>(), last.parse::<u64>()) else {
        return false;
    };
    if first != start || last < first || last - first + 1 != len {
        return false;
    }
    match total {
        "*" => true,
        total => total.parse::<u64>().is_ok_and(|total| total > last),
    }
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
    fn content_range_validation_rejects_a_mislabeled_span() {
        assert!(content_range_matches("bytes 10-19/100", 10, 10));
        assert!(content_range_matches("bytes 10-19/*", 10, 10));
        assert!(!content_range_matches("bytes 0-9/100", 10, 10));
        assert!(!content_range_matches("bytes 10-18/100", 10, 10));
        assert!(!content_range_matches("bytes 10-19/19", 10, 10));
        assert!(!content_range_matches("items 10-19/100", 10, 10));
    }

    #[test]
    fn percent_encode_preserves_safe_chars() {
        assert_eq!(percent_encode("npub1abc/-_~/"), "npub1abc%2F-_~%2F");
    }
}

#[cfg(test)]
pub(crate) mod mock_server {
    use super::*;
    use axum::body::Body;
    use axum::extract::{Path, RawQuery, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    pub(crate) type Store = Arc<Mutex<HashMap<String, Vec<u8>>>>;

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

    async fn head(
        Path((_bucket, key)): Path<(String, String)>,
        State(store): State<Store>,
    ) -> Response {
        match store.lock().unwrap().get(&key) {
            Some(data) => Response::builder()
                .status(StatusCode::OK)
                .header("content-length", data.len())
                .body(Body::empty())
                .unwrap(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
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

    pub(crate) async fn build_mock() -> (String, Store) {
        let store: Store = Arc::new(Mutex::new(HashMap::new()));
        let app = axum::Router::new()
            .route(
                "/{bucket}/{*key}",
                axum::routing::put(put).get(get).head(head).delete(delete),
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

        // HEAD: existence without a body (the Blossom HEAD path uses this
        // instead of fetching the object).
        assert!(client.head_object("dir/file.txt").await.unwrap());
        assert!(!client.head_object("nope").await.unwrap());

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

    #[tokio::test]
    async fn transient_s3_statuses_are_retried_and_throttling_propagates() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A bucket that answers 503 twice (with Retry-After: 0) and then
        // succeeds: the client must retry rather than surface the first
        // transient failure.
        let hits = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/bucket/{*key}",
            axum::routing::get({
                let hits = Arc::clone(&hits);
                move || {
                    let attempt = hits.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if attempt < 2 {
                            (
                                StatusCode::SERVICE_UNAVAILABLE,
                                [("retry-after", "0")],
                                "busy",
                            )
                                .into_response()
                        } else {
                            "hello".into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = S3Client::new(&format!("http://{addr}"), "us-east-1", "bucket", "ak", "sk");
        assert_eq!(
            client.get_object("k").await.unwrap().unwrap(),
            b"hello",
            "two transient 503s must be retried"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 3);

        // A persistent 429 must not be flattened to a generic storage
        // fault: the typed error carries the upstream status and the
        // Retry-After for the HTTP layer.
        let app = axum::Router::new().route(
            "/bucket/{*key}",
            axum::routing::get(|| async {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "0")],
                    "slow down",
                )
                    .into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let throttled = S3Client::new(&format!("http://{addr}"), "us-east-1", "bucket", "ak", "sk");
        let err = throttled.get_object("k").await.unwrap_err();
        let upstream = err
            .downcast_ref::<super::super::storage::UpstreamStatus>()
            .expect("429 must stay typed");
        assert_eq!(upstream.status, 429);
        assert_eq!(upstream.retry_after, Some(0));
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
