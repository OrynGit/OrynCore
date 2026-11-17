//! 出口查询与选点全部经调用方注入的固定叶子 Connector。
//! 来源与接口参考 better-speedtest 238741b0bb7873e168c68f8f27cf4cf6750bba4e：
//! internal/nodes/ookla.go、assets/config.default.json；Copyright (c) 2026 gaimoy (MIT)。
//! 独立 Rust 实现，来源清单与许可记录见 Oryn_dev/docs/oryncore/provenance.md。

use super::conn::{Body, Reply, SpeedConn};
use super::{Source, DISCOVERY_MAX_BODY, REQUEST_TIMEOUT};
use oryn_http::{fetch, Connector, Options, Request, Response, Url};
use serde::Deserialize;
use serde_json::Value;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

const PROBE_BYTES: usize = 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_CANDIDATES: usize = 5;
/// 选点与列表：预热后在同一连接上测的次数（取中位数）。
const SELECT_PINGS: usize = 3;
/// 选定后报告的延迟：同一连接上再测的次数（取中位数）。
const FINAL_PINGS: usize = 10;
const FINAL_TIMEOUT: Duration = Duration::from_secs(6);
/// 列表最多返回的服务器数（Ookla config-sdk 的 `limit` 也是 10）。
const MAX_LISTED: usize = 10;
/// 展示用文本的字符上限。
const MAX_TEXT: usize = 64;
const MAX_HOST: usize = 255;
const OOKLA_CONFIG: &str =
    "https://www.speedtest.net/api/js/config-sdk?engine=js&limit=10&https_functional=true";

#[derive(Clone, Debug)]
pub(super) struct Server {
    /// 稳定标识：Ookla 为 host authority，大陆 CDN 为目录名，Cloudflare 为机房代码。
    pub id: String,
    pub name: String,
    /// 城市、国家等展示用位置，可为空。
    pub location: String,
    /// 相对出口的距离（公里），仅 Ookla 提供。
    pub distance_km: Option<f64>,
    pub download: String,
    pub upload: Option<String>,
    pub parameter: &'static str,
    pub range: bool,
    pub user_agent: Option<String>,
}

impl Server {
    /// 不限速时每个下载请求的大小：Ookla 主机接受任意大小，取 1 GB（方向结束时中止）；
    /// Cloudflare `__down` 在 100 MB 时拒绝，取 25 MB；大陆 CDN 的 Range 受文件大小限制，保持 1 MiB。
    pub fn max_download(&self) -> usize {
        match self.parameter {
            "size" => 1_000_000_000,
            "bytes" => 25_000_000,
            _ => 1024 * 1024,
        }
    }

    /// 展示用的 `host[:port]`，默认 443 端口省略。
    pub fn host(&self) -> String {
        match Url::parse(&self.download) {
            Ok(url) if url.port == 443 || url.port == 80 => url.host,
            Ok(url) => format!("{}:{}", url.host, url.port),
            Err(_) => String::new(),
        }
    }

    pub fn request_url(&self, upload: bool, bytes: usize) -> String {
        let base = if upload {
            self.upload.as_deref().unwrap_or("")
        } else {
            &self.download
        };
        // 保留原查询参数；每次请求使用新 nonce，避免缓存命中掩盖真实数据路径。
        let separator = if base.contains('?') { '&' } else { '?' };
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        if upload || self.range {
            format!("{base}{separator}oryn_nocache={nonce}")
        } else {
            format!(
                "{base}{separator}{}={bytes}&oryn_nocache={nonce}",
                self.parameter
            )
        }
    }

    /// 在 `conn` 上发一次测试请求并校验，返回计入吞吐的字节数（上传为发出的正文）。
    /// 上传正文是 `bytes` 个零字节，循环写出；下载体只计数不保留。
    pub async fn transfer(
        &self,
        conn: &mut SpeedConn,
        connector: &dyn Connector,
        upload: bool,
        bytes: usize,
        timeout: Duration,
    ) -> Result<usize, String> {
        let reply = self.request(conn, connector, upload, bytes, timeout).await?;
        validate_response(&reply.response, reply.length, upload, self.range, bytes)?;
        if upload && self.parameter == "size" {
            validate_ookla_upload(&reply.response.body, bytes)?;
        }
        Ok(if upload { bytes } else { reply.length })
    }

    async fn request(
        &self,
        conn: &mut SpeedConn,
        connector: &dyn Connector,
        upload: bool,
        bytes: usize,
        timeout: Duration,
    ) -> Result<Reply, String> {
        if upload && self.upload.is_none() {
            return Err("this source supports download only".into());
        }
        let url = self.request_url(upload, bytes);
        let range = format!("bytes=0-{}", bytes.saturating_sub(1));
        let mut headers = vec![
            ("Cache-Control", "no-cache"),
            ("Accept-Encoding", "identity"),
        ];
        if let Some(ua) = &self.user_agent {
            headers.push(("User-Agent", ua));
        }
        if self.range && !upload {
            headers.push(("Range", &range));
        }
        if upload {
            headers.push(("Content-Type", "application/octet-stream"));
        }
        conn.send(
            connector,
            if upload { "POST" } else { "GET" },
            &url,
            &headers,
            if upload { Body::Zeros(bytes) } else { Body::Empty },
            if upload { 64 * 1024 } else { bytes },
            !upload,
            timeout,
        )
        .await
        .map_err(|e| format!("test request failed: {e}"))
    }

    /// 一个延迟样本（毫秒），在 `conn` 已建立的连接上测：Ookla 为 `/ping`；Cloudflare 为
    /// `__down?bytes=0`，按 Cloudflare 测速库的做法减去 `Server-Timing` 的第一个 `dur`；
    /// 大陆 CDN 为 1 字节的 Range 请求。
    pub async fn ping(
        &self,
        conn: &mut SpeedConn,
        connector: &dyn Connector,
        timeout: Duration,
    ) -> Result<f64, String> {
        let reply = match self.parameter {
            "size" => {
                let url = Url::parse(&self.download).map_err(|e| e.to_string())?;
                let scheme = if url.https { "https" } else { "http" };
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let ping = format!("{scheme}://{}/ping?oryn_nocache={nonce}", url.host_header());
                let mut headers = vec![("Cache-Control", "no-cache")];
                if let Some(ua) = &self.user_agent {
                    headers.push(("User-Agent", ua));
                }
                conn.send(
                    connector,
                    "GET",
                    &ping,
                    &headers,
                    Body::Empty,
                    1024,
                    true,
                    timeout,
                )
                .await
                .map_err(|e| format!("latency request failed: {e}"))?
            }
            "bytes" => self.request(conn, connector, false, 0, timeout).await?,
            _ => self.request(conn, connector, false, 1, timeout).await?,
        };
        if !reply.response.is_success() {
            return Err(format!(
                "latency request returned HTTP {}",
                reply.response.status
            ));
        }
        let elapsed = reply.elapsed.as_secs_f64() * 1000.0;
        Ok((elapsed - server_time_ms(&reply.response)).max(0.0))
    }

    /// 在已预热的 `conn` 上连续测 `samples` 次，取中位数。
    pub async fn latency(
        &self,
        conn: &mut SpeedConn,
        connector: &dyn Connector,
        samples: usize,
    ) -> Result<f64, String> {
        let mut values = Vec::with_capacity(samples);
        for _ in 0..samples {
            values.push(self.ping(conn, connector, PROBE_TIMEOUT).await?);
        }
        Ok(median(values))
    }
}

/// `Server-Timing` 里第一个 `dur=`（毫秒），没有时为 0。
fn server_time_ms(r: &Response) -> f64 {
    r.header("server-timing")
        .and_then(|v| v.split("dur=").nth(1))
        .and_then(|rest| {
            rest.split(|c: char| !(c.is_ascii_digit() || c == '.'))
                .next()
        })
        .and_then(|n| n.parse::<f64>().ok())
        .filter(|n| n.is_finite() && *n >= 0.0)
        .unwrap_or(0.0)
}

fn median(mut values: Vec<f64>) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn validate_ookla_upload(body: &[u8], bytes: usize) -> Result<(), String> {
    let received = std::str::from_utf8(body)
        .ok()
        .and_then(|s| s.trim().strip_prefix("size="))
        .and_then(|s| s.parse::<usize>().ok());
    if received == Some(bytes) {
        Ok(())
    } else {
        Err("Ookla upload acknowledgement does not match the sent payload".into())
    }
}

/// `length` 是实际收到的响应体字节数（下载体不保留，`r.body` 为空）。
fn validate_response(
    r: &Response,
    length: usize,
    upload: bool,
    range: bool,
    bytes: usize,
) -> Result<(), String> {
    if !r.is_success() {
        return Err(format!("test request returned HTTP {}", r.status));
    }
    if upload {
        return Ok(());
    }
    if r.header("content-type").is_some_and(|v| {
        let v = v.to_ascii_lowercase();
        v.contains("text/html") || v.contains("application/json")
    }) {
        return Err("test server returned a page instead of download data".into());
    }
    if length != bytes {
        return Err("test server returned an unexpected download length".into());
    }
    if range {
        let expected = format!("bytes 0-{}/", bytes.saturating_sub(1));
        let valid = r
            .header("content-range")
            .and_then(|v| v.strip_prefix(&expected))
            .and_then(|total| total.parse::<u64>().ok())
            .is_some_and(|total| total >= bytes as u64);
        if r.status != 206 || !valid {
            return Err("CDN server did not honor the requested byte range".into());
        }
    }
    Ok(())
}

pub(super) struct Discovery {
    pub server: Server,
    pub egress_ip: String,
    pub latency_ms: f64,
}

async fn control(connector: &dyn Connector, url: &str) -> Result<Vec<u8>, String> {
    let response = fetch(
        connector,
        Request {
            method: "GET",
            url,
            headers: &[
                ("Accept", "application/json, text/plain"),
                ("Cache-Control", "no-cache"),
            ],
            body: &[],
        },
        &Options {
            timeout: REQUEST_TIMEOUT,
            max_body: DISCOVERY_MAX_BODY,
            max_redirects: 0,
            skip_verify: false,
        },
    )
    .await
    .map_err(|e| format!("server discovery failed: {e}"))?;
    if !response.is_success() {
        return Err(format!(
            "server discovery returned HTTP {}",
            response.status
        ));
    }
    Ok(response.body)
}

fn ip(value: Option<&str>) -> Result<String, String> {
    value
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .ok_or_else(|| "discovery response has no valid egress IP".into())
}

pub(super) struct Catalog {
    pub egress_ip: String,
    pub servers: Vec<Server>,
}

/// 经注入的 Connector 读取出口 IP 与该来源的服务器目录（Ookla 按距离排序）。
async fn catalog(connector: &dyn Connector, source: Source) -> Result<Catalog, String> {
    let (egress_ip, servers) = match source {
        Source::Cloudflare => {
            let body = control(connector, "https://speed.cloudflare.com/cdn-cgi/trace").await?;
            cloudflare(&body)?
        }
        Source::Ookla => {
            let body = control(connector, OOKLA_CONFIG).await?;
            ookla(&body)?
        }
        Source::China => {
            let body = control(connector, "https://myip.ipip.net/json").await?;
            let value: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            let egress_ip = ip(value.pointer("/data/ip").and_then(Value::as_str))?;
            (egress_ip, china_servers()?)
        }
    };
    Ok(Catalog { egress_ip, servers })
}

/// `choice` 为 None 时在最近的几台里探测取最快；指定时只探测这一台，不可用则失败，不换别的服务器。
pub(super) async fn discover(
    connector: &dyn Connector,
    source: Source,
    need_download: bool,
    need_upload: bool,
    choice: Option<&str>,
) -> Result<Discovery, String> {
    // 外层 timeout 同时覆盖控制请求、所有探测及 future 取消后的连接释放。
    tokio::time::timeout(Duration::from_secs(45), async {
        if source == Source::China && need_upload {
            return Err("China mainland CDN supports download only".into());
        }
        let Catalog {
            egress_ip,
            mut servers,
        } = catalog(connector, source).await?;
        if let Some(id) = choice {
            servers = vec![pick(source, servers, id)?];
        }
        let (server, mut conn, mut latency_ms) =
            select(connector, servers, need_download, need_upload).await?;
        // 选定后在同一条已预热的连接上再测，报告中位数；失败时保留选点时的读数。
        if let Ok(Ok(final_ms)) = tokio::time::timeout(
            FINAL_TIMEOUT,
            server.latency(&mut conn, connector, FINAL_PINGS),
        )
        .await
        {
            latency_ms = final_ms;
        }
        Ok(Discovery {
            server,
            egress_ip,
            latency_ms,
        })
    })
    .await
    .map_err(|_| "server discovery timed out".to_string())?
}

fn pick(source: Source, servers: Vec<Server>, id: &str) -> Result<Server, String> {
    if let Some(found) = servers.into_iter().find(|s| s.id == id) {
        return Ok(found);
    }
    match source {
        // 该台可能已不在最新的前 10 名里；host 仍须通过与列表相同的 authority 校验。
        Source::Ookla => ookla_server(id, "", "", "", None)
            .ok_or_else(|| "the selected Ookla server is invalid".to_string()),
        _ => Err("the selected server is not available through this outbound".into()),
    }
}

/// 同一任务内并发推进全部 future，按输入顺序返回结果（不引入 futures 依赖）。
async fn join_all<F: Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pending: Vec<Option<Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut done: Vec<Option<F::Output>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut all_ready = true;
        for (slot, out) in pending.iter_mut().zip(done.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *out = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => all_ready = false,
                }
            }
        }
        if all_ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    done.into_iter().flatten().collect()
}

async fn probe_all(connector: &dyn Connector, servers: Vec<Server>) -> Vec<Listed> {
    let probes = servers
        .into_iter()
        .take(MAX_LISTED)
        .map(|server| async move {
            let result = tokio::time::timeout(
                PROBE_TIMEOUT,
                probe(connector, &server, true, false),
            )
            .await;
            let latency_ms = match result {
                Ok(Ok((_, latency))) => Some(latency),
                _ => None,
            };
            Listed { server, latency_ms }
        });
    join_all(probes.collect()).await
}

pub(super) struct Listed {
    pub server: Server,
    /// 并发探测得到的延迟（预热后同一连接上的中位数）；探测失败为 None，表示当前不可用。
    pub latency_ms: Option<f64>,
}

/// 列出服务器并并发探测延迟。每台最多 4 秒，整体仍受 45 秒上限。
pub(super) async fn list(
    connector: &dyn Connector,
    source: Source,
) -> Result<(String, Vec<Listed>), String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let Catalog {
            egress_ip, servers, ..
        } = catalog(connector, source).await?;
        Ok((egress_ip, probe_all(connector, servers).await))
    })
    .await
    .map_err(|_| "server list timed out".to_string())?
}

fn cloudflare(body: &[u8]) -> Result<(String, Vec<Server>), String> {
    let text = std::str::from_utf8(body).map_err(|e| e.to_string())?;
    let field = |key| {
        text.lines()
            .filter_map(|s| s.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    };
    let egress_ip = ip(field("ip"))?;
    let colo = field("colo")
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase()))
        .ok_or("Cloudflare trace has no valid edge location")?;
    Ok((
        egress_ip,
        vec![Server {
            id: colo.into(),
            name: format!("Cloudflare · {colo}"),
            location: String::new(),
            distance_km: None,
            download: "https://speed.cloudflare.com/__down".into(),
            upload: Some("https://speed.cloudflare.com/__up".into()),
            parameter: "bytes",
            range: false,
            user_agent: None,
        }],
    ))
}

/// API 的 host 是 authority，不接受路径、userinfo 或头部注入。
fn ookla_server(
    host: &str,
    sponsor: &str,
    city: &str,
    country: &str,
    distance_km: Option<f64>,
) -> Option<Server> {
    if host.is_empty()
        || host.len() > MAX_HOST
        || host
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/?#@".contains(c))
    {
        return None;
    }
    let base = format!("https://{host}");
    let parsed = Url::parse(&base).ok()?;
    if parsed.port == 0 {
        return None;
    }
    let name = if sponsor.is_empty() && city.is_empty() {
        clip(host)
    } else {
        clip(&format!(
            "{} · {}",
            if sponsor.is_empty() { "Ookla" } else { sponsor },
            city
        ))
    };
    let location = [city, country]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    Some(Server {
        id: host.into(),
        name,
        location: clip(&location),
        distance_km,
        download: format!("{base}/download"),
        upload: Some(format!("{base}/upload")),
        parameter: "size",
        range: false,
        user_agent: None,
    })
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_TEXT).collect()
}

fn ookla(body: &[u8]) -> Result<(String, Vec<Server>), String> {
    let value: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid Ookla config: {e}"))?;
    let egress_ip = ip(value.get("ipAddress").and_then(Value::as_str))?;
    let list = value
        .get("servers")
        .and_then(Value::as_array)
        .ok_or("Ookla returned no server list")?;
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();
    let mut candidates: Vec<_> = list
        .iter()
        .filter_map(|v| {
            let distance = v
                .get("distance")
                .and_then(|d| d.as_f64().or_else(|| d.as_str()?.parse().ok()))?;
            if !distance.is_finite() || distance < 0.0 {
                return None;
            }
            let host = v.get("host")?.as_str()?;
            let server = ookla_server(
                host,
                &clip(&text(v, "sponsor")),
                &clip(&text(v, "name")),
                &clip(&text(v, "country")),
                Some(distance),
            )?;
            Some((distance, server))
        })
        .collect();
    candidates.sort_by(|a, b| a.0.total_cmp(&b.0));
    let servers = candidates
        .into_iter()
        .take(MAX_LISTED)
        .map(|(_, s)| s)
        .collect();
    Ok((egress_ip, servers))
}

#[derive(Deserialize)]
struct CdnSource {
    name: String,
    url: String,
    user_agent: Option<String>,
}

fn china_servers() -> Result<Vec<Server>, String> {
    let sources: Vec<CdnSource> =
        serde_json::from_str(include_str!("china_cdn.json")).map_err(|e| e.to_string())?;
    Ok(sources
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|s| Server {
            id: s.name.clone(),
            name: s.name,
            location: String::new(),
            distance_km: None,
            download: s.url,
            upload: None,
            parameter: "",
            range: true,
            user_agent: s.user_agent,
        })
        .collect())
}

/// 一台候选：在一条新连接上先做需要的下载 / 上传小请求（同时预热连接），再测延迟。
async fn probe(
    connector: &dyn Connector,
    server: &Server,
    need_download: bool,
    need_upload: bool,
) -> Result<(SpeedConn, f64), String> {
    let mut conn = SpeedConn::default();
    if need_download {
        server
            .transfer(&mut conn, connector, false, PROBE_BYTES, PROBE_TIMEOUT)
            .await?;
    }
    if need_upload {
        server
            .transfer(&mut conn, connector, true, PROBE_BYTES, PROBE_TIMEOUT)
            .await?;
    }
    if !need_download && !need_upload {
        server.ping(&mut conn, connector, PROBE_TIMEOUT).await?;
    }
    let latency = server.latency(&mut conn, connector, SELECT_PINGS).await?;
    Ok((conn, latency))
}

/// 并发探测候选，取延迟最低的一台，连同它已预热的连接一起返回。
async fn select(
    connector: &dyn Connector,
    servers: Vec<Server>,
    need_download: bool,
    need_upload: bool,
) -> Result<(Server, SpeedConn, f64), String> {
    let probes = servers
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|server| async move {
            let result = tokio::time::timeout(
                PROBE_TIMEOUT,
                probe(connector, &server, need_download, need_upload),
            )
            .await
            .unwrap_or_else(|_| Err("candidate probe timed out".into()));
            (server, result)
        });
    let mut best: Option<(Server, SpeedConn, f64)> = None;
    let mut last_error = "no candidates".to_string();
    for (server, result) in join_all(probes.collect()).await {
        match result {
            Ok((conn, latency)) if best.as_ref().is_none_or(|(_, _, time)| latency < *time) => {
                best = Some((server, conn, latency))
            }
            Ok(_) => {}
            Err(e) => last_error = e,
        }
    }
    best.ok_or_else(|| format!("no usable test server through the selected outbound: {last_error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oryn_outbound::BoxStream;
    use std::io;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server(host: &str, range: bool) -> Server {
        Server {
            id: host.into(),
            name: host.into(),
            location: String::new(),
            distance_km: None,
            download: format!("http://{host}/download?existing=1"),
            upload: Some(format!("http://{host}/upload")),
            parameter: "size",
            range,
            user_agent: None,
        }
    }

    #[test]
    fn ookla_uses_egress_distance_and_https_host_not_legacy_php_url() {
        let config = serde_json::json!({"ipAddress":"203.0.113.7", "servers":[
            {"host":"far.test:8080", "distance":1000, "url":"http://wrong.test/speedtest/upload.php"},
            {"host":"near.test:8443", "distance":"2", "name":"Nearby", "sponsor":"Test"},
            {"host":"bad.test/path", "distance":0},
            {"host":"user@bad.test", "distance":0},
            {"host":"negative.test", "distance":-1}
        ]});
        let (ip, servers) = ookla(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(ip, "203.0.113.7");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].download, "https://near.test:8443/download");
        assert_eq!(
            servers[0].upload.as_deref(),
            Some("https://near.test:8443/upload")
        );
        assert_eq!(servers[1].download, "https://far.test:8080/download");
        assert!(ookla(br#"{"servers":[]}"#).is_err());
    }

    #[test]
    fn cloudflare_requires_egress_and_records_actual_colo() {
        let (ip, servers) = cloudflare(b"ip=2001:db8::1\ncolo=SIN\nloc=SG\n").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(servers[0].name, "Cloudflare · SIN");
        assert!(cloudflare(b"ip=not-an-ip\ncolo=SIN\n").is_err());
        assert!(cloudflare(b"ip=192.0.2.1\n").is_err());
    }

    #[test]
    fn mainland_catalog_and_query_are_bounded() {
        let list = china_servers().unwrap();
        assert_eq!(list.len(), MAX_CANDIDATES);
        for s in list {
            assert!(s.range && s.upload.is_none());
            assert!(Url::parse(&s.download).unwrap().https);
        }
        let s = server("test.invalid", false);
        assert!(s
            .request_url(false, 32)
            .starts_with("http://test.invalid/download?existing=1&size=32&oryn_nocache="));
        let s = server("test.invalid", true);
        assert!(!s.request_url(false, 32).contains("size="));
    }

    #[test]
    fn rejects_pages_truncation_and_ignored_or_incorrect_range() {
        let mut r = Response {
            status: 206,
            headers: vec![("content-range".into(), "bytes 0-1023/4096".into())],
            body: Vec::new(),
        };
        assert!(validate_response(&r, 1024, false, true, 1024).is_ok());
        r.status = 200;
        assert!(validate_response(&r, 1024, false, true, 1024).is_err());
        r.status = 206;
        r.headers[0].1 = "bytes 1-1024/4096".into();
        assert!(validate_response(&r, 1024, false, true, 1024).is_err());
        r.headers = vec![("content-type".into(), "Text/HTML; charset=utf-8".into())];
        assert!(validate_response(&r, 1024, false, false, 1024).is_err());
        r.headers.clear();
        assert!(validate_response(&r, 1023, false, false, 1024).is_err());
        assert!(validate_ookla_upload(b"size=1024\n", 1024).is_ok());
        assert!(validate_ookla_upload(b"size=0\n", 1024).is_err());
        assert!(validate_ookla_upload(b"<html>OK</html>", 1024).is_err());
    }

    /// 不打开真实 socket；域名只有经注入 Connector 才能获得响应。
    #[derive(Default)]
    struct SelectedExit {
        requests: Mutex<Vec<String>>,
        tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    }
    impl Drop for SelectedExit {
        fn drop(&mut self) {
            for task in self.tasks.get_mut().unwrap().drain(..) {
                task.abort();
            }
        }
    }
    #[async_trait::async_trait]
    impl Connector for SelectedExit {
        async fn connect(&self, host: &str, _port: u16) -> io::Result<BoxStream> {
            if host == "offline.invalid" {
                return Err(io::ErrorKind::ConnectionRefused.into());
            }
            let (client, mut peer) = tokio::io::duplex(8192);
            let host = host.to_string();
            self.requests.lock().unwrap().push(host.clone());
            let handle = tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 2048];
                let head_end = loop {
                    let n = peer.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(i) = raw.windows(4).position(|s| s == b"\r\n\r\n") {
                        break i + 4;
                    }
                    assert!(raw.len() < 4096);
                };
                let head = String::from_utf8_lossy(&raw[..head_end]);
                let upload = head.starts_with("POST ");
                assert!(head.contains("oryn_nocache="));
                assert!(head.contains("Cache-Control: no-cache"));
                let size = if upload { 1024 } else { 0 };
                let range = head.contains("Range: bytes=0-1023");
                while raw.len() < head_end + size {
                    let n = peer.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                if host == "slow.invalid" {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
                let (status, extra, body) = if host == "page.invalid" {
                    (200, "Content-Type: text/html\r\n", vec![b'x'; 1024])
                } else if upload && host == "no-upload.invalid" {
                    (405, "", Vec::new())
                } else if upload {
                    (200, "", b"size=1024\n".to_vec())
                } else if range {
                    (206, "Content-Range: bytes 0-1023/100000\r\n", vec![1; 1024])
                } else {
                    (200, "", vec![1; 1024])
                };
                let head=format!("HTTP/1.1 {status} Test\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",body.len());
                peer.write_all(head.as_bytes()).await.unwrap();
                peer.write_all(&body).await.unwrap();
            });
            self.tasks.lock().unwrap().push(handle);
            Ok(Box::new(client))
        }
    }

    #[tokio::test]
    async fn candidate_probes_and_transfer_stay_on_selected_exit() {
        let connector = SelectedExit::default();
        let candidates = [
            "offline.invalid",
            "page.invalid",
            "no-upload.invalid",
            "slow.invalid",
            "fast.invalid",
        ]
        .into_iter()
        .map(|s| server(s, false))
        .collect();
        let (chosen, mut conn, latency) = select(&connector, candidates, true, true).await.unwrap();
        assert_eq!(chosen.name, "fast.invalid");
        assert!(latency < 30.0, "{latency}");
        chosen
            .transfer(&mut conn, &connector, false, 1024, PROBE_TIMEOUT)
            .await
            .unwrap();
        let records = connector.requests.lock().unwrap();
        assert_eq!(records.last().unwrap(), "fast.invalid");
        // 测试服务端每个请求后关闭：下载、上传、3 次 ping、之后的传输各一条连接
        assert_eq!(records.iter().filter(|h| *h == "fast.invalid").count(), 6);
        assert_eq!(records.iter().filter(|h| *h == "page.invalid").count(), 1);
    }

    #[tokio::test]
    async fn range_requests_use_same_connector_and_failure_does_not_fallback() {
        let connector = SelectedExit::default();
        let (chosen, _, _) = select(&connector, vec![server("cdn.invalid", true)], true, false)
            .await
            .unwrap();
        assert_eq!(chosen.name, "cdn.invalid");
        assert!(select(
            &connector,
            vec![server("offline.invalid", false)],
            true,
            true
        )
        .await
        .is_err());
        // Range 下载探测 1 次 + 3 次 1 字节 ping，全部在所选出站上
        assert_eq!(connector.requests.lock().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn listing_probes_concurrently_and_marks_unavailable_servers() {
        let connector = SelectedExit::default();
        let servers = [
            "offline.invalid",
            "page.invalid",
            "fast.invalid",
            "slow.invalid",
        ]
        .into_iter()
        .map(|s| server(s, false))
        .collect();
        let listed = probe_all(&connector, servers).await;
        let ids: Vec<_> = listed.iter().map(|l| l.server.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "offline.invalid",
                "page.invalid",
                "fast.invalid",
                "slow.invalid"
            ]
        );
        let available: Vec<_> = listed.iter().map(|l| l.latency_ms.is_some()).collect();
        assert_eq!(available, [false, false, true, true]);
    }

    #[test]
    fn latency_helpers_follow_cloudflare_and_use_the_median() {
        let r = Response {
            status: 200,
            headers: vec![(
                "Server-Timing".into(),
                "cfSpeedEdge;dur=2.5, cfSpeedWorker;dur=14".into(),
            )],
            body: Vec::new(),
        };
        assert_eq!(server_time_ms(&r), 2.5);
        let none = Response {
            status: 200,
            headers: vec![("Server-Timing".into(), "cfL4;desc=\"x\"".into())],
            body: Vec::new(),
        };
        assert_eq!(server_time_ms(&none), 0.0);
        assert_eq!(median(vec![9.0, 1.0, 5.0]), 5.0);
        assert_eq!(median(vec![4.0, 1.0, 2.0, 100.0]), 3.0);
        assert_eq!(median(Vec::new()), 0.0);
    }

    #[test]
    fn explicit_choice_uses_listed_server_or_validated_ookla_host() {
        let listed = vec![server("a.test:8080", false), server("b.test:8080", false)];
        let chosen = pick(Source::Ookla, listed, "b.test:8080").unwrap();
        assert_eq!(chosen.id, "b.test:8080");
        // 不在最新列表里的 Ookla host 仍按同样的校验构造。
        let built = pick(Source::Ookla, Vec::new(), "gone.test:8080").unwrap();
        assert_eq!(built.download, "https://gone.test:8080/download");
        assert!(pick(Source::Ookla, Vec::new(), "bad.test/path").is_err());
        assert!(pick(Source::Ookla, Vec::new(), "user@bad.test").is_err());
        assert!(pick(Source::China, Vec::new(), "Unknown CDN").is_err());
        assert!(pick(Source::Cloudflare, Vec::new(), "SIN").is_err());
    }

    #[test]
    fn ookla_list_keeps_ten_nearest_with_location_and_distance() {
        let servers: Vec<_> = (0..14)
            .map(|i| {
                serde_json::json!({"host": format!("s{i}.test:8080"), "distance": 100 - i,
                "name": "City", "country": "Land", "sponsor": "Net"})
            })
            .collect();
        let body =
            serde_json::to_vec(&serde_json::json!({"ipAddress":"203.0.113.9","servers":servers}))
                .unwrap();
        let (_, list) = ookla(&body).unwrap();
        assert_eq!(list.len(), MAX_LISTED);
        assert_eq!(list[0].id, "s13.test:8080");
        assert_eq!(list[0].location, "City, Land");
        assert_eq!(list[0].distance_km, Some(87.0));
        assert_eq!(list[0].name, "Net · City");
    }

    #[tokio::test]
    async fn join_all_keeps_input_order() {
        let futures: Vec<_> = [30u64, 1, 10]
            .into_iter()
            .map(|ms| async move {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                ms
            })
            .collect();
        assert_eq!(join_all(futures).await, [30, 1, 10]);
    }

    #[test]
    fn host_for_display_omits_default_ports() {
        let mut s = server("test.invalid", false);
        s.download = "https://test.invalid/download".into();
        assert_eq!(s.host(), "test.invalid");
        s.download = "https://test.invalid:8443/download".into();
        assert_eq!(s.host(), "test.invalid:8443");
    }
}
