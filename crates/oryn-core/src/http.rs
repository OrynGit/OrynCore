//! HTTP/1.1 与 HTTP/2 的消息边界由 hyper 验证。未命中 Body 规则的流保持流式转发。
use crate::stats::{ConnGuard, Stats};
use bytes::Bytes;
use http::{Request, Response, Uri, Version};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use oryn_config::TargetAddr;
use oryn_http_inspect::{Message, Plan};
use oryn_outbound::Outbound;
use std::{
    collections::VecDeque,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
type BoxBody = UnsyncBoxBody<Bytes, io::Error>;
/// 正文预算按 4 KiB 页计费，小正文可高并发共享同一预算池，大正文按实际页数扣减。
pub(crate) const BODY_PAGE: usize = 4096;
pub(crate) fn body_budget_pages(bytes: usize) -> usize {
    bytes.max(1).div_ceil(BODY_PAGE)
}
fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
#[derive(Clone)]
struct LocalExecutor;
impl<F: Future + 'static> hyper::rt::Executor<F> for LocalExecutor
where
    F::Output: 'static,
{
    fn execute(&self, f: F) {
        tokio::task::spawn_local(f);
    }
}
#[derive(Clone)]
pub struct Inspector {
    pub scripts: Arc<crate::scripts::ScriptHost>,
    pub plan: Rc<Plan>,
    pub outbound: Arc<dyn Outbound>,
    pub origin: String,
    pub skip_verify: bool,
    pub transactions: Option<Arc<Semaphore>>,
    pub upstream_establish: Arc<Semaphore>,
    pub bodies: Arc<Semaphore>,
    pub max_body: usize,
}
impl Inspector {
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin + 'static>(
        self,
        stream: S,
        http2: bool,
    ) -> io::Result<()> {
        let service = service_fn(move |req| {
            let this = self.clone();
            async move {
                let response =
                    match tokio::time::timeout(Duration::from_secs(120), this.exchange(req)).await {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionAborted => {
                            return Err(e)
                        }
                        Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => error_response(503),
                        Ok(Err(e)) if e.kind() == io::ErrorKind::TimedOut => error_response(504),
                        Ok(Err(e)) => {
                            log::warn!("HTTP inspection failed: {e}");
                            error_response(502)
                        }
                        Err(_) => error_response(504),
                    };
                Ok::<_, io::Error>(response)
            }
        });
        // hyper 的 Upgrade 要求 I/O 为 Send；lwIP 仍留在原线程，通过有界内存流接入。
        let (http_io, mut bridge) = tokio::io::duplex(8192);
        let mut stream = stream;
        let pump = tokio::io::copy_bidirectional(&mut stream, &mut bridge);
        let serving = async {
            let io = TokioIo::new(http_io);
            if http2 {
                hyper::server::conn::http2::Builder::new(LocalExecutor)
                    .max_concurrent_streams(16)
                    .initial_stream_window_size(65535)
                    .initial_connection_window_size(262144)
                    .max_header_list_size(32768)
                    .max_send_buf_size(32768)
                    .serve_connection(io, service)
                    .await
                    .map_err(err)
            } else {
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .max_buf_size(32768)
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(15))
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                    .map_err(err)
            }
        };
        tokio::pin!(pump, serving);
        tokio::select! {
            result=&mut serving=>{result?;pump.await.map(|_|())},
            result=&mut pump=>{result?;serving.await}
        }
    }
    async fn exchange(&self, mut req: Request<Incoming>) -> io::Result<Response<BoxBody>> {
        // 满额时排队等其他事务结束（有界等待），而不是立刻失败
        let _transaction = match self.transactions.clone() {
            Some(semaphore) => Some(
                tokio::time::timeout(crate::admission::patience(10), semaphore.acquire_owned())
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "HTTP concurrency limit"))?,
            ),
            None => None,
        };
        let upgrading = req.headers().contains_key("upgrade");
        let downstream_upgrade = hyper::upgrade::on(&mut req);
        let (parts, body) = req.into_parts();
        let downstream_h2 = parts.version == Version::HTTP_2;
        // 解密后的源站连接里不应出现 CONNECT。h2 扩展 CONNECT（RFC 8441）只在服务端通告
        // SETTINGS_ENABLE_CONNECT_PROTOCOL 后才会使用；这里不通告，浏览器的 WebSocket 会另开
        // HTTP/1.1 连接走 Upgrade（已支持双向桥接）。
        if parts.method == http::Method::CONNECT {
            return Ok(error_response(405));
        }
        let url = if parts.uri.scheme().is_some() {
            parts.uri.to_string()
        } else {
            let host = parts.headers.get("host").and_then(|v| v.to_str().ok());
            let base: Uri = self.origin.parse().map_err(err)?;
            format!(
                "{}://{}{}",
                base.scheme_str().unwrap_or("http"),
                host.unwrap_or(base.authority().map(|x| x.as_str()).unwrap_or("")),
                parts
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
            )
        };
        let mut message = Message {
            url,
            method: parts.method.to_string(),
            status: None,
            headers: header_pairs(&parts.headers),
            body: vec![],
        };
        let original: Uri = self.origin.parse().map_err(err)?;
        let requested: Uri = message.url.parse().map_err(err)?;
        if original.scheme_str() == Some("https")
            && (requested.host() != original.host() || requested.scheme_str() != Some("https"))
        {
            return Ok(error_response(421));
        }
        let need = self.plan.needs_body_after_rewrite(&message, None);
        let (passthrough_body, buffer, permit, request_trailers) =
            buffer_if_needed(body, need, self.bodies.clone(), self.max_body).await?;
        let buffered = buffer.is_some();
        let request_trailer_names = trailer_names(request_trailers.as_ref());
        if need && !buffered {
            return Ok(error_response(413));
        }
        if let Some(data) = buffer {
            message.body = data;
        }
        // 完整Rewrite只执行一次；请求脚本按改写后的URL/headers选择。
        let (mock, body_rewritten) = self.plan.apply_request_with_effects(&mut message)?;
        if let Some(mock) = mock {
            return self.local_response(mock, _transaction, permit);
        }
        let scripts = self
            .plan
            .scripts(&message, None)
            .into_iter()
            .filter(|s| {
                !(s.requires_body && !buffered
                    || s.dialect == oryn_module::ModuleFormat::Loon
                        && body_rewritten)
            })
            .cloned()
            .collect::<Vec<_>>();
        // 依次执行，后一个脚本看到前一个的结果；某个脚本给出本地响应时后面的不再执行。
        // 后写出的出口覆盖前面的。
        let mut script_policy = None;
        for spec in &scripts {
            match self
                .scripts
                .execute(spec, &message, None, self.outbound.clone())
                .await
            {
                Ok(done) if done.message.as_ref().is_some_and(|m| m.status.is_some()) => {
                    return self.local_response(done.message.unwrap(), _transaction, permit)
                }
                Ok(done) => {
                    if let Some(mut updated) = done.message {
                        if !done.body_modified {
                            updated.body = std::mem::take(&mut message.body);
                        }
                        message = updated;
                    }
                    if done.policy.is_some() {
                        script_policy = done.policy;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => return Err(e),
                Err(e) => log::warn!("HTTP request script {} skipped: {e}", spec.name),
            }
        }
        // 无 response 正文脚本时无需跨网络等待期保留请求正文与页面配额，发送完毕即由 GuardedBody 释放。
        let keep_req_body = buffered && self.plan.has_response_body_scripts();
        let (body, _request_body_permit, request_meta) = if buffered {
            if keep_req_body {
                let body = full_trailers(message.body.clone(), request_trailers);
                (body, permit, message)
            } else {
                let req_body = std::mem::take(&mut message.body);
                let inner = full_trailers(req_body, request_trailers);
                let body = GuardedBody {
                    inner,
                    _permit: permit,
                }
                .boxed_unsync();
                (body, None, message)
            }
        } else {
            let body = passthrough_body.expect("unbuffered request must have passthrough body");
            (body, None, message)
        };
        let target: Uri = request_meta.url.parse().map_err(err)?;
        let host = target.host().ok_or_else(|| err("HTTP URL missing host"))?;
        let https = target.scheme_str() == Some("https");
        let port = target.port_u16().unwrap_or(if https { 443 } else { 80 });
        // 跨主机重写不再匹配 Router。请求脚本点名的策略组或节点只影响这一次上游连接。
        let outbound = if let Some(name) = script_policy.as_deref() {
            match self.scripts.policy_outbound(name, host, port) {
                Ok(outbound) => outbound,
                Err(e) => {
                    log::warn!("HTTP request script policy {name}: {e}");
                    return Err(e);
                }
            }
        } else {
            Arc::clone(&self.outbound)
        };
        // 独立于入口预算，避免出站 DNS 再入时争抢入口额度；满载不排队。
        let establish = tokio::time::timeout(
            crate::admission::patience(20),
            self.upstream_establish.clone().acquire_owned(),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "HTTP upstream establish limit"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let timed_out = |_| io::Error::new(io::ErrorKind::TimedOut, "HTTP upstream establish timeout");
        let tcp = tokio::time::timeout_at(deadline, outbound
            .connect_tcp(&TargetAddr::from_host(host, port)))
            .await.map_err(timed_out)??;
        let (stream, h2): (oryn_outbound::BoxStream, bool) = if https {
            let alpn: Vec<&[u8]> = if upgrading {
                vec![b"http/1.1"]
            } else {
                vec![b"h2", b"http/1.1"]
            };
            let tls = tokio::time::timeout_at(deadline,
                oryn_tls::connect(tcp, host, &alpn, self.skip_verify))
                .await.map_err(timed_out)??;
            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            (Box::new(tls), h2)
        } else {
            (tcp, false)
        };
        let mut outgoing = Request::builder()
            .method(request_meta.method.as_str())
            .uri(if h2 {
                request_meta.url.clone()
            } else {
                target
                    .path_and_query()
                    .map(|x| x.as_str())
                    .unwrap_or("/")
                    .to_string()
            })
            .version(if h2 {
                Version::HTTP_2
            } else {
                Version::HTTP_11
            })
            .body(body)
            .map_err(err)?;
        *outgoing.headers_mut() = headers_with(&request_meta.headers, Some(&parts.headers))?;
        if !upgrading {
            strip_hop(outgoing.headers_mut());
        }
        if !h2 {
            if let Some(names) = request_trailer_names {
                outgoing.headers_mut().insert("trailer", names);
            }
            if outgoing.headers().contains_key("trailer") {
                outgoing.headers_mut().remove("content-length");
                outgoing.headers_mut().insert(
                    "transfer-encoding",
                    http::HeaderValue::from_static("chunked"),
                );
            }
            if !outgoing.headers().contains_key("host") {
                outgoing.headers_mut().insert(
                    "host",
                    target
                        .authority()
                        .ok_or_else(|| err("missing authority"))?
                        .as_str()
                        .parse()
                        .map_err(err)?,
                );
            }
            if !upgrading {
                outgoing
                    .headers_mut()
                    .insert("connection", http::HeaderValue::from_static("close"));
            }
        }
        let (mut response, driver) = if h2 {
            let (mut tx, connection) = tokio::time::timeout_at(deadline, hyper::client::conn::http2::Builder::new(LocalExecutor)
                .initial_stream_window_size(65535)
                .initial_connection_window_size(262144)
                .max_send_buf_size(32768)
                .handshake(TokioIo::new(stream)))
                .await.map_err(timed_out)?
                .map_err(err)?;
            drop(establish);
            let driver = Driver(tokio::task::spawn_local(async move {
                let _ = connection.await;
            }));
            (tx.send_request(outgoing).await.map_err(err)?, driver)
        } else {
            let (mut tx, connection) = tokio::time::timeout_at(deadline,
                hyper::client::conn::http1::handshake(TokioIo::new(stream)))
                .await.map_err(timed_out)?
                .map_err(err)?;
            drop(establish);
            let driver = Driver(tokio::task::spawn_local(async move {
                let _ = connection.with_upgrades().await;
            }));
            (tx.send_request(outgoing).await.map_err(err)?, driver)
        };
        if upgrading && response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            let mut result = Response::builder()
                .status(101)
                .body(full(vec![]))
                .map_err(err)?;
            *result.headers_mut() = response.headers().clone();
            tokio::task::spawn_local(async move {
                let _driver = driver;
                let _permit = _transaction;
                let tunnel = async {
                    let (a, b) =
                        tokio::try_join!(downstream_upgrade, upstream_upgrade).map_err(err)?;
                    tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))
                        .await
                        .map(|_| ())
                };
                let _ = tokio::time::timeout(Duration::from_secs(3600), tunnel).await;
            });
            return Ok(result);
        }
        let (parts, body) = response.into_parts();
        let mut msg = Message {
            url: request_meta.url.clone(),
            method: request_meta.method.clone(),
            status: Some(parts.status.as_u16()),
            headers: header_pairs(&parts.headers),
            body: vec![],
        };
        let need = self.plan.needs_body_after_rewrite(&msg, Some(&request_meta));
        let (passthrough_body, buffer, permit, response_trailers) =
            buffer_if_needed(body, need, self.bodies.clone(), self.max_body).await?;
        let response_trailer_names = trailer_names(response_trailers.as_ref());
        let buffered = buffer.is_some();
        if let Some(data) = buffer {
            msg.body = data;
        }
        let scripts = self
            .plan
            .scripts(&msg, Some(&request_meta))
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        // Response选择仍使用原始响应；Rewrite后只依据实际命中的正文动作抑制Loon。
        let body_rewritten = self.plan.apply_response_with_effects(&mut msg, &request_meta, !need || buffered)?;
        if need && !buffered {
            log::warn!("HTTP response body exceeds rewrite budget; passing through");
        }
        for spec in scripts.iter().filter(|s| (!s.requires_body || buffered)
            && !(s.dialect == oryn_module::ModuleFormat::Loon && body_rewritten)) {
            if let Err(e) = self
                .scripts
                .execute(spec, &request_meta, Some(&mut msg), self.outbound.clone())
                .await
            {
                if e.kind() == io::ErrorKind::ConnectionAborted {
                    return Err(e);
                }
                log::warn!("HTTP response script {} skipped: {e}", spec.name);
            }
        }
        let body = if buffered {
            full_trailers(std::mem::take(&mut msg.body), response_trailers)
        } else {
            passthrough_body.expect("unbuffered response must have passthrough body")
        };
        let mut response = response_from_message(msg, body, false, Some(&parts.headers))?;
        if !downstream_h2 {
            if let Some(names) = response_trailer_names {
                response.headers_mut().insert("trailer", names);
            }
        }
        if (h2 || response.headers().contains_key("trailer"))
            && !downstream_h2
            && request_meta.method != "HEAD"
            && !matches!(response.status().as_u16(), 204 | 304)
        {
            // h2 的 trailers 要在 HTTP/1.1 中通过 chunked 发送，不能同时保留 Content-Length。
            response.headers_mut().remove("content-length");
            response.headers_mut().insert(
                "transfer-encoding",
                http::HeaderValue::from_static("chunked"),
            );
        }
        // driver 在 response 被消费或取消之前存活，取消请求不会遗留后台连接。
        let body = std::mem::replace(response.body_mut(), full(vec![]));
        *response.body_mut() = DrivenBody::new(body, Some(driver), _transaction, permit).boxed_unsync();
        Ok(response)
    }
    fn local_response(
        &self,
        message: Message,
        transaction: Option<OwnedSemaphorePermit>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> io::Result<Response<BoxBody>> {
        let need_pages = u32::try_from(body_budget_pages(message.body.len())).unwrap_or(u32::MAX);
        let permit = match permit {
            Some(mut p) => {
                if p.num_permits() < need_pages as usize {
                    let extra = need_pages - p.num_permits() as u32;
                    let Ok(more) = self.bodies.clone().try_acquire_many_owned(extra) else {
                        return Ok(error_response(503));
                    };
                    p.merge(more);
                }
                p
            }
            None => match self.bodies.clone().try_acquire_many_owned(need_pages) {
                Ok(p) => p,
                Err(_) => return Ok(error_response(503)),
            },
        };
        let mut response = response_from_message(message, full(vec![]), true, None)?;
        let body = std::mem::replace(response.body_mut(), full(vec![]));
        *response.body_mut() = DrivenBody::new(body, None, transaction, Some(permit)).boxed_unsync();
        Ok(response)
    }
}
fn error_response(code: u16) -> Response<BoxBody> {
    Response::builder().status(code).body(full(vec![])).unwrap()
}
fn full_trailers(data: Vec<u8>, trailers: Option<http::HeaderMap>) -> BoxBody {
    Full::new(Bytes::from(data))
        .map_err(|e: Infallible| match e {})
        .with_trailers(std::future::ready(trailers.map(Ok)))
        .boxed_unsync()
}
fn trailer_names(trailers: Option<&http::HeaderMap>) -> Option<http::HeaderValue> {
    let names = trailers?
        .keys()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if names.is_empty() {
        None
    } else {
        names.parse().ok()
    }
}
fn full(data: Vec<u8>) -> BoxBody {
    Full::new(Bytes::from(data))
        .map_err(|e: Infallible| match e {})
        .boxed_unsync()
}
fn response_from_message(
    m: Message,
    body: BoxBody,
    local: bool,
    original: Option<&http::HeaderMap>,
) -> io::Result<Response<BoxBody>> {
    let mut r = Response::builder()
        .status(m.status.unwrap_or(200))
        .body(if local { full(m.body) } else { body })
        .map_err(err)?;
    *r.headers_mut() = headers_with(&m.headers, original)?;
    strip_hop(r.headers_mut());
    Ok(r)
}
fn header_pairs(h: &http::HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().into(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}
/// 规则与脚本只看到 UTF-8 文本；原值不是合法 UTF-8 且未被改写时，转发原始字节，
/// 不把 `from_utf8_lossy` 的替换字符写回线上。
fn headers_with(
    h: &[(String, String)],
    original: Option<&http::HeaderMap>,
) -> io::Result<http::HeaderMap> {
    let mut out = http::HeaderMap::new();
    for (k, v) in h {
        let name = http::header::HeaderName::from_bytes(k.as_bytes()).map_err(err)?;
        let raw = original.and_then(|o| {
            o.get_all(&name)
                .iter()
                .find(|ov| {
                    std::str::from_utf8(ov.as_bytes()).is_err()
                        && String::from_utf8_lossy(ov.as_bytes()) == v.as_str()
                })
                .cloned()
        });
        let value = match raw {
            Some(raw) => raw,
            None => v.parse::<http::HeaderValue>().map_err(err)?,
        };
        out.append(name, value);
    }
    Ok(out)
}
fn strip_hop(h: &mut http::HeaderMap) {
    if let Some(v) = h
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        for n in v.split(',') {
            h.remove(n.trim());
        }
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "proxy-authenticate",
        "proxy-authorization",
    ] {
        h.remove(name);
    }
    if h.get("te").is_some_and(|v| v != "trailers") {
        h.remove("te");
    }
}
async fn buffer_if_needed(
    mut body: Incoming,
    need: bool,
    budget: Arc<Semaphore>,
    max_body: usize,
) -> io::Result<(
    Option<BoxBody>,
    Option<Vec<u8>>,
    Option<OwnedSemaphorePermit>,
    Option<http::HeaderMap>,
)> {
    if !need {
        return Ok((Some(body.map_err(err).boxed_unsync()), None, None, None));
    }
    let Ok(Ok(mut permit)) =
        tokio::time::timeout(crate::admission::patience(3), budget.clone().acquire_many_owned(1))
            .await
    else {
        return Ok((Some(body.map_err(err).boxed_unsync()), None, None, None));
    };
    let mut covered_pages = 1usize;
    let mut first: Option<Bytes> = None;
    let mut buf: Vec<u8> = Vec::new();
    let mut n = 0usize;
    let mut trailers = None;
    // 每帧之间最多等 5 秒，整体最多 30 秒：慢速但持续的上传不会因总时长被判为超时。
    let total = tokio::time::Instant::now() + Duration::from_secs(30);
    let make_prefix = |first: Option<Bytes>, buf: Vec<u8>, extra: Option<Frame<Bytes>>| {
        let mut prefix = VecDeque::new();
        if let Some(b) = first {
            if !b.is_empty() {
                prefix.push_back(Frame::data(b));
            }
        } else if !buf.is_empty() {
            prefix.push_back(Frame::data(Bytes::from(buf)));
        }
        if let Some(f) = extra {
            prefix.push_back(f);
        }
        prefix
    };
    loop {
        let deadline = (tokio::time::Instant::now() + Duration::from_secs(5)).min(total);
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(frame)) => frame.map_err(err)?,
            Ok(None) => break,
            Err(_) => {
                return Ok((
                    Some(
                        ReplayBody {
                            prefix: make_prefix(first, buf, None),
                            inner: body,
                            permit: Some(permit),
                        }
                        .boxed_unsync(),
                    ),
                    None,
                    None,
                    None,
                ))
            }
        };
        if frame.is_data() {
            let chunk_len = frame.data_ref().map_or(0, |d| d.len());
            let next_n = n.saturating_add(chunk_len);
            if next_n > max_body {
                return Ok((
                    Some(
                        ReplayBody {
                            prefix: make_prefix(first, buf, Some(frame)),
                            inner: body,
                            permit: Some(permit),
                        }
                        .boxed_unsync(),
                    ),
                    None,
                    None,
                    None,
                ));
            }
            let target_pages = body_budget_pages(next_n);
            if target_pages > covered_pages {
                let extra = u32::try_from(target_pages - covered_pages).unwrap_or(u32::MAX);
                match tokio::time::timeout(
                    crate::admission::patience(2),
                    budget.clone().acquire_many_owned(extra),
                )
                .await
                {
                    Ok(Ok(more)) => {
                        permit.merge(more);
                        covered_pages = target_pages;
                    }
                    _ => {
                        return Ok((
                            Some(
                                ReplayBody {
                                    prefix: make_prefix(first, buf, Some(frame)),
                                    inner: body,
                                    permit: Some(permit),
                                }
                                .boxed_unsync(),
                            ),
                            None,
                            None,
                            None,
                        ))
                    }
                }
            }
            let bytes = frame.into_data().expect("is_data");
            if !bytes.is_empty() {
                if first.is_none() && buf.is_empty() {
                    first = Some(bytes);
                } else {
                    if let Some(b) = first.take() {
                        buf = Vec::from(b);
                    }
                    let new_len = buf.len() + bytes.len();
                    if new_len > buf.capacity() {
                        let target = (buf.capacity().saturating_mul(2))
                            .max(new_len)
                            .min(max_body);
                        buf.reserve_exact(target - buf.len());
                    }
                    buf.extend_from_slice(&bytes);
                }
            }
            n = next_n;
        } else if let Some(h) = frame.trailers_ref() {
            trailers = Some(h.clone());
        }
    }
    let data = if let Some(b) = first {
        Vec::from(b)
    } else {
        buf
    };
    Ok((None, Some(data), Some(permit), trailers))
}
struct GuardedBody {
    inner: BoxBody,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Body for GuardedBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
struct ReplayBody {
    prefix: VecDeque<Frame<Bytes>>,
    inner: Incoming,
    permit: Option<OwnedSemaphorePermit>,
}
impl Body for ReplayBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if let Some(f) = self.prefix.pop_front() {
            return Poll::Ready(Some(Ok(f)));
        }
        self.permit.take();
        Pin::new(&mut self.inner)
            .poll_frame(cx)
            .map(|f| f.map(|r| r.map_err(err)))
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// 客户端停止读取响应正文多久后释放事务 / 正文配额并断开上游。
const BODY_STALL: Duration = Duration::from_secs(60);
/// 正文转发期间持有的资源；客户端长时间不读取时由看门狗提前释放。
struct BodyHold {
    driver: Option<Driver>,
    transaction: Option<OwnedSemaphorePermit>,
    body: Option<OwnedSemaphorePermit>,
}
struct BodyWatch {
    /// 上次把一帧交给客户端的时间。
    last: std::sync::Mutex<std::time::Instant>,
    /// 正在等待上游数据（返回了 Pending）：这时没有数据可写，不算客户端停读。
    waiting: std::sync::atomic::AtomicBool,
    expired: std::sync::atomic::AtomicBool,
    hold: std::sync::Mutex<BodyHold>,
}
struct DrivenBody {
    inner: BoxBody,
    watch: Arc<BodyWatch>,
}
impl DrivenBody {
    fn new(
        inner: BoxBody,
        driver: Option<Driver>,
        transaction: Option<OwnedSemaphorePermit>,
        body: Option<OwnedSemaphorePermit>,
    ) -> Self {
        let watch = Arc::new(BodyWatch {
            last: std::sync::Mutex::new(std::time::Instant::now()),
            waiting: std::sync::atomic::AtomicBool::new(false),
            expired: std::sync::atomic::AtomicBool::new(false),
            hold: std::sync::Mutex::new(BodyHold {
                driver,
                transaction,
                body,
            }),
        });
        let w = Arc::downgrade(&watch);
        tokio::task::spawn_local(async move {
            loop {
                tokio::time::sleep(BODY_STALL / 6).await;
                let Some(watch) = w.upgrade() else { break };
                let stalled = !watch.waiting.load(std::sync::atomic::Ordering::Relaxed)
                    && watch.last.lock().unwrap().elapsed() >= BODY_STALL;
                if stalled {
                    watch.expired.store(true, std::sync::atomic::Ordering::Relaxed);
                    let mut hold = watch.hold.lock().unwrap();
                    hold.driver = None;
                    hold.transaction = None;
                    hold.body = None;
                    log::debug!("HTTP response body stalled by client; resources released");
                    break;
                }
            }
        });
        Self { inner, watch }
    }
}
impl Drop for DrivenBody {
    fn drop(&mut self) {
        let mut hold = self.watch.hold.lock().unwrap();
        hold.driver = None;
        hold.transaction = None;
        hold.body = None;
    }
}
impl Body for DrivenBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        use std::sync::atomic::Ordering::Relaxed;
        if self.watch.expired.load(Relaxed) {
            return Poll::Ready(Some(Err(err("response body stalled by client"))));
        }
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        let pending = poll.is_pending();
        self.watch.waiting.store(pending, Relaxed);
        if !pending {
            *self.watch.last.lock().unwrap() = std::time::Instant::now();
        }
        poll
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
/// 首包回放不额外拨出本地 Socket；读写计数覆盖 TLS 与 HTTP/2 线格式。
pub struct FlowIo<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
    conn: Rc<ConnGuard>,
    stats: Arc<Stats>,
}
impl<S> FlowIo<S> {
    pub fn new(prefix: Vec<u8>, inner: S, conn: Rc<ConnGuard>, stats: Arc<Stats>) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
            conn,
            stats,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for FlowIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = if (self.prefix.position() as usize) < self.prefix.get_ref().len() {
            Pin::new(&mut self.prefix).poll_read(cx, buf)
        } else {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        };
        if let Poll::Ready(Ok(())) = &poll {
            let n = (buf.filled().len() - before) as u64;
            self.conn.add_up(n);
            self.stats.add_up(n);
        }
        poll
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for FlowIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let p = Pin::new(&mut self.inner).poll_write(cx, b);
        if let Poll::Ready(Ok(n)) = p {
            self.conn.add_down(n as u64);
            self.stats.add_down(n as u64);
        }
        p
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Peer(std::net::SocketAddr);
    #[async_trait::async_trait]
    impl Outbound for Peer {
        fn tag(&self) -> &str {
            "test"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<oryn_outbound::BoxStream> {
            Ok(Box::new(tokio::net::TcpStream::connect(self.0).await?))
        }
        async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn oryn_outbound::PacketConn>> {
            Err(err("no UDP"))
        }
    }
    /// 已建立入口的 h2 扇出共用独立的 8 个上游建立额度，满载立即 503。
    #[tokio::test(flavor = "current_thread")]
    async fn h2_slow_tls_upstream_fanout_after_entry_established() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        #[derive(Default)]
        struct Counts {
            dialed: AtomicUsize,
            active: AtomicUsize,
            peak: AtomicUsize,
            hellos: AtomicUsize,
            cancelled: AtomicUsize,
        }
        struct SlowTls(Arc<Counts>);
        #[async_trait::async_trait]
        impl Outbound for SlowTls {
            fn tag(&self) -> &str { "slow-tls-test" }
            fn kind(&self) -> &'static str { "test" }
            async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<oryn_outbound::BoxStream> {
                let (stream, mut peer) = tokio::io::duplex(8192);
                let counts = self.0.clone();
                counts.dialed.fetch_add(1, SeqCst);
                let active = counts.active.fetch_add(1, SeqCst) + 1;
                counts.peak.fetch_max(active, SeqCst);
                tokio::spawn(async move {
                    // 接收真实 rustls ClientHello，但不发送任何 TLS 字节。
                    let mut header = [0; 5];
                    peer.read_exact(&mut header).await.unwrap();
                    assert_eq!(header[0], 22);
                    let mut record = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
                    peer.read_exact(&mut record).await.unwrap();
                    assert_eq!(record[0], 1);
                    counts.hellos.fetch_add(1, SeqCst);
                    let mut buffer = [0; 4096];
                    while peer.read(&mut buffer).await.unwrap() != 0 {}
                    counts.active.fetch_sub(1, SeqCst);
                    counts.cancelled.fetch_add(1, SeqCst);
                });
                Ok(Box::new(stream))
            }
            async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn oryn_outbound::PacketConn>> {
                Err(err("no UDP"))
            }
        }
        tokio::task::LocalSet::new().run_until(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let counts = Arc::new(Counts::default());
                let transactions = Arc::new(Semaphore::new(32));
                let upstream_establish = Arc::new(Semaphore::new(8));
                let ir = oryn_module::parse("[Rewrite]\nrequest if ${url} ~= /never-match/ then request.header.set(\"X-Test\", \"yes\")", Some(oryn_module::ModuleFormat::Loon)).unwrap();
                let inspector = Inspector {
                    scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
                    plan: Rc::new(oryn_http_inspect::compile_module(&ir, &Default::default(), &Default::default()).unwrap()),
                    outbound: Arc::new(SlowTls(counts.clone())),
                    origin: "https://fixture.test".into(), skip_verify: true,
                    transactions: Some(transactions.clone()),
                    bodies: Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
                    upstream_establish: upstream_establish.clone(),
                    max_body: oryn_http_inspect::MAX_BODY,
                };
                let admission = crate::admission::Admission::default();
                let entries: Vec<_> = (0..8).map(|_| admission.try_tcp().unwrap()).collect();
                assert!(admission.try_tcp().is_none());
                let mut clients = Vec::new();
                let mut drivers = Vec::new();
                let mut servers = Vec::new();
                let mut requests = Vec::new();
                for entry in entries {
                    let (app, server) = tokio::io::duplex(65536);
                    let inspector = inspector.clone();
                    let (established, ready) = tokio::sync::oneshot::channel();
                    servers.push(tokio::task::spawn_local(async move {
                        // 与生产进入 inspection 的边界一致；不模拟入口 TLS/嗅探。
                        entry.phase().complete();
                        established.send(()).unwrap();
                        entry.run(inspector.serve(server, true)).await
                    }));
                    let (client, driver) = hyper::client::conn::http2::handshake(LocalExecutor, TokioIo::new(app)).await.unwrap();
                    clients.push(client);
                    drivers.push(tokio::task::spawn_local(driver));
                    ready.await.unwrap();
                }
                // 原 8 条 active 仍存活，但全部 establish 已释放。
                let spare: Vec<_> = (0..8).map(|_| admission.try_tcp().unwrap()).collect();
                assert!(admission.try_tcp().is_none());
                drop(spare);
                for client in &mut clients {
                    for _ in 0..4 {
                        let response = client.send_request(Request::builder().uri("https://fixture.test/slow").body(full(vec![])).unwrap());
                        requests.push(tokio::task::spawn_local(response));
                    }
                }
                while counts.hellos.load(SeqCst) != 8 || requests.iter().filter(|r| r.is_finished()).count() != 24 { tokio::task::yield_now().await; }
                let mut pending = Vec::new();
                for request in requests {
                    if request.is_finished() {
                        assert_eq!(request.await.unwrap().unwrap().status(), 503);
                    } else {
                        pending.push(request);
                    }
                }
                let requests = pending;
                assert_eq!(counts.active.load(SeqCst), 8);
                assert_eq!(counts.peak.load(SeqCst), 8);
                assert_eq!(transactions.available_permits(), 24);
                assert_eq!(upstream_establish.available_permits(), 0);
                let rejected = clients[0].send_request(Request::builder().uri("https://fixture.test/overflow").body(full(vec![])).unwrap()).await.unwrap();
                assert_eq!(rejected.status(), 503);
                drop(rejected);
                assert_eq!(counts.dialed.load(SeqCst), 8);
                // 应用侧关闭连接；不得通过 abort Inspector/上游任务伪造资源回收。
                drop(clients);
                for request in requests { request.abort(); let _ = request.await; }
                for driver in drivers { driver.abort(); let _ = driver.await; }
                for server in servers { let _ = server.await.unwrap(); }
                while counts.cancelled.load(SeqCst) != 8 { tokio::task::yield_now().await; }
                assert_eq!(upstream_establish.available_permits(), 8);
                assert_eq!(counts.active.load(SeqCst), 0);
                assert_eq!(transactions.available_permits(), 32);
                let restored: Vec<_> = (0..64).map(|_| {
                    let entry = admission.try_tcp().unwrap();
                    entry.phase().complete();
                    entry
                }).collect();
                assert!(admission.try_tcp().is_none());
                drop(restored);
                eprintln!("h2 slow TLS: dialed/peak=8; overflow=503; application drop restores upstream=8 transactions=32 entries=64");
            }).await.expect("h2 fanout or application-drop cleanup timed out");
        }).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upstream_establish_released_before_pending_response() {
        tokio::task::LocalSet::new().run_until(async {
            tokio::time::timeout(Duration::from_secs(10), async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let (seen, mut received) = tokio::sync::mpsc::channel(32);
                let peer = tokio::task::spawn_local(async move {
                    loop {
                        let (stream, _) = listener.accept().await.unwrap();
                        let seen = seen.clone();
                        tokio::task::spawn_local(async move {
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(
                                TokioIo::new(stream), service_fn(move |_req| {
                                    let seen = seen.clone();
                                    async move {
                                        seen.send(()).await.unwrap();
                                        std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
                                    }
                                })).await;
                        });
                    }
                });
                let upstream_establish = Arc::new(Semaphore::new(8));
                let transactions = Arc::new(Semaphore::new(32));
                let ir = oryn_module::parse("[Rewrite]\nrequest if ${url} ~= /never-match/ then request.header.set(\"X-Test\", \"yes\")", Some(oryn_module::ModuleFormat::Loon)).unwrap();
                let inspector = Inspector {
                    scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
                    plan: Rc::new(oryn_http_inspect::compile_module(&ir, &Default::default(), &Default::default()).unwrap()),
                    outbound: Arc::new(Peer(addr)), origin: "http://fixture.test".into(), skip_verify: false,
                    transactions: Some(transactions.clone()), upstream_establish: upstream_establish.clone(),
                    bodies: Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
                    max_body: oryn_http_inspect::MAX_BODY,
                };
                let mut servers = Vec::new();
                let mut drivers = Vec::new();
                let mut clients = Vec::new();
                let mut requests = Vec::new();
                // 逐个确认 HTTP 握手完成、响应仍 Pending；可超过 8，但事务上限仍是 32。
                for _ in 0..3 {
                    let (app, server) = tokio::io::duplex(65536);
                    servers.push(tokio::task::spawn_local(inspector.clone().serve(server, true)));
                    let (mut client, driver) = hyper::client::conn::http2::handshake(LocalExecutor, TokioIo::new(app)).await.unwrap();
                    drivers.push(tokio::task::spawn_local(driver));
                    for _ in 0..if clients.len() < 2 { 16 } else { 0 } {
                        requests.push(tokio::task::spawn_local(client.send_request(Request::builder()
                            .uri("http://fixture.test/pending").body(full(vec![])).unwrap())));
                        received.recv().await.unwrap();
                        assert_eq!(upstream_establish.available_permits(), 8);
                    }
                    clients.push(client);
                }
                assert!(requests.iter().all(|r| !r.is_finished()));
                assert_eq!(transactions.available_permits(), 0);
                let rejected = clients[2].send_request(Request::builder().uri("http://fixture.test/overflow")
                    .body(full(vec![])).unwrap()).await.unwrap();
                assert_eq!(rejected.status(), 503);
                drop(rejected);
                drop(clients);
                for request in requests { request.abort(); let _ = request.await; }
                for driver in drivers { driver.abort(); let _ = driver.await; }
                for server in servers { let _ = server.await.unwrap(); }
                assert_eq!(transactions.available_permits(), 32);
                assert_eq!(upstream_establish.available_permits(), 8);
                peer.abort();
            }).await.expect("pending response test timed out");
        }).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scripts_select_after_request_rewrite_with_full_body() {
        tokio::task::LocalSet::new().run_until(async {
            let module = r#"[Rewrite]
request if ${url} ~= /fixture/ then request.header.add("X-Once", "yes") | request.header.set("X-Select", "new")
[Script]
request if ${request.header['X-Select']} == "old" then script("old.js")
request if ${request.header['X-Select']} == "new" then script("new.js") with requires_body=true
"#;
            let ir = oryn_module::parse(module, Some(oryn_module::ModuleFormat::Loon)).unwrap();
            let resources = [
                ("old.js".into(), b"$done({response:{status:500,body:'wrong'}});".as_slice().into()),
                ("new.js".into(), b"$done({response:{status:200,body:$request.body+'|'+$request.headers['X-Once']}});".as_slice().into()),
            ].into();
            let plan = oryn_http_inspect::compile_module(&ir, &Default::default(), &resources).unwrap();
            let inspector = Inspector {
                scripts: Arc::new(crate::scripts::ScriptHost::new(None)), plan: Rc::new(plan),
                outbound: Arc::new(Peer("127.0.0.1:1".parse().unwrap())),
                origin:"http://fixture.test".into(), skip_verify:false,
                transactions:Some(Arc::new(Semaphore::new(32))),
                bodies:Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
                upstream_establish: Arc::new(Semaphore::new(8)),
                max_body: oryn_http_inspect::MAX_BODY,
            };
            let (app, server) = tokio::io::duplex(65536);
            let serving = tokio::task::spawn_local(inspector.serve(server, false));
            let (mut client, driver) = hyper::client::conn::http1::handshake(TokioIo::new(app)).await.unwrap();
            let driving = tokio::task::spawn_local(driver);
            let response = client.send_request(Request::builder().method("POST").uri("http://fixture.test/api")
                .header("X-Select", "old").body(full(b"nonempty-body".to_vec())).unwrap()).await.unwrap();
            assert_eq!(response.status(),200);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), "nonempty-body|yes");
            drop(client); driving.abort(); serving.abort();
        }).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unrelated_upload_streams_and_response_selection_is_original() {
        tokio::task::LocalSet::new().run_until(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr=listener.local_addr().unwrap();
            let peer=tokio::task::spawn_local(async move {
                let (socket,_) = listener.accept().await.unwrap();
                let service=service_fn(|req:Request<Incoming>| async move {
                    let b=req.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(b.len(), oryn_http_inspect::MAX_BODY+1);
                    Ok::<_,Infallible>(Response::builder().header("X-State","old")
                        .body(full(b"original-body".to_vec())).unwrap())
                });
                let _=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket),service).await;
            });
            let ir=oryn_module::parse(r#"[Rewrite]
request if ${url} ~= /a\.example/ then request.header.set("X", "yes")
request if ${url} ~= /b\.example/ then request.json.replace("value", 2)
response if ${url} ~= /fixture/ then response.header.set("X-State", "new")
[Script]
response if ${url} ~= /fixture/ && ${response.header['X-State']} == "old" then script("old.js") with requires_body=true
response if ${url} ~= /fixture/ && ${response.header['X-State']} == "new" then script("new.js") with requires_body=true
"#,Some(oryn_module::ModuleFormat::Loon)).unwrap();
            let resources=[("old.js".into(),b"$done({body:$response.body+'|'+$response.headers['X-State']});".as_slice().into()),
                ("new.js".into(),b"$done({body:'wrong'});".as_slice().into())].into();
            let plan=oryn_http_inspect::compile_module(&ir,&Default::default(),&resources).unwrap();
            let inspector=Inspector { scripts:Arc::new(crate::scripts::ScriptHost::new(None)),plan:Rc::new(plan),outbound:Arc::new(Peer(addr)),origin:"http://fixture.test".into(),skip_verify:false,transactions:Some(Arc::new(Semaphore::new(32))),bodies:Arc::new(Semaphore::new(body_budget_pages(6*1024*1024))),upstream_establish:Arc::new(Semaphore::new(8)),max_body:oryn_http_inspect::MAX_BODY };
            let (app,server)=tokio::io::duplex(65536);
            let serving=tokio::task::spawn_local(inspector.serve(server,false));
            let (mut client,driver)=hyper::client::conn::http1::handshake(TokioIo::new(app)).await.unwrap();
            let driving=tokio::task::spawn_local(driver);
            let response=client.send_request(Request::builder().method("POST").uri("http://fixture.test/api")
                .body(full(vec![b'x';oryn_http_inspect::MAX_BODY+1])).unwrap()).await.unwrap();
            assert_eq!(response.status(),200);
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(),"original-body|new");
            drop(client); driving.abort(); serving.abort(); peer.abort();
        }).await;
    }

    async fn fixture(h2: bool, upstream_h2: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut upstream_ca =
            oryn_mitm::CertificateAuthority::generate("Upstream fixture CA").unwrap();
        let upstream_tls = upstream_ca.server_config("fixture.test", true).unwrap();
        let peer = tokio::task::spawn_local(async move {
            let mut tasks = vec![];
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                if upstream_h2 {
                    let tls = tokio_rustls::TlsAcceptor::from(upstream_tls.clone())
                        .accept(s)
                        .await
                        .unwrap();
                    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                    tasks.push(tokio::task::spawn_local(async move {
                        let service = service_fn(|_req: Request<Incoming>| async {
                            let mut trailers = http::HeaderMap::new();
                            trailers.insert(
                                "x-fixture-trailer",
                                http::HeaderValue::from_static("kept"),
                            );
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("Content-Type", "application/json")
                                    .body(full_trailers(
                                        br#"{"ad":true,"ok":1}"#.to_vec(),
                                        Some(trailers),
                                    ))
                                    .unwrap(),
                            )
                        });
                        let _ = hyper::server::conn::http2::Builder::new(LocalExecutor)
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    }));
                } else {
                    let mut header = vec![];
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(s.read_u8().await.unwrap());
                        assert!(header.len() < 32768);
                    }
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n12\r\n{\"ad\":true,\"ok\":1}\r\n0\r\n\r\n").await.unwrap();
                }
            }
            for task in tasks {
                let _ = task.await;
            }
        });
        let ir = oryn_module::parse(
            "[Body Rewrite]\nhttp-response-jq ^https?://fixture.test/ 'del(.ad)'",
            None,
        )
        .unwrap();
        let plan = oryn_http_inspect::compile_module(&ir, &Default::default(), &Default::default())
            .unwrap();
        let inspector = Inspector {
            scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
            plan: Rc::new(plan),
            outbound: Arc::new(Peer(addr)),
            origin: if upstream_h2 {
                "https://fixture.test".into()
            } else {
                "http://fixture.test".into()
            },
            skip_verify: upstream_h2, // 测试上游是独立自签 CA；产品默认严格验证。
            transactions: Some(Arc::new(Semaphore::new(32))),
            upstream_establish: Arc::new(Semaphore::new(8)),
            bodies: Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
            max_body: oryn_http_inspect::MAX_BODY,
        };
        let (app, local) = tokio::io::duplex(65536);
        let mut ca = oryn_mitm::CertificateAuthority::generate("Oryn Test CA").unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                ca.material().certificate_der.clone(),
            ))
            .unwrap();
        let server = ca.server_config("fixture.test", h2).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(oryn_tls::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let server_task = tokio::task::spawn_local(async move {
            let tls = tokio_rustls::TlsAcceptor::from(server)
                .accept(local)
                .await
                .unwrap();
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(if h2 {
                    b"h2".as_slice()
                } else {
                    b"http/1.1".as_slice()
                })
            );
            inspector.serve(tls, h2).await.unwrap();
        });
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
            .connect(oryn_tls::server_name("fixture.test").unwrap(), app)
            .await
            .unwrap();
        if h2 {
            let (mut tx, c) =
                hyper::client::conn::http2::handshake(LocalExecutor, TokioIo::new(tls))
                    .await
                    .unwrap();
            let driver = tokio::task::spawn_local(async move {
                let _ = c.await;
            });
            let a = tx.send_request(
                Request::builder()
                    .uri("https://fixture.test/a")
                    .body(full(vec![]))
                    .unwrap(),
            );
            let b = tx.send_request(
                Request::builder()
                    .uri("https://fixture.test/b")
                    .body(full(vec![]))
                    .unwrap(),
            );
            let (a, b) = tokio::join!(a, b);
            for response in [a, b] {
                let r = response.unwrap();
                assert_eq!(r.version(), Version::HTTP_2);
                let collected = r.into_body().collect().await.unwrap();
                assert_eq!(
                    collected
                        .trailers()
                        .and_then(|h| h.get("x-fixture-trailer"))
                        .and_then(|v| v.to_str().ok()),
                    Some("kept")
                );
                assert_eq!(collected.to_bytes(), Bytes::from_static(br#"{"ok":1}"#));
            }
            drop(tx);
            driver.abort();
            let _ = driver.await;
        } else {
            let (mut tx, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .unwrap();
            let driver = tokio::task::spawn_local(async move {
                let _ = c.await;
            });
            for p in ["/a", "/b"] {
                tx.ready().await.unwrap();
                let r = tx
                    .send_request(
                        Request::builder()
                            .uri(p)
                            .header("host", "fixture.test")
                            .header("te", "trailers")
                            .body(full(vec![]))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let collected = r.into_body().collect().await.unwrap();
                if upstream_h2 {
                    assert_eq!(
                        collected
                            .trailers()
                            .and_then(|h| h.get("x-fixture-trailer"))
                            .and_then(|v| v.to_str().ok()),
                        Some("kept")
                    );
                }
                assert_eq!(collected.to_bytes(), Bytes::from_static(br#"{"ok":1}"#));
            }
            drop(tx);
            driver.abort();
            let _ = driver.await;
        }
        peer.await.unwrap();
        server_task.abort();
        let _ = server_task.await;
    }
    #[tokio::test]
    async fn tls_http1_rewrites_chunked_and_keepalive() {
        tokio::task::LocalSet::new()
            .run_until(async {
                tokio::time::timeout(Duration::from_secs(10), fixture(false, false))
                    .await
                    .unwrap()
            })
            .await;
    }
    #[tokio::test]
    async fn tls_http1_client_to_http2_upstream() {
        tokio::task::LocalSet::new()
            .run_until(async {
                tokio::time::timeout(Duration::from_secs(10), fixture(false, true))
                    .await
                    .unwrap()
            })
            .await;
    }
    #[tokio::test]
    async fn tls_http2_concurrent_streams_rewrite() {
        tokio::task::LocalSet::new()
            .run_until(async {
                tokio::time::timeout(Duration::from_secs(10), fixture(true, true))
                    .await
                    .unwrap()
            })
            .await;
    }

    /// 请求脚本点名的出口必须真正拨出去，策略头不能出现在上游请求里。
    #[tokio::test(flavor = "current_thread")]
    async fn script_policy_dials_the_named_outbound() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        tokio::task::LocalSet::new()
            .run_until(async {
                tokio::time::timeout(Duration::from_secs(10), async {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let policy_hits = Arc::new(AtomicUsize::new(0));
                    let direct_hits = Arc::new(AtomicUsize::new(0));
                    tokio::task::spawn_local(async move {
                        let (mut sock, _) = listener.accept().await.unwrap();
                        let mut buf = [0u8; 2048];
                        let n = sock.read(&mut buf).await.unwrap();
                        let text = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                        assert!(!text.contains("x-surge-policy"), "{text}");
                        assert!(text.starts_with("get /play "), "{text}");
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                            .await;
                    });
                    struct Marked {
                        tag: &'static str,
                        addr: Option<std::net::SocketAddr>,
                        hits: Arc<AtomicUsize>,
                    }
                    #[async_trait::async_trait]
                    impl Outbound for Marked {
                        fn tag(&self) -> &str {
                            self.tag
                        }
                        fn kind(&self) -> &'static str {
                            "test"
                        }
                        async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<oryn_outbound::BoxStream> {
                            self.hits.fetch_add(1, SeqCst);
                            let Some(addr) = self.addr else {
                                return Err(io::Error::other("original outbound was dialed"));
                            };
                            Ok(Box::new(tokio::net::TcpStream::connect(addr).await?))
                        }
                        async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn oryn_outbound::PacketConn>> {
                            Err(io::Error::other("no udp"))
                        }
                    }
                    let config = oryn_config::parse_config("rules: ['MATCH,DIRECT']").unwrap();
                    let sets = Arc::new(oryn_router::RuleSetStore::new(&[]));
                    let router = oryn_router::Router::new(&config, sets.clone(), Arc::new(oryn_router::GeoIp::default()));
                    let dns = Arc::new(oryn_dns::DnsEngine::new(config.dns.clone(), vec![], sets));
                    let routing = Arc::new(oryn_dns::Routing {
                        router,
                        outbounds: vec![
                            Arc::new(Marked { tag: "DIRECT", addr: None, hits: direct_hits.clone() }) as Arc<dyn Outbound>,
                            Arc::new(Marked { tag: "HK", addr: Some(addr), hits: policy_hits.clone() }),
                        ],
                    });
                    let scripts = Arc::new(crate::scripts::ScriptHost::new(None));
                    scripts.set_network(routing, dns);
                    let ir = oryn_module::parse(
                        "[Script]\npick = type=http-request, pattern=^http://example\\.test/, ability=http-client-policy, script-path=p.js\n",
                        Some(oryn_module::ModuleFormat::Surge),
                    )
                    .unwrap();
                    let mut resources = oryn_module::Resources::new();
                    resources.insert(
                        "p.js".into(),
                        std::sync::Arc::<[u8]>::from(
                            &b"$done({policy:'HK', headers:{Host:'example.test','X-Surge-Policy':'HK'}});"[..],
                        ),
                    );
                    let plan = oryn_http_inspect::compile_module(&ir, &Default::default(), &resources).unwrap();
                    assert!(plan.warnings.iter().all(|w| !w.contains("skipped")), "{:?}", plan.warnings);
                    let inspector = Inspector {
                        scripts,
                        plan: Rc::new(plan),
                        outbound: Arc::new(Marked { tag: "DIRECT", addr: None, hits: direct_hits.clone() }),
                        origin: "http://example.test".into(),
                        skip_verify: false,
                        transactions: Some(Arc::new(Semaphore::new(4))),
                        upstream_establish: Arc::new(Semaphore::new(4)),
                        bodies: Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
                        max_body: oryn_http_inspect::MAX_BODY,
                    };
                    let (mut client, server) = tokio::io::duplex(8192);
                    let serve = tokio::task::spawn_local(async move {
                        let result = inspector.serve(server, false).await;
                        result
                    });
                    client
                        .write_all(b"GET /play HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                    let mut response = vec![0u8; 512];
                    let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut response))
                        .await
                        .expect("no HTTP response")
                        .unwrap();
                    let text = String::from_utf8_lossy(&response[..n]);
                    assert!(text.contains("200"), "{text}");
                    assert!(text.contains("ok"), "{text}");
                    assert_eq!(policy_hits.load(SeqCst), 1, "named outbound was not dialed");
                    assert_eq!(direct_hits.load(SeqCst), 0, "original outbound was dialed");
                    drop(client);
                    let _ = serve.await;
                })
                .await
                .unwrap();
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn four_mib_text_and_binary_response_scripts_succeed() {
        tokio::task::LocalSet::new().run_until(async {
            for binary in [false, true] {
                let payload = if binary {
                    vec![0x5au8; oryn_http_inspect::MAX_BODY]
                } else {
                    vec![b'a'; oryn_http_inspect::MAX_BODY]
                };
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let upstream_body = payload.clone();
                let peer = tokio::task::spawn_local(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let service = service_fn(move |_req: Request<Incoming>| {
                        let body = upstream_body.clone();
                        async move {
                            Ok::<_, Infallible>(Response::builder().body(full(body)).unwrap())
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
                let module = if binary {
                    "[Script]\ntransform = type=http-response, pattern=^http://fixture\\.test/big$, script-path=s.js, requires-body=true, binary-body-mode=true"
                } else {
                    "[Script]\ntransform = type=http-response, pattern=^http://fixture\\.test/big$, script-path=s.js, requires-body=true"
                };
                let ir = oryn_module::parse(module, Some(oryn_module::ModuleFormat::Surge)).unwrap();
                let script_code: &[u8] = if binary {
                    b"let b = new Uint8Array($response.body); b[0] = 0xa5; $done({body: b});"
                } else {
                    b"let s = $response.body; $done({body: 'Z' + s.slice(1)});"
                };
                let resources = [("s.js".into(), script_code.into())].into();
                let plan = oryn_http_inspect::compile_module(&ir, &Default::default(), &resources).unwrap();
                let inspector = Inspector {
                    scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
                    plan: Rc::new(plan),
                    outbound: Arc::new(Peer(addr)),
                    origin: "http://fixture.test".into(),
                    skip_verify: false,
                    transactions: Some(Arc::new(Semaphore::new(32))),
                    upstream_establish: Arc::new(Semaphore::new(8)),
                    bodies: Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024))),
                    max_body: oryn_http_inspect::MAX_BODY,
                };
                let (app, server) = tokio::io::duplex(65536);
                let serving = tokio::task::spawn_local(inspector.serve(server, false));
                let (mut client, driver) = hyper::client::conn::http1::handshake(TokioIo::new(app)).await.unwrap();
                let driving = tokio::task::spawn_local(driver);
                let response = client
                    .send_request(
                        Request::builder()
                            .method("GET")
                            .uri("http://fixture.test/big")
                            .body(full(vec![]))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                let got = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(got.len(), oryn_http_inspect::MAX_BODY);
                assert_eq!(got[0], if binary { 0xa5 } else { b'Z' });
                assert_eq!(got[1], if binary { 0x5a } else { b'a' });
                drop(client);
                driving.abort();
                serving.abort();
                peer.abort();
            }
        }).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn page_weighted_budget_allows_many_concurrent_small_bodies() {
        tokio::task::LocalSet::new().run_until(async {
            let budget = Arc::new(Semaphore::new(body_budget_pages(6 * 1024 * 1024)));
            // 与旧固定 2 条计数相比，6 MiB 页预算应允许 >2 条小正文并发占用；同时阻止两条 4 MiB 并发缓冲。
            let small_count = 8usize;
            let mut responses = Vec::new();
            let mut guards = Vec::new();
            let ir = oryn_module::parse(
                "[Script]\ns = type=http-response, pattern=^http://fixture\\.test/small$, script-path=s.js, requires-body=true",
                Some(oryn_module::ModuleFormat::Surge),
            )
            .unwrap();
            let resources = [("s.js".into(), b"$done({body: $response.body + '!'});".as_slice().into())].into();
            let plan = Rc::new(oryn_http_inspect::compile_module(&ir, &Default::default(), &resources).unwrap());

            for _ in 0..small_count {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let peer = tokio::task::spawn_local(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let service = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, Infallible>(Response::builder().body(full(vec![b'x'; 16 * 1024])).unwrap())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
                let inspector = Inspector {
                    scripts: Arc::new(crate::scripts::ScriptHost::new(None)),
                    plan: plan.clone(),
                    outbound: Arc::new(Peer(addr)),
                    origin: "http://fixture.test".into(),
                    skip_verify: false,
                    transactions: Some(Arc::new(Semaphore::new(32))),
                    upstream_establish: Arc::new(Semaphore::new(32)),
                    bodies: budget.clone(),
                    max_body: oryn_http_inspect::MAX_BODY,
                };
                let (app, server) = tokio::io::duplex(65536);
                let serving = tokio::task::spawn_local(inspector.serve(server, false));
                let (mut client, driver) = hyper::client::conn::http1::handshake(TokioIo::new(app)).await.unwrap();
                let driving = tokio::task::spawn_local(driver);
                let response = client
                    .send_request(Request::builder().method("GET").uri("http://fixture.test/small").body(full(vec![])).unwrap())
                    .await
                    .unwrap();
                responses.push(response);
                guards.push((client, driving, serving, peer));
            }
            for response in responses {
                let bytes = response.into_body().collect().await.unwrap().to_bytes();
                assert_eq!(bytes.len(), 16 * 1024 + 1);
                assert!(bytes.ends_with(b"!"));
            }
            drop(guards);

            let four_mib_pages = u32::try_from(body_budget_pages(4 * 1024 * 1024)).unwrap();
            let first = budget.clone().try_acquire_many_owned(four_mib_pages).unwrap();
            assert!(budget.clone().try_acquire_many_owned(four_mib_pages).is_err());
            drop(first);
            assert!(budget.clone().try_acquire_many_owned(four_mib_pages).is_ok());
        }).await;
    }
}
