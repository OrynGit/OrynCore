//! 远程资源（代理集合、规则集、GeoIP / ASN 数据库）的下载出站选择。

use std::io;
use std::sync::Arc;

use oryn_config::ProviderVia;
use oryn_dns::Routing;
use oryn_http::{fetch, Connector, Options, OutboundConnector, Request, Response};
use oryn_outbound::{resolve, BoxStream, PickMeta};
use oryn_router::{DomainSource, FlowContext, Network};

/// 遵循分流规则的连接方式：每次连接（含重定向）都按目标域名走一遍 Router，与普通流量一致。
pub(crate) struct RulesConnector(pub(crate) Arc<Routing>);

#[async_trait::async_trait]
impl Connector for RulesConnector {
    async fn connect(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        let mut flow = FlowContext::new(
            0,
            Network::Tcp,
            "127.0.0.1:0".parse().unwrap(),
            format!("0.0.0.0:{port}").parse().unwrap(),
        );
        flow.set_domain(host.into(), DomainSource::Sniffed);
        let route = self.0.router.route(&flow);
        let target = oryn_config::TargetAddr::from_host(host, port);
        let meta = PickMeta {
            source: None,
            target: &target,
            network: Network::Tcp,
        };
        let resolved = resolve(&self.0.outbounds[route.outbound], &meta).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "rejected by the routing rules",
            )
        })?;
        resolved.leaf.connect_tcp(&target).await
    }
}

/// 按 `via` 下载：指定出站时只用它；遵循分流规则时，规则指向的出站连不上或返回非 2xx
/// （例如指向还没有节点的策略组）再直连试一次，两次都失败时返回规则路径的结果。
pub async fn fetch_via<'a>(
    routing: &Arc<Routing>,
    direct: usize,
    via: ProviderVia,
    request: impl Fn() -> Request<'a>,
    opts: &Options,
) -> io::Result<Response> {
    match via {
        ProviderVia::Outbound(i) => {
            fetch(
                &OutboundConnector(routing.outbounds[i].clone()),
                request(),
                opts,
            )
            .await
        }
        ProviderVia::Rules => {
            // 直连模式没有代理链可试。少走一遍相同的 DIRECT，避免一次更新占用两个超时。
            if routing.router.mode() == oryn_config::Mode::Direct {
                return fetch(
                    &OutboundConnector(routing.outbounds[direct].clone()),
                    request(),
                    opts,
                )
                .await;
            }
            let routed = fetch(&RulesConnector(routing.clone()), request(), opts).await;
            match routed {
                Ok(r) if r.is_success() => Ok(r),
                other => {
                    let direct = OutboundConnector(routing.outbounds[direct].clone());
                    match fetch(&direct, request(), opts).await {
                        Ok(r) => Ok(r),
                        Err(_) => other,
                    }
                }
            }
        }
    }
}

/// 数据库 GET 的文件版本：每次尝试重新截断临时文件，不能将重试正文接到失败的半文件后。
/// 仅最终 200 正文写入文件；重定向与非 200 由 HTTP 层处理且不写 sink。
/// 同步文件写每次最多 16 KiB，不派生脱离生命周期的文件任务，取消后可立即删除临时文件。
pub async fn get_via_file(
    routing: &Arc<Routing>,
    direct: usize,
    via: ProviderVia,
    url: &str,
    opts: &Options,
    path: &std::path::Path,
) -> io::Result<Response> {
    match via {
        ProviderVia::Outbound(i) => {
            fetch_file(
                &OutboundConnector(routing.outbounds[i].clone()),
                url,
                opts,
                path,
            )
            .await
        }
        ProviderVia::Rules => {
            if routing.router.mode() == oryn_config::Mode::Direct {
                return fetch_file(
                    &OutboundConnector(routing.outbounds[direct].clone()),
                    url,
                    opts,
                    path,
                )
                .await;
            }
            let routed = fetch_file(&RulesConnector(routing.clone()), url, opts, path).await;
            match routed {
                Ok(r) if r.is_success() => Ok(r),
                other => match fetch_file(
                    &OutboundConnector(routing.outbounds[direct].clone()),
                    url,
                    opts,
                    path,
                )
                .await
                {
                    Ok(r) => Ok(r),
                    Err(_) => other,
                },
            }
        }
    }
}

async fn fetch_file(
    connector: &dyn Connector,
    url: &str,
    opts: &Options,
    path: &std::path::Path,
) -> io::Result<Response> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    let mut sink = FileSink(file);
    let (response, _) = oryn_http::fetch_to_writer(
        connector,
        Request {
            method: "GET",
            url,
            headers: &[],
            body: &[],
        },
        opts,
        &mut sink,
    )
    .await?;
    Ok(response)
}

struct FileSink(std::fs::File);
impl tokio::io::AsyncWrite for FileSink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::io::Write;
        std::task::Poll::Ready(self.0.write(&data[..data.len().min(16 * 1024)]))
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::io::Write;
        std::task::Poll::Ready(self.0.flush())
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// GET 版本的 [`fetch_via`]。
pub async fn get_via(
    routing: &Arc<Routing>,
    direct: usize,
    via: ProviderVia,
    url: &str,
    opts: &Options,
) -> io::Result<Response> {
    let request = || Request {
        method: "GET",
        url,
        headers: &[],
        body: &[],
    };
    fetch_via(routing, direct, via, request, opts).await
}
