//! Shadowsocks 的 SIP003 插件：作为 SS 服务器地址上的 TCP 拨号器，在 SS 流下面再包一层。
//!
//! 插件只改变「到 SS 服务器的字节流」，SS 自己的加密与分帧不变，所以实现为一个 [`Dialer`]。
//! gost-plugin 与 v2ray-plugin 同样是 WebSocket（± TLS）；开启复用时前者是每条连接一个 smux v1 会话
//! （与 mihomo `transport/gost` 相同），后者是 Mux.Cool 单会话。

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use oryn_config::{SsPlugin, TargetAddr, WsSpec};

use crate::muxcool::MuxCool;
use crate::{wrap_tls, BoxStream, Dialer};

pub(crate) struct PluginDialer {
    pub inner: Arc<dyn Dialer>,
    pub plugin: SsPlugin,
    pub server: TargetAddr,
}

#[async_trait]
impl Dialer for PluginDialer {
    async fn dial_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let stream = self.inner.dial_tcp(target).await?;
        match &self.plugin {
            SsPlugin::None => Ok(stream),
            SsPlugin::ShadowTls(spec) => match spec.version {
                1 => Ok(Box::new(
                    oryn_tls::shadowtls::connect_v1(stream, spec).await?,
                )),
                2 => Ok(Box::new(
                    oryn_tls::shadowtls::connect_v2(stream, spec).await?,
                )),
                _ => Ok(Box::new(oryn_tls::shadowtls::connect(stream, spec).await?)),
            },
            SsPlugin::Obfs(spec) => {
                if spec.tls {
                    Ok(Box::new(oryn_transport::TlsObfs::new(stream, &spec.host)))
                } else {
                    Ok(Box::new(oryn_transport::HttpObfs::new(
                        stream,
                        &spec.host,
                        self.server.port(),
                    )))
                }
            }
            SsPlugin::V2Ray(spec) | SsPlugin::Gost(spec) => {
                let stream = wrap_tls(stream, &spec.tls, &self.server).await?;
                let authority = match &self.server {
                    TargetAddr::Ip(a) => a.to_string(),
                    TargetAddr::Domain(d, p) => format!("{d}:{p}"),
                };
                let mut headers = Vec::new();
                if !spec.host.is_empty() {
                    headers.push(("Host".to_string(), spec.host.clone()));
                }
                headers.extend(spec.headers.iter().cloned());
                let ws = oryn_transport::connect(
                    stream,
                    &authority,
                    &WsSpec {
                        path: spec.path.clone(),
                        headers,
                        max_early_data: 0,
                        early_data_header: "Sec-WebSocket-Protocol".into(),
                    },
                    &[],
                )
                .await?;
                match (&self.plugin, spec.mux) {
                    (SsPlugin::Gost(_), true) => crate::mux::smux_single(Box::new(ws)).await,
                    (_, true) => Ok(Box::new(MuxCool::new(ws))),
                    (_, false) => Ok(Box::new(ws)),
                }
            }
        }
    }
}
