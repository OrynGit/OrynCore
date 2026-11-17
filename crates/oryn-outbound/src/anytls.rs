//! AnyTLS 认证与 TLS 下层；会话帧调度使用有界复用池。
use crate::{unsupported, with_timeout, wrap_tls, BoxStream, Dialer, Outbound, PacketConn};
use async_trait::async_trait;
use oryn_config::{AnyTlsSpec, TargetAddr};
use std::{io, sync::Arc};
use tokio::io::AsyncWriteExt;
pub(crate) struct AnyCarrier {
    tag: String,
    spec: AnyTlsSpec,
    dialer: Arc<dyn Dialer>,
}
impl AnyCarrier {
    pub(crate) fn new(tag: String, spec: AnyTlsSpec, dialer: Arc<dyn Dialer>) -> Self {
        Self { tag, spec, dialer }
    }
}
#[async_trait]
impl Outbound for AnyCarrier {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "anytls"
    }
    async fn connect_tcp(&self, _: &TargetAddr) -> io::Result<BoxStream> {
        with_timeout(
            async {
                let s = self.dialer.dial_tcp(&self.spec.server).await?;
                let mut s = wrap_tls(s, &Some(self.spec.tls.clone()), &self.spec.server).await?;
                let mut auth =
                    ring::digest::digest(&ring::digest::SHA256, self.spec.password.as_bytes())
                        .as_ref()
                        .to_vec();
                auth.extend(30u16.to_be_bytes());
                auth.extend([0; 30]);
                s.write_all(&auth).await?;
                s.flush().await?;
                Ok(s)
            },
            "AnyTLS authentication",
        )
        .await
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        // UDP 由 MuxOutbound 在会话的 UoT 流上承载，不直接使用载体
        Err(unsupported("AnyTLS carrier does not carry UDP directly"))
    }
}
