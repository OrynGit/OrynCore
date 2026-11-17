use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use oryn_config::{ProxyAuth, TargetAddr, TlsSpec};

use crate::{unsupported, with_timeout, wrap_tls, BoxStream, Dialer, Outbound, PacketConn};

pub struct HttpOutbound {
    tag: String,
    server: TargetAddr,
    auth: Option<ProxyAuth>,
    tls: Option<TlsSpec>,
    dialer: Arc<dyn Dialer>,
}

impl HttpOutbound {
    pub fn new(
        tag: String,
        server: TargetAddr,
        auth: Option<ProxyAuth>,
        mut tls: Option<TlsSpec>,
        dialer: Arc<dyn Dialer>,
    ) -> Self {
        if let Some(tls) = &mut tls {
            if tls.client_fingerprint.is_some() && tls.alpn.is_empty() {
                tls.alpn = vec!["http/1.1".into()];
            }
        }
        HttpOutbound {
            tag,
            server,
            auth,
            tls,
            dialer,
        }
    }
}

#[async_trait]
impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        with_timeout(
            async {
                let stream = self.dialer.dial_tcp(&self.server).await?;
                let mut stream = wrap_tls(stream, &self.tls, &self.server).await?;
                oryn_protocol::http::connect(&mut stream, target, self.auth.as_ref()).await?;
                Ok(stream)
            },
            "HTTP proxy handshake",
        )
        .await
    }

    async fn bind_udp(&self, _first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        Err(unsupported("HTTP proxy does not support UDP"))
    }
}
