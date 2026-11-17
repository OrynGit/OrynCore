//! SSH 出站：同一出站共享一条 SSH 连接，每个 Flow 打开一个 `direct-tcpip` 通道（与 mihomo 相同）。
//!
//! SSH 协议本身由 russh（Apache-2.0，ring 后端）实现。认证依次尝试私钥与密码；配置了 `host-key` 时
//! 服务端主机公钥必须与其中之一相同；未配置时首次连接记录公钥（TOFU，数据目录下 `ssh_known_hosts`），
//! 之后必须一致，没有数据目录才退回不校验。客户端标识随机取 `SSH-2.0-OpenSSH_7.x / 8.x`。
//! UDP 默认关闭；Oryn 可显式启用 BadVPN / tun2proxy 网关，访问服务器侧网关监听地址。
mod udpgw;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use oryn_config::{SshSpec, TargetAddr};
use ring::rand::{SecureRandom, SystemRandom};
use russh::client;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};

use crate::{BoxStream, Dialer, Outbound, PacketConn};

/// 每个通道的接收窗口：并发通道数 × 窗口决定最坏情况的内存占用。
const CHANNEL_WINDOW: u32 = 512 * 1024;
const CHANNEL_BUFFER: usize = 32;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// 未配置 `host-key` 时的 TOFU 记录文件（数据目录下，每行 `host:port 算法 base64`）。
const KNOWN_HOSTS: &str = "ssh_known_hosts";

struct Verifier {
    host_keys: Arc<Vec<PublicKey>>,
    /// 未配置 `host-key` 时的首次信任记录：`(文件, 服务器标识)`；没有数据目录则为 None。
    tofu: Option<(std::path::PathBuf, String)>,
}

impl Verifier {
    /// 首次使用即信任（TOFU）：记录过的服务器必须出示同一公钥，没记录过的记下来。
    /// 记录写失败时仍放行这一次（与旧行为相同），下次再尝试记录。
    fn trust_on_first_use(&self, key: &PublicKey) -> bool {
        let Some((path, server)) = &self.tofu else {
            log::warn!("ssh: host key not verified (no host-key configured and no data directory)");
            return true;
        };
        let text = std::fs::read_to_string(path).unwrap_or_default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if parts.next() != Some(server.as_str()) {
                continue;
            }
            let known = parts
                .nth(1)
                .and_then(|b64| russh::keys::parse_public_key_base64(b64).ok());
            return match known {
                Some(known) if known.key_data() == key.key_data() => true,
                _ => {
                    log::warn!("ssh: host key for {server} changed; refusing connection (remove its line from {KNOWN_HOSTS} to accept the new key)");
                    false
                }
            };
        }
        match key.to_openssh() {
            Ok(openssh) => {
                use std::io::Write;
                let written = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .and_then(|mut file| writeln!(file, "{server} {openssh}"));
                if let Err(err) = written {
                    log::warn!("ssh: cannot record host key for {server}: {err}");
                } else {
                    log::info!("ssh: recorded host key for {server} (trust on first use)");
                }
            }
            Err(err) => log::warn!("ssh: cannot encode host key for {server}: {err}"),
        }
        true
    }
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(match server {
            PublicKeyOrCertificate::PublicKey { key, .. } if self.host_keys.is_empty() => {
                self.trust_on_first_use(key)
            }
            PublicKeyOrCertificate::PublicKey { key, .. } => self
                .host_keys
                .iter()
                .any(|known| known.key_data() == key.key_data()),
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

pub(crate) struct SshOutbound {
    name: String,
    spec: SshSpec,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn crate::Resolver>,
    udp_slots: Arc<tokio::sync::Semaphore>,
    key: Option<Arc<PrivateKey>>,
    host_keys: Arc<Vec<PublicKey>>,
    known_hosts: Option<std::path::PathBuf>,
    config: Arc<client::Config>,
    session: tokio::sync::Mutex<Option<Arc<client::Handle<Verifier>>>>,
}

/// 按失败原因映射错误类型，上层据此决定是否重试：主机公钥不符是 PermissionDenied，
/// 通道被服务端拒绝是 ConnectionRefused，底层 IO 错误保留原类型，其余协议错误是 InvalidData。
fn ssh_error(what: &str, err: russh::Error) -> io::Error {
    let kind = match &err {
        russh::Error::UnknownKey => io::ErrorKind::PermissionDenied,
        russh::Error::ChannelOpenFailure(_) => io::ErrorKind::ConnectionRefused,
        russh::Error::IO(e) => e.kind(),
        russh::Error::Disconnect => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, format!("{what}: {err}"))
}

fn client_id() -> String {
    let mut r = [0u8; 2];
    let _ = SystemRandom::new().fill(&mut r);
    if r[0] & 1 == 0 {
        format!("SSH-2.0-OpenSSH_7.{}", r[1] % 10)
    } else {
        format!("SSH-2.0-OpenSSH_8.{}", r[1] % 9)
    }
}

impl SshOutbound {
    pub(crate) fn new(
        name: String,
        spec: SshSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn crate::Resolver>,
        data_dir: Option<&std::path::Path>,
    ) -> io::Result<Arc<Self>> {
        let invalid = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
        let key = match &spec.private_key {
            Some(text) => Some(Arc::new(
                russh::keys::decode_secret_key(text, spec.private_key_passphrase.as_deref())
                    .map_err(|e| invalid(format!("ssh private key: {e}")))?,
            )),
            None => None,
        };
        let mut host_keys = Vec::new();
        for line in &spec.host_keys {
            let base64 = line.split_whitespace().nth(1).unwrap_or_default();
            host_keys.push(
                russh::keys::parse_public_key_base64(base64)
                    .map_err(|e| invalid(format!("ssh host key: {e}")))?,
            );
        }
        let mut config = client::Config {
            client_id: russh::SshId::Standard(client_id().into()),
            window_size: CHANNEL_WINDOW,
            channel_buffer_size: CHANNEL_BUFFER,
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        };
        if !spec.host_key_algorithms.is_empty() {
            let algorithms = spec
                .host_key_algorithms
                .iter()
                .map(|name| {
                    russh::keys::Algorithm::from_str(name)
                        .map_err(|e| invalid(format!("ssh host-key-algorithms: {e}")))
                })
                .collect::<io::Result<Vec<_>>>()?;
            config.preferred.key = algorithms.into();
        }
        Ok(Arc::new(Self {
            name,
            resolver,
            udp_slots: Arc::new(tokio::sync::Semaphore::new(32)),
            spec,
            dialer,
            key,
            host_keys: Arc::new(host_keys),
            known_hosts: data_dir.map(|dir| dir.join(KNOWN_HOSTS)),
            config: Arc::new(config),
            session: tokio::sync::Mutex::new(None),
        }))
    }

    async fn handshake(&self) -> io::Result<client::Handle<Verifier>> {
        let tcp = self.dialer.dial_tcp(&self.spec.server).await?;
        let server = match &self.spec.server {
            TargetAddr::Domain(host, port) => format!("{host}:{port}"),
            TargetAddr::Ip(addr) => addr.to_string(),
        };
        let verifier = Verifier {
            host_keys: self.host_keys.clone(),
            tofu: self.known_hosts.clone().map(|path| (path, server)),
        };
        let mut handle = client::connect_stream(self.config.clone(), tcp, verifier)
            .await
            .map_err(|e| ssh_error("ssh handshake", e))?;
        let user = self.spec.username.clone();
        if let Some(key) = &self.key {
            let hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(io::Error::other)?
                .flatten();
            let result = handle
                .authenticate_publickey(user.clone(), PrivateKeyWithHashAlg::new(key.clone(), hash))
                .await
                .map_err(io::Error::other)?;
            if result.success() {
                return Ok(handle);
            }
        }
        if let Some(password) = &self.spec.password {
            let result = handle
                .authenticate_password(user, password.clone())
                .await
                .map_err(io::Error::other)?;
            if result.success() {
                return Ok(handle);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ssh authentication failed",
        ))
    }

    /// 复用现有连接；它已关闭（或 `fresh`）则重新握手。并发 Flow 等同一次握手。
    async fn session(&self, fresh: bool) -> io::Result<Arc<client::Handle<Verifier>>> {
        let mut guard = self.session.lock().await;
        if let Some(handle) = guard.as_ref() {
            if !fresh && !handle.is_closed() {
                return Ok(handle.clone());
            }
        }
        *guard = None;
        let handle = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.handshake())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ssh handshake timed out"))??;
        let handle = Arc::new(handle);
        *guard = Some(handle.clone());
        Ok(handle)
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "ssh"
    }
    fn session_control(&self) -> Option<Arc<dyn crate::SessionControl>> {
        None
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let (host, port) = match target {
            TargetAddr::Domain(host, port) => (host.clone(), *port),
            TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
        };
        let mut fresh = false;
        loop {
            let handle = self.session(fresh).await?;
            match handle
                .channel_open_direct_tcpip(host.clone(), u32::from(port), "127.0.0.1", 0)
                .await
            {
                Ok(channel) => return Ok(Box::new(channel.into_stream())),
                // 连接已断（网络切换、服务端重启）：重新握手一次
                Err(_) if handle.is_closed() && !fresh => fresh = true,
                Err(err) => return Err(ssh_error("ssh direct-tcpip", err)),
            }
        }
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let gateway = self.spec.udp_gateway.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "SSH UDP gateway is disabled")
        })?;
        let slot = self
            .udp_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| io::Error::other("SSH UDP gateway channel limit reached"))?;
        let stream = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            self.connect_tcp(&TargetAddr::Ip(gateway.server)),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "SSH UDP gateway channel timed out")
        })??;
        Ok(Box::new(udpgw::Gateway::new(
            stream,
            gateway.mode,
            self.resolver.clone(),
            slot,
        )))
    }
}
