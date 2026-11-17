// 线格式参考 / 移植 MetaCubeX/mihomo transport/sudoku @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。
// GPL-3.0；原文件未单列版权声明。Oryn 使用自身 Flow、Dialer 与有界生命周期。
mod go_rng;
mod mux;
mod record;
mod table;
mod transport;
mod udp;
use crate::{
    slots::{Counted, Slot, Slots},
    BoxStream, Dialer, Outbound, PacketConn, Resolver, SessionControl,
};
use async_trait::async_trait;
use oryn_config::{SudokuSpec, TargetAddr};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::Mutex as AsyncMutex,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn random<const N: usize>() -> io::Result<[u8; N]> {
    use ring::rand::SecureRandom;
    let mut b = [0; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| bad("Sudoku random failed"))?;
    Ok(b)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect()
}
fn canonical(key: &str) -> String {
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    };
    let key = key.trim();
    let Some(bytes) = unhex(key) else {
        return key.into();
    };
    if bytes.len() == 32 {
        let b: [u8; 32] = bytes[..].try_into().unwrap();
        if let Some(point) = CompressedEdwardsY(b).decompress() {
            return hex(point.compress().as_bytes());
        }
        if let Some(scalar) = Option::<Scalar>::from(Scalar::from_canonical_bytes(b)) {
            return hex((scalar * ED25519_BASEPOINT_POINT).compress().as_bytes());
        }
    }
    if bytes.len() == 64 {
        let a = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            bytes[..32].try_into().unwrap(),
        ));
        let b = Option::<Scalar>::from(Scalar::from_canonical_bytes(
            bytes[32..].try_into().unwrap(),
        ));
        if let (Some(a), Some(b)) = (a, b) {
            return hex(((a + b) * ED25519_BASEPOINT_POINT).compress().as_bytes());
        }
    }
    key.into()
}
#[derive(Default)]
struct Control {
    sleeping: AtomicBool,
    tokens: Mutex<Vec<Weak<CancellationToken>>>,
}
impl Control {
    fn register(&self) -> io::Result<Arc<CancellationToken>> {
        let mut tokens = self.tokens.lock().unwrap();
        if self.sleeping.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Sudoku is sleeping",
            ));
        }
        tokens.retain(|w| w.upgrade().is_some_and(|c| !c.is_cancelled()));
        if tokens.len() >= 33 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Sudoku session limit reached",
            ));
        }
        let token = Arc::new(CancellationToken::new());
        tokens.push(Arc::downgrade(&token));
        Ok(token)
    }
    fn reset(&self) {
        for token in self
            .tokens
            .lock()
            .unwrap()
            .drain(..)
            .filter_map(|t| t.upgrade())
        {
            token.cancel();
        }
    }
}
impl SessionControl for Control {
    fn on_network_changed(&self) {
        self.reset();
    }
    fn on_sleep(&self) {
        self.sleeping.store(true, Ordering::SeqCst);
        self.reset();
    }
    fn on_wake(&self) {
        self.sleeping.store(false, Ordering::SeqCst);
    }
}
pub struct SudokuOutbound {
    name: String,
    spec: SudokuSpec,
    seed: String,
    dialer: Arc<dyn Dialer>,
    resolver: Arc<dyn Resolver>,
    tables: OnceLock<Vec<Arc<table::Table>>>,
    control: Arc<Control>,
    slots: Slots,
    mux: AsyncMutex<Option<Arc<mux::Session>>>,
    http: Arc<transport::HttpPool>,
}
impl SudokuOutbound {
    pub fn new(
        name: String,
        spec: SudokuSpec,
        dialer: Arc<dyn Dialer>,
        resolver: Arc<dyn Resolver>,
    ) -> Arc<Self> {
        Arc::new(Self {
            seed: canonical(&spec.key),
            name,
            spec,
            dialer,
            resolver,
            tables: OnceLock::new(),
            control: Arc::new(Control::default()),
            slots: Slots::default(),
            mux: AsyncMutex::new(None),
            http: Arc::new(transport::HttpPool::default()),
        })
    }
    fn tables(&self) -> &[Arc<table::Table>] {
        self.tables.get_or_init(|| {
            let map = table::Mapping::new(&self.seed);
            self.spec
                .tables
                .iter()
                .map(|pattern| {
                    Arc::new(table::Table::new(
                        &self.seed,
                        &self.spec.table_type,
                        pattern,
                        map.clone(),
                    ))
                })
                .collect()
        })
    }
    async fn handshake(&self) -> io::Result<BoxStream> {
        let tables = self.tables();
        let table = tables[usize::from(random::<1>()?[0]) % tables.len()].clone();
        let mut security = record::Security::new(
            table.clone(),
            !self.spec.pure_downlink,
            self.spec.padding_min,
            self.spec.padding_max,
            self.spec.aead.clone(),
            &self.seed,
        )?;
        let ephemeral = StaticSecret::from(random::<32>()?);
        let public = PublicKey::from(&ephemeral);
        let nonce = random::<16>()?;
        let key_bytes = unhex(self.spec.key.trim())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| self.spec.key.trim().as_bytes().to_vec());
        let user_hash = record::sha(&key_bytes);
        let mut hello = now().to_be_bytes().to_vec();
        hello.extend_from_slice(&user_hash[..8]);
        hello.extend_from_slice(&nonce);
        hello.extend_from_slice(public.as_bytes());
        hello.extend_from_slice(&23u32.to_be_bytes()); // 始终发送合法的表提示，避免 ASCII 上行无法区分多个下行表。
        hello.extend_from_slice(&table.hint.to_be_bytes());
        let request = security.encode(&record::kip(1, &hello)?)?;
        let (stream, prefix) = transport::dial(
            &self.spec,
            &self.seed,
            self.dialer.clone(),
            self.http.clone(),
            &request,
        )
        .await?;
        let mut stream = record::SecureStream::new(stream, security, &prefix)?;
        let mut head = [0; 6];
        stream.read_exact(&mut head).await?;
        if &head[..4] != b"kip\x02" || u16::from_be_bytes([head[4], head[5]]) != 52 {
            return Err(bad("invalid Sudoku server hello"));
        }
        let mut response = [0; 52];
        stream.read_exact(&mut response).await?;
        if response[..16] != nonce {
            return Err(bad("Sudoku nonce mismatch"));
        }
        let peer = PublicKey::from(<[u8; 32]>::try_from(&response[16..48]).unwrap());
        let shared = ephemeral.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(bad("Sudoku invalid X25519 peer"));
        }
        // KIP 特性位是能力提示；真正的操作由后续控制消息决定。
        let (tx, rx) = record::session_keys(&self.seed, shared.as_bytes(), &nonce);
        stream.security.rekey(tx, rx)?;
        Ok(Box::new(stream))
    }
    async fn raw(
        &self,
        kind: u8,
        target: Option<&TargetAddr>,
        slot: Slot,
    ) -> io::Result<BoxStream> {
        let token = self.control.register()?;
        let work = async {
            let mut stream = self.handshake().await?;
            let mut address = Vec::new();
            if let Some(target) = target {
                oryn_protocol::socks5::encode_addr(target, &mut address)?;
            }
            stream.write_all(&record::kip(kind, &address)?).await?;
            stream.flush().await?;
            Ok::<_, io::Error>(guard(stream, token.clone(), slot))
        };
        let result = tokio::select! {_=token.cancelled()=>Err(io::Error::new(io::ErrorKind::Interrupted,"Sudoku connection cancelled")),result=crate::with_timeout(work,"Sudoku handshake")=>result};
        // 握手失败 / 超时时显式撤销登记：即使有后台任务意外持有 token 克隆，也不能占着 33 个名额之一
        if result.is_err() {
            token.cancel();
        }
        result
    }
}
struct SessionControls {
    control: Arc<Control>,
    http: Arc<transport::HttpPool>,
}
impl SessionControl for SessionControls {
    fn on_network_changed(&self) {
        self.control.on_network_changed();
        self.http.clear();
    }
    fn on_sleep(&self) {
        self.control.on_sleep();
        self.http.clear();
    }
    fn on_wake(&self) {
        self.control.on_wake();
        self.http.clear();
    }
}
impl Drop for SudokuOutbound {
    fn drop(&mut self) {
        self.control.reset();
        self.http.clear();
    }
}
#[async_trait]
impl Outbound for SudokuOutbound {
    fn tag(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "sudoku"
    }
    fn session_control(&self) -> Option<Arc<dyn SessionControl>> {
        Some(Arc::new(SessionControls {
            control: self.control.clone(),
            http: self.http.clone(),
        }))
    }
    async fn connect_tcp(&self, target: &TargetAddr) -> io::Result<BoxStream> {
        let slot = self.slots.acquire(32).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "Sudoku active flow limit reached",
            )
        })?;
        if self.spec.multiplex != "on" {
            return self.raw(16, Some(target), slot).await;
        }
        crate::with_timeout(async {
            let mut current=self.mux.lock().await;
            if current.as_ref().is_none_or(|s|s.stop.is_cancelled()){
                let token=self.control.register()?;let mut stream=tokio::select!{_=token.cancelled()=>return Err(bad("Sudoku cancelled")),r=self.handshake()=>r?};
                stream.write_all(&record::kip(17,&[])?).await?;stream.flush().await?;*current=Some(mux::Session::new(stream,token));
            }
            let session=current.as_ref().unwrap().clone();drop(current);let stream=session.open(target).await?;Ok(Counted::boxed(stream,slot))
        },"Sudoku multiplex connect").await
    }
    async fn bind_udp(&self, _: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let slot = self.slots.acquire(32).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "Sudoku active flow limit reached",
            )
        })?;
        let stream = self.raw(18, None, slot).await?;
        Ok(Box::new(udp::Packet::new(stream, self.resolver.clone())))
    }
}
struct Guarded {
    inner: DuplexStream,
    token: Arc<CancellationToken>,
    task: JoinHandle<()>,
    error: Arc<Mutex<Option<String>>>,
    _slot: Slot,
}
fn guard(mut stream: BoxStream, token: Arc<CancellationToken>, slot: Slot) -> BoxStream {
    let (app, mut bridge) = tokio::io::duplex(16 * 1024);
    let cancel = token.clone();
    let error = Arc::new(Mutex::new(None));
    let errors = error.clone();
    let task = tokio::spawn(async move {
        tokio::select! {_=cancel.cancelled()=>{},result=tokio::io::copy_bidirectional(&mut bridge,&mut stream)=>{if let Err(e)=result{*errors.lock().unwrap()=Some(e.to_string());}}}
    });
    Box::new(Guarded {
        inner: app,
        token,
        task,
        error,
        _slot: slot,
    })
}
impl Drop for Guarded {
    fn drop(&mut self) {
        self.token.cancel();
        self.task.abort();
    }
}
impl AsyncRead for Guarded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.token.is_cancelled() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Sudoku connection cancelled",
            )));
        }
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(r, Poll::Ready(Ok(()))) && before == buf.filled().len() {
            if let Some(e) = self.error.lock().unwrap().as_ref() {
                return Poll::Ready(Err(io::Error::other(e.clone())));
            }
        }
        r
    }
}
impl AsyncWrite for Guarded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.token.is_cancelled() {
            return Poll::Ready(Err(bad("Sudoku cancelled")));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
