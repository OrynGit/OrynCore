//! VMess 客户端；依据 V2Fly 公开报文规范独立实现。
//! alterId / authenticated-length 行为核对 sing-vmess v0.2.7，见协议笔记。
mod crypto;
use bytes::{Buf, Bytes, BytesMut};
use crypto::*;
use oryn_config::{TargetAddr, VmessSpec};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128, Shake128Reader,
};
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const MAX_FRAME: usize = 65535;
/// 每次从底层流读取的上限。
const READ_CHUNK: usize = 16 * 1024;

pub fn address(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = target.port().to_be_bytes().to_vec();
    match target {
        TargetAddr::Ip(a) => match a.ip() {
            std::net::IpAddr::V4(a) => {
                out.push(1);
                out.extend(a.octets());
            }
            std::net::IpAddr::V6(a) => {
                out.push(3);
                out.extend(a.octets());
            }
        },
        TargetAddr::Domain(d, _) => {
            if d.is_empty() || d.len() > 255 {
                return Err(bad("invalid VMess destination"));
            }
            out.extend([2, d.len() as u8]);
            out.extend(d.as_bytes());
        }
    }
    Ok(out)
}
fn hash16(data: &[u8], legacy: bool) -> [u8; 16] {
    if legacy {
        md5(data)
    } else {
        sha256(data)[..16].try_into().unwrap()
    }
}
struct Body {
    security: u8,
    options: u8,
    nonce: [u8; 12],
    len_nonce: [u8; 12],
    count: u32,
    shake: Shake128Reader,
    cfb: Option<Cfb>,
    next: Option<(usize, usize)>,
    /// 按连接预先扩展好的 AEAD 密钥（AES-GCM / ChaCha20 时有）。
    aead: Option<ring::aead::LessSafeKey>,
    len_aead: Option<ring::aead::LessSafeKey>,
}
impl Body {
    fn new(
        spec: &VmessSpec,
        options: u8,
        key: &[u8],
        iv: &[u8],
        request_key: &[u8],
        request_iv: &[u8],
    ) -> Self {
        let security = security_byte(&spec.cipher).unwrap_or(5);
        let mut shake = Shake128::default();
        shake.update(iv);
        let len_key = kdf(request_key, &[b"auth_len"]);
        let body_key = if security == 4 {
            chacha_key(key)
        } else {
            key.to_vec()
        };
        let len_key = if security == 4 {
            chacha_key(&len_key[..16])
        } else {
            len_key[..16].to_vec()
        };
        let aead_kind = matches!(security, 3 | 4);
        Self {
            security,
            options,
            aead: aead_kind
                .then(|| aead_key(&body_key, security == 4))
                .flatten(),
            len_aead: aead_kind
                .then(|| aead_key(&len_key, security == 4))
                .flatten(),
            nonce: iv[..12].try_into().unwrap(),
            len_nonce: request_iv[..12].try_into().unwrap(),
            count: 0,
            shake: shake.finalize_xof(),
            cfb: (security == 1).then(|| Cfb::new(key, iv)),
            next: None,
        }
    }
    fn number(&mut self) -> u16 {
        let mut b = [0; 2];
        self.shake.read(&mut b);
        u16::from_be_bytes(b)
    }
    fn padding(&mut self) -> usize {
        if self.options & 8 != 0 {
            self.number() as usize % 64
        } else {
            0
        }
    }
    /// 块计数只有 16 位，超过 65535 块（Xray 每块 8 KiB，约 512 MiB）后与 Xray / V2Ray / sing-vmess 一样回绕；
    /// 协议没有重新协商密钥的办法，报错会让大文件下载在中途断开。
    fn nonce(&mut self) -> io::Result<()> {
        self.nonce[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        self.len_nonce[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        self.count = self.count.wrapping_add(1);
        Ok(())
    }
    /// 一帧的密钥：AEAD 用预扩展的密钥，缺失（密钥长度异常）时报错。
    fn body_key(&self) -> io::Result<&ring::aead::LessSafeKey> {
        self.aead.as_ref().ok_or_else(|| bad("invalid AEAD key"))
    }
    fn length_key(&self) -> io::Result<&ring::aead::LessSafeKey> {
        self.len_aead.as_ref().ok_or_else(|| bad("invalid AEAD key"))
    }
    /// 一帧直接写进一个缓冲：长度首部、（校验和）、负载原地加密 + 标签、填充，最后整体 CFB。
    /// 只分配一次、拷贝一次负载。
    fn encode(&mut self, data: &[u8]) -> io::Result<Bytes> {
        if self.options & 1 == 0 {
            return Ok(Bytes::copy_from_slice(data));
        }
        let aead = matches!(self.security, 3 | 4);
        if aead {
            self.nonce()?;
        }
        let pad = self.padding();
        let body_len = data.len() + if self.security == 1 { 4 } else { 0 } + if aead { 16 } else { 0 };
        let len = body_len + pad;
        if len > MAX_FRAME {
            return Err(bad("VMess packet exceeds frame limit"));
        }
        let auth_len = self.options & 16 != 0;
        let mut out = Vec::with_capacity(if auth_len { 18 } else { 2 } + len);
        if auth_len {
            out.extend_from_slice(&((len - 16) as u16).to_be_bytes());
            let tag = seal_slice(self.length_key()?, &self.len_nonce, &mut out[..2])?;
            out.extend_from_slice(tag.as_ref());
        } else {
            let mask = if self.options & 4 != 0 {
                self.number()
            } else {
                0
            };
            out.extend_from_slice(&((len as u16) ^ mask).to_be_bytes());
        }
        let start = out.len();
        if self.security == 1 {
            out.extend_from_slice(&fnv(data).to_be_bytes());
        }
        out.extend_from_slice(data);
        if aead {
            let tag = seal_slice(self.body_key()?, &self.nonce, &mut out[start..])?;
            out.extend_from_slice(tag.as_ref());
        }
        if pad > 0 {
            let random = random::<64>()?;
            out.extend_from_slice(&random[..pad]);
        }
        if let Some(cfb) = &mut self.cfb {
            cfb.apply(&mut out, false);
        }
        Ok(out.into())
    }
    /// 从 `buffer` 切出一帧。帧体用 `split_to` 取出后原地解密，不拷贝、不搬移剩余数据。
    fn decode(&mut self, buffer: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if self.options & 1 == 0 {
            return Ok((!buffer.is_empty()).then(|| buffer.split().freeze()));
        }
        if self.next.is_none() {
            let n = if self.options & 16 != 0 { 18 } else { 2 };
            if buffer.len() < n {
                return Ok(None);
            }
            if matches!(self.security, 3 | 4) {
                self.nonce()?;
            }
            let pad = self.padding();
            let mut header = [0u8; 18];
            header[..n].copy_from_slice(&buffer[..n]);
            if self.options & 16 != 0 {
                open_slice(self.length_key()?, &self.len_nonce, &mut header)?;
            }
            let len = u16::from_be_bytes([header[0], header[1]]) as usize;
            let len = if self.options & 16 != 0 {
                len + 16
            } else {
                len ^ if self.options & 4 != 0 {
                    self.number() as usize
                } else {
                    0
                }
            };
            if len > MAX_FRAME || len < pad {
                return Err(bad("invalid VMess frame length"));
            }
            buffer.advance(n);
            self.next = Some((len, pad));
        }
        let (len, pad) = self.next.unwrap();
        if buffer.len() < len {
            return Ok(None);
        }
        let mut body = buffer.split_to(len);
        body.truncate(len - pad);
        self.next = None;
        if self.security == 3 || self.security == 4 {
            let n = open_slice(self.body_key()?, &self.nonce, &mut body)?;
            body.truncate(n);
        }
        if self.security == 1 {
            if body.len() < 4
                || u32::from_be_bytes(body[..4].try_into().unwrap()) != fnv(&body[4..])
            {
                return Err(bad("invalid VMess CFB checksum"));
            }
            body.advance(4);
        }
        Ok(Some(body.freeze()))
    }
}
/// 请求首部的 security 字节。`zero` 与 `none` 一样发 5（NONE）：sing-vmess（client.go
/// `case "none", "zero": rawSecurity = SecurityTypeNone`）、V2Ray 客户端都把 zero 落成 NONE 并去掉分块，
/// 线上没有 6（ZERO）；sing-vmess 服务端只接受 1 / 3 / 4 / 5，收到 6 报 `unknown security type`
/// （OrynCore#60）。`auto` 按 AES-128-GCM。
fn security_byte(cipher: &str) -> Option<u8> {
    match cipher {
        "aes-128-cfb" => Some(1),
        "aes-128-gcm" | "auto" => Some(3),
        "chacha20-poly1305" => Some(4),
        "none" | "zero" => Some(5),
        _ => None,
    }
}
/// 请求选项：CFB 分块；AEAD 分块 + 长度掩码（可选全局填充、认证长度）；NONE 只在 UDP 分块，
/// TCP 原样传输（与 sing-vmess client.go 一致）。
fn request_options(spec: &VmessSpec, security: u8, command: u8) -> u8 {
    match security {
        1 => 1,
        3 | 4 => {
            5 | if spec.global_padding { 8 } else { 0 }
                | if spec.authenticated_length { 16 } else { 0 }
        }
        _ => {
            if command == 2 {
                1
            } else {
                0
            }
        }
    }
}
pub struct Session {
    key: [u8; 16],
    iv: [u8; 16],
    response: u8,
    packet: bool,
    legacy: bool,
    read: Body,
    write: Body,
}
impl Session {
    pub fn request(
        spec: &VmessSpec,
        target: &TargetAddr,
        command: u8,
    ) -> io::Result<(Bytes, Self)> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| bad("VMess clock before Unix epoch"))?
            .as_secs();
        Self::request_at(spec, target, command, timestamp)
    }
    /// 显式时钟入口用于报文验收；正常出站使用 request 的系统时钟。
    pub fn request_at(
        spec: &VmessSpec,
        target: &TargetAddr,
        command: u8,
        timestamp: u64,
    ) -> io::Result<(Bytes, Self)> {
        let key = random::<16>()?;
        let iv = random::<16>()?;
        let response = random::<1>()?[0];
        let legacy = spec.alter_id > 0;
        let security =
            security_byte(&spec.cipher).ok_or_else(|| bad("unsupported VMess cipher"))?;
        let options = request_options(spec, security, command);
        let mut header = vec![1];
        header.extend(iv);
        header.extend(key);
        header.extend([response, options, security, 0, command]);
        if command != 3 {
            header.extend(address(target)?);
        }
        header.extend(fnv(&header).to_be_bytes());
        let timestamp = timestamp.to_be_bytes();
        let command_key = md5(&[
            spec.uuid.as_slice(),
            b"c48619fe-8f02-49e0-b9e9-edf763e17e21",
        ]
        .concat());
        let mut wire = Vec::new();
        if legacy {
            let alter_key = md5(&[
                spec.uuid.as_slice(),
                b"16167dc8-16b6-4e6d-b8bb-65dd68113a81",
            ]
            .concat());
            wire.extend(hmac_md5(&alter_key, &timestamp));
            let header_iv = md5(&timestamp.repeat(4));
            Cfb::new(&command_key, &header_iv).apply(&mut header, false);
            wire.extend(header);
        } else {
            let mut auth = [0; 16];
            auth[..8].copy_from_slice(&timestamp);
            auth[8..12].copy_from_slice(&random::<4>()?);
            let crc = crc32fast::hash(&auth[..12]);
            auth[12..].copy_from_slice(&crc.to_be_bytes());
            aes_block(
                &kdf(&command_key, &[b"AES Auth ID Encryption"])[..16],
                &mut auth,
            );
            let nonce = random::<8>()?;
            let mut length = (header.len() as u16).to_be_bytes().to_vec();
            seal(
                &kdf(
                    &command_key,
                    &[b"VMess Header AEAD Key_Length", &auth, &nonce],
                )[..16],
                &kdf(
                    &command_key,
                    &[b"VMess Header AEAD Nonce_Length", &auth, &nonce],
                )[..12],
                &auth,
                &mut length,
                false,
            )?;
            seal(
                &kdf(&command_key, &[b"VMess Header AEAD Key", &auth, &nonce])[..16],
                &kdf(&command_key, &[b"VMess Header AEAD Nonce", &auth, &nonce])[..12],
                &auth,
                &mut header,
                false,
            )?;
            wire.extend(auth);
            wire.extend(length);
            wire.extend(nonce);
            wire.extend(header);
        }
        let response_key = hash16(&key, legacy);
        let response_iv = hash16(&iv, legacy);
        let mut read = Body::new(spec, options, &response_key, &response_iv, &key, &iv);
        // 旧版响应首部使用同一 CFB 状态；AEAD 认证的 CFB 负载独立从 IV 开始。
        if legacy {
            read.cfb = Some(Cfb::new(&response_key, &response_iv));
        }
        let write = Body::new(spec, options, &key, &iv, &key, &iv);
        Ok((
            wire.into(),
            Self {
                key,
                iv,
                response,
                packet: command == 2,
                legacy,
                read,
                write,
            },
        ))
    }
    pub fn stream<S: AsyncRead + AsyncWrite + Unpin>(self, stream: S) -> VmessStream<S> {
        VmessStream {
            stream,
            session: self,
            buffer: BytesMut::new(),
            payload: Bytes::new(),
            pending: Bytes::new(),
            header_len: None,
            header_done: false,
            eof: false,
            failed: false,
            closed: false,
        }
    }
}
pub struct VmessStream<S> {
    stream: S,
    session: Session,
    buffer: BytesMut,
    payload: Bytes,
    pending: Bytes,
    header_len: Option<usize>,
    header_done: bool,
    eof: bool,
    failed: bool,
    closed: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    fn response(&mut self) -> io::Result<bool> {
        let key = hash16(&self.session.key, self.session.legacy);
        let iv = hash16(&self.session.iv, self.session.legacy);
        if self.session.legacy {
            if self.buffer.len() < 4 {
                return Ok(false);
            }
            if self.header_len.is_none() {
                self.session
                    .read
                    .cfb
                    .as_mut()
                    .unwrap()
                    .apply(&mut self.buffer[..4], true);
                if self.buffer[0] != self.session.response {
                    return Err(bad("invalid VMess response authentication"));
                }
                self.header_len = Some(4 + self.buffer[3] as usize);
            }
        } else {
            if self.header_len.is_none() {
                if self.buffer.len() < 18 {
                    return Ok(false);
                }
                let mut len = self.buffer[..18].to_vec();
                open(
                    &kdf(&key, &[b"AEAD Resp Header Len Key"])[..16],
                    &kdf(&iv, &[b"AEAD Resp Header Len IV"])[..12],
                    &[],
                    &mut len,
                    false,
                )?;
                let n = u16::from_be_bytes(len.try_into().unwrap()) as usize;
                if !(4..=1024).contains(&n) {
                    return Err(bad("invalid VMess response length"));
                }
                self.buffer.advance(18);
                self.header_len = Some(n + 16);
            }
        }
        let n = self.header_len.unwrap();
        if self.buffer.len() < n {
            return Ok(false);
        }
        if !self.session.legacy {
            let mut header = self.buffer[..n].to_vec();
            open(
                &kdf(&key, &[b"AEAD Resp Header Key"])[..16],
                &kdf(&iv, &[b"AEAD Resp Header IV"])[..12],
                &[],
                &mut header,
                false,
            )?;
            if header.first() != Some(&self.session.response)
                || header.len() != 4 + header[3] as usize
            {
                return Err(bad("invalid VMess response authentication"));
            }
        }
        if self.session.legacy && n > 4 {
            self.session
                .read
                .cfb
                .as_mut()
                .unwrap()
                .apply(&mut self.buffer[4..n], true);
        }
        self.buffer.advance(n);
        self.header_done = true;
        if self.session.read.security == 1 {
            self.session
                .read
                .cfb
                .as_mut()
                .unwrap()
                .apply(&mut self.buffer, true);
        }
        // 非 CFB 负载不能沿用响应首部的 CFB 状态。
        if self.session.read.security != 1 {
            self.session.read.cfb = None;
        }
        Ok(true)
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.stream).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed || self.closed {
            return Poll::Ready(Err(bad("VMess stream closed")));
        }
        ready!(self.drain(cx))?;
        let n = if self.session.packet {
            data.len()
        } else {
            data.len().min(15000)
        };
        if n > 0 {
            match self.session.write.encode(&data[..n]) {
                Ok(b) => self.pending = b,
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    /// 半关闭。分块模式（options 第 0 位）用协议内的结束块（空负载块）告知服务端「请求发完了」，
    /// 承载保持打开以继续接收响应，与 V2Ray 客户端一致；服务端（V2Ray / Xray / sing-vmess）读到它即
    /// 半关闭到目标的连接。WebSocket、smux 等没有半关闭的承载上，关闭承载会连同响应一起丢掉
    /// （OrynCore#61）。不分块（none / zero 的 TCP）没有结束标记，只能关闭承载的写方向。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        if self.session.write.options & 1 == 0 || self.failed {
            self.closed = true;
            return Pin::new(&mut self.stream).poll_shutdown(cx);
        }
        if !self.closed {
            match self.session.write.encode(&[]) {
                Ok(end) => self.pending = end,
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
            self.closed = true;
        }
        ready!(self.drain(cx))?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed {
            return Poll::Ready(Err(bad("VMess stream failed")));
        }
        loop {
            if !self.payload.is_empty() {
                let n = self.payload.len().min(buf.remaining());
                buf.put_slice(&self.payload[..n]);
                self.payload.advance(n);
                return Poll::Ready(Ok(()));
            }
            let decoded = (|| {
                if !self.header_done && !self.response()? {
                    return Ok(None);
                }
                let this = &mut *self;
                this.session.read.decode(&mut this.buffer)
            })();
            match decoded {
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
                Ok(Some(data)) => {
                    if data.is_empty() {
                        self.eof = true;
                    } else {
                        self.payload = data;
                        continue;
                    }
                }
                Ok(None) => {}
            }
            if self.eof {
                if !self.header_done || !self.buffer.is_empty() || self.session.read.next.is_some()
                {
                    self.failed = true;
                    return Poll::Ready(Err(bad("truncated VMess response")));
                }
                return Poll::Ready(Ok(()));
            }
            // 直接读进接收缓冲尾部：一次最多 READ_CHUNK，不经栈上中转再拷贝
            let start = self.buffer.len();
            let want = (MAX_FRAME + 4096).saturating_sub(start).min(READ_CHUNK);
            if want == 0 {
                self.failed = true;
                return Poll::Ready(Err(bad("VMess receive buffer exceeded")));
            }
            self.buffer.resize(start + want, 0);
            let this = &mut *self;
            let mut read = ReadBuf::new(&mut this.buffer[start..]);
            let polled = Pin::new(&mut this.stream).poll_read(cx, &mut read);
            let n = read.filled().len();
            this.buffer.truncate(start + n);
            ready!(polled)?;
            if n == 0 {
                self.eof = true;
                continue;
            }
            if self.header_done {
                let this = &mut *self;
                if let Some(cfb) = &mut this.session.read.cfb {
                    cfb.apply(&mut this.buffer[start..], true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec(cipher: &str, pad: bool, auth: bool) -> VmessSpec {
        VmessSpec {
            uuid: [42; 16],
            alter_id: 0,
            cipher: cipher.into(),
            global_padding: pad,
            authenticated_length: auth,
        }
    }
    /// zero 与 none 线上相同：security 5、TCP 不分块、UDP 分块（OrynCore#60，对照 sing-vmess）。
    #[test]
    fn zero_maps_to_none_like_sing_vmess() {
        assert_eq!(security_byte("zero"), Some(5));
        assert_eq!(security_byte("none"), Some(5));
        assert_eq!(security_byte("auto"), Some(3));
        assert_eq!(security_byte("bogus"), None);
        for cipher in ["zero", "none"] {
            let spec = spec(cipher, true, true);
            assert_eq!(request_options(&spec, 5, 1), 0, "{cipher} tcp");
            assert_eq!(request_options(&spec, 5, 2), 1, "{cipher} udp");
        }
        assert_eq!(request_options(&spec("aes-128-gcm", false, false), 3, 1), 5);
        assert!(Session::request(&spec("bogus", false, false), &TargetAddr::Domain("a.test".into(), 443), 1).is_err());
    }
    #[test]
    fn stream_ciphers_do_not_have_an_aead_nonce_limit() {
        for cipher in ["aes-128-cfb", "none"] {
            let spec = spec(cipher, false, false);
            let mut write = Body::new(&spec, 1, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
            let mut read = Body::new(&spec, 1, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
            // 模拟第 65537 个分块；CFB 的状态和 none 的分帧都不使用 AEAD nonce。
            write.count = 65536;
            read.count = 65536;
            let mut wire = BytesMut::from(&write.encode(b"still open").unwrap()[..]);
            if let Some(cfb) = &mut read.cfb {
                cfb.apply(&mut wire, true);
            }
            assert_eq!(
                read.decode(&mut wire).unwrap().unwrap().as_ref(),
                b"still open"
            );
        }
    }
    #[test]
    fn chunk_boundaries_integrity_and_nonce_wrap() {
        for cipher in ["aes-128-gcm", "chacha20-poly1305", "aes-128-cfb", "none"] {
            for pad in [false, true] {
                for auth in [false, true] {
                    let spec = spec(cipher, pad, auth);
                    let options = if cipher == "aes-128-cfb" || cipher == "none" {
                        1
                    } else {
                        5 | if pad { 8 } else { 0 } | if auth { 16 } else { 0 }
                    };
                    let mut write =
                        Body::new(&spec, options, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
                    let mut read =
                        Body::new(&spec, options, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
                    for n in [1, 7, 4096, 15000] {
                        let data = vec![43; n];
                        let wire = write.encode(&data).unwrap();
                        let mut pending = BytesMut::new();
                        let mut decoded = None;
                        for chunk in wire.chunks(3) {
                            let mut chunk = chunk.to_vec();
                            if let Some(cfb) = &mut read.cfb {
                                cfb.apply(&mut chunk, true);
                            }
                            pending.extend(chunk);
                            if let Some(b) = read.decode(&mut pending).unwrap() {
                                assert!(decoded.is_none());
                                decoded = Some(b);
                            }
                        }
                        assert_eq!(decoded.unwrap().as_ref(), data);
                    }
                    // 计数回绕后继续可用（与 Xray / sing-vmess 一致），对端同样回绕时能解开
                    write.count = 65535;
                    read.count = 65535;
                    for _ in 0..3 {
                        let mut wire = BytesMut::from(&write.encode(b"wrap").unwrap()[..]);
                        if let Some(cfb) = &mut read.cfb {
                            cfb.apply(&mut wire, true);
                        }
                        assert_eq!(read.decode(&mut wire).unwrap().unwrap().as_ref(), b"wrap");
                    }
                }
            }
        }
        let spec = spec("aes-128-gcm", false, false);
        let mut w = Body::new(&spec, 5, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
        let mut r = Body::new(&spec, 5, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
        let mut wire = BytesMut::from(&w.encode(b"secret").unwrap()[..]);
        *wire.last_mut().unwrap() ^= 1;
        assert!(r.decode(&mut wire).is_err());
    }
    fn session(spec: &VmessSpec, options: u8) -> Session {
        Session {
            key: [1; 16],
            iv: [2; 16],
            response: 0,
            packet: false,
            legacy: false,
            read: Body::new(spec, options, &[3; 16], &[4; 16], &[1; 16], &[2; 16]),
            write: Body::new(spec, options, &[1; 16], &[2; 16], &[1; 16], &[2; 16]),
        }
    }
    /// 分块模式的半关闭发结束块、不关闭承载；不分块时关闭承载写方向（OrynCore#61）。
    #[tokio::test]
    async fn half_close_sends_end_chunk_and_keeps_transport_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (cipher, options) in [("aes-128-gcm", 5 | 8 | 16), ("chacha20-poly1305", 5), ("aes-128-cfb", 1)] {
            let spec = spec(cipher, options & 8 != 0, options & 16 != 0);
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let mut stream = session(&spec, options).stream(client);
            stream.write_all(b"request").await.unwrap();
            stream.shutdown().await.unwrap();
            assert!(stream.write_all(b"late").await.is_err(), "{cipher}");
            let mut wire = vec![0; 4096];
            let n = server.read(&mut wire).await.unwrap();
            let mut wire = BytesMut::from(&wire[..n]);
            let mut read = Body::new(&spec, options, &[1; 16], &[2; 16], &[1; 16], &[2; 16]);
            if let Some(cfb) = &mut read.cfb {
                cfb.apply(&mut wire, true);
            }
            assert_eq!(read.decode(&mut wire).unwrap().unwrap().as_ref(), b"request");
            assert!(read.decode(&mut wire).unwrap().unwrap().is_empty(), "{cipher} end chunk");
            assert!(wire.is_empty());
            // 承载没有关闭：对端读不到 EOF，仍可回写
            let mut probe = [0; 1];
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), server.read(&mut probe))
                    .await
                    .is_err(),
                "{cipher} transport must stay open"
            );
            server.write_all(b"x").await.unwrap();
        }
        // none 的 TCP 不分块：没有结束标记，关闭承载写方向
        let spec = spec("none", false, false);
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let mut stream = session(&spec, 0).stream(client);
        stream.write_all(b"raw").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"raw");
    }
}

#[cfg(test)]
mod legacy_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    fn alter_ids(uuid: &[u8; 16], count: u16) -> Vec<[u8; 16]> {
        let mut out = Vec::with_capacity(usize::from(count) + 1);
        let mut cur = *uuid;
        for _ in 0..count {
            cur = md5(&[cur.as_slice(), b"16167dc8-16b6-4e6d-b8bb-65dd68113a81"].concat());
            out.push(cur);
        }
        out.push(*uuid);
        out
    }

    struct ParsedLegacyHeader {
        req_key: [u8; 16],
        req_iv: [u8; 16],
        resp_auth: u8,
        options: u8,
        security: u8,
        command: u8,
        consumed: usize,
    }

    /// 独立按 V2Fly VMess legacy（MD5/HMAC-MD5 + CFB）协议解析并校验请求首部。
    fn parse_legacy_request(
        uuid: &[u8; 16],
        alter_id: u16,
        ts: u64,
        wire: &[u8],
    ) -> ParsedLegacyHeader {
        assert!(wire.len() >= 16 + 38, "legacy request too short");
        let auth = &wire[..16];
        let ts_bytes = ts.to_be_bytes();
        let candidates = alter_ids(uuid, alter_id);
        assert!(
            candidates.iter().any(|id| hmac_md5(id, &ts_bytes) == auth),
            "HMAC-MD5 auth tag did not match any alterId for alterId={alter_id}"
        );

        let command_key = md5(&[uuid.as_slice(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21"].concat());
        let header_iv = md5(&ts_bytes.repeat(4));
        let mut plain = wire[16..].to_vec();
        Cfb::new(&command_key, &header_iv).apply(&mut plain, true);

        assert_eq!(plain[0], 1, "VMess version must be 1");
        let req_iv: [u8; 16] = plain[1..17].try_into().unwrap();
        let req_key: [u8; 16] = plain[17..33].try_into().unwrap();
        let resp_auth = plain[33];
        let options = plain[34];
        let pad_len = usize::from(plain[35] >> 4);
        let security = plain[35] & 0x0f;
        let command = plain[37];

        // port(2) + atype(1) + addr
        let addr_len = match plain[40] {
            1 => 2 + 1 + 4,
            3 => 2 + 1 + 16,
            2 => 2 + 1 + 1 + usize::from(plain[41]),
            other => panic!("unexpected VMess atyp {other}"),
        };
        let header_body_len = 38 + addr_len + pad_len;
        let expected_fnv = fnv(&plain[..header_body_len]).to_be_bytes();
        assert_eq!(
            &plain[header_body_len..header_body_len + 4],
            &expected_fnv,
            "FNV1a checksum mismatch"
        );
        ParsedLegacyHeader {
            req_key,
            req_iv,
            resp_auth,
            options,
            security,
            command,
            consumed: 16 + header_body_len + 4,
        }
    }

    /// 按 alterId=1 与 alterId=64 × 全部加密方式验证 legacy 握手、分块/无分块载荷、半关闭与分段响应头（OrynCore#62）。
    #[tokio::test]
    async fn legacy_alter_id_tcp_roundtrip_and_fragmented_response_header() {
        let ts = 1_764_000_000u64;
        for alter_id in [1u16, 64u16] {
            for cipher in [
                "aes-128-cfb",
                "aes-128-gcm",
                "chacha20-poly1305",
                "none",
                "zero",
                "auto",
            ] {
                let (pad, auth_len) = if matches!(cipher, "aes-128-gcm" | "chacha20-poly1305" | "auto") {
                    (true, true)
                } else {
                    (false, false)
                };
                let spec = VmessSpec {
                    uuid: UUID,
                    alter_id,
                    cipher: cipher.into(),
                    global_padding: pad,
                    authenticated_length: auth_len,
                };
                let target = TargetAddr::Domain("echo.example.com".into(), 443);
                let (header, session) = Session::request_at(&spec, &target, 1, ts).unwrap();

                let (mut client, mut server) = tokio::io::duplex(64 * 1024);
                client.write_all(&header).await.unwrap();
                let mut stream = session.stream(client);
                stream.write_all(b"hello-vmess-legacy").await.unwrap();
                stream.shutdown().await.unwrap();

                let mut client_wire = vec![0u8; 4096];
                let mut total = 0usize;
                loop {
                    let n = tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        server.read(&mut client_wire[total..]),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    if n == 0 {
                        break;
                    }
                    total += n;
                    if cipher != "none" && cipher != "zero" {
                        // 分块模式在半关闭后等待回显再收，不依赖 TCP FIN。
                        let parsed = parse_legacy_request(&UUID, alter_id, ts, &client_wire[..total]);
                        let mut srv_read = Body::new(
                            &spec,
                            parsed.options,
                            &parsed.req_key,
                            &parsed.req_iv,
                            &parsed.req_key,
                            &parsed.req_iv,
                        );
                        let mut rest = BytesMut::from(&client_wire[parsed.consumed..total]);
                        if let Some(cfb) = &mut srv_read.cfb {
                            cfb.apply(&mut rest, true);
                        }
                        if let Ok(Some(first)) = srv_read.decode(&mut rest) {
                            assert_eq!(first.as_ref(), b"hello-vmess-legacy");
                            if matches!(srv_read.decode(&mut rest), Ok(Some(end)) if end.is_empty()) {
                                break;
                            }
                        }
                    }
                }

                let parsed = parse_legacy_request(&UUID, alter_id, ts, &client_wire[..total]);
                assert_eq!(parsed.command, 1);
                if matches!(cipher, "none" | "zero") {
                    assert_eq!(parsed.security, 5);
                    assert_eq!(parsed.options, 0);
                    assert_eq!(&client_wire[parsed.consumed..total], b"hello-vmess-legacy");
                }

                let resp_key = hash16(&parsed.req_key, true);
                let resp_iv = hash16(&parsed.req_iv, true);
                // 包含非零 command 字节，验证 legacy 响应首部跨字节分片与之后负载的 CFB 状态切换。
                let mut resp_header = vec![parsed.resp_auth, 0, 0, 2, 0xaa, 0xbb];
                let mut resp_cfb = Cfb::new(&resp_key, &resp_iv);
                resp_cfb.apply(&mut resp_header, false);

                let mut srv_write = Body::new(
                    &spec,
                    parsed.options,
                    &resp_key,
                    &resp_iv,
                    &parsed.req_key,
                    &parsed.req_iv,
                );
                if parsed.security == 1 {
                    // legacy + aes-128-cfb 的响应首部与载荷共用同一条连续 CFB 流。
                    srv_write.cfb = Some(resp_cfb);
                }
                let mut resp_wire = resp_header;
                let payload_wire = srv_write.encode(b"reply-from-legacy-peer").unwrap();
                resp_wire.extend_from_slice(&payload_wire);
                if parsed.options & 1 != 0 {
                    resp_wire.extend_from_slice(&srv_write.encode(&[]).unwrap());
                }

                // 按小分片写回（先写 3 字节破坏首个 read>=4 假设，再写剩余字节），测试响应头分段解密。
                let split = 3usize.min(resp_wire.len());
                server.write_all(&resp_wire[..split]).await.unwrap();
                server.flush().await.unwrap();
                tokio::task::yield_now().await;
                server.write_all(&resp_wire[split..]).await.unwrap();
                server.shutdown().await.unwrap();

                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"reply-from-legacy-peer", "alter_id={alter_id} cipher={cipher}");
            }
        }
    }

    #[tokio::test]
    async fn legacy_alter_id_udp_and_bad_response_auth_rejected() {
        let ts = 1_764_000_123u64;
        for cipher in ["aes-128-cfb", "aes-128-gcm", "none", "zero"] {
            let spec = VmessSpec {
                uuid: UUID,
                alter_id: 64,
                cipher: cipher.into(),
                global_padding: false,
                authenticated_length: false,
            };
            let target = TargetAddr::Ip("198.51.100.9:53".parse().unwrap());
            let (header, session) = Session::request_at(&spec, &target, 2, ts).unwrap();
            let parsed = parse_legacy_request(&UUID, 64, ts, &header);
            assert_eq!(parsed.command, 2);
            assert_ne!(parsed.options & 1, 0, "UDP must chunk even for {cipher}");

            let (mut client, mut server) = tokio::io::duplex(4096);
            client.write_all(&header).await.unwrap();
            let mut stream = session.stream(client);
            stream.write_all(b"dns-query").await.unwrap();
            stream.flush().await.unwrap();

            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let mut rest = BytesMut::from(&buf[parsed.consumed..n]);
            let mut srv_read = Body::new(
                &spec,
                parsed.options,
                &parsed.req_key,
                &parsed.req_iv,
                &parsed.req_key,
                &parsed.req_iv,
            );
            if let Some(cfb) = &mut srv_read.cfb {
                cfb.apply(&mut rest, true);
            }
            assert_eq!(srv_read.decode(&mut rest).unwrap().unwrap().as_ref(), b"dns-query");

            // 错误的 response auth 字节必须拒绝
            let resp_key = hash16(&parsed.req_key, true);
            let resp_iv = hash16(&parsed.req_iv, true);
            let mut bad_resp = [parsed.resp_auth ^ 0xff, 0, 0, 0];
            Cfb::new(&resp_key, &resp_iv).apply(&mut bad_resp, false);
            server.write_all(&bad_resp).await.unwrap();
            server.flush().await.unwrap();
            let mut out = [0u8; 16];
            assert!(stream.read(&mut out).await.is_err());
        }
    }
}
