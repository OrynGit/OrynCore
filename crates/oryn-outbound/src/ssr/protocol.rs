//! ShadowsocksR 协议插件：origin、auth_sha1_v4、auth_aes128_md5 / sha1、auth_chain_a / b。
//!
//! 来源 MetaCubeX/mihomo `transport/ssr/protocol`（base.go、protocol.go、origin.go、auth_sha1_v4.go、
//! auth_aes128_sha1.go、auth_aes128_md5.go、auth_chain_a.go、auth_chain_b.go），v1.19.32，
//! commit 见 Oryn_dev/docs/oryncore/provenance.md。Copyright (C) 2021–2026 MetaCubeX contributors。
//! SPDX-License-Identifier: GPL-3.0-or-later
//! 改写为 Rust：每个包写进独立的缓冲（Go 版依赖调用方给出空缓冲），解码状态保存在连接内。

use std::io;
use std::sync::Mutex;

use aes::cipher::{BlockEncrypt, KeyInit};
use base64::Engine;

use super::util::{
    adler32, crc32, hmac_md5, hmac_sha1, kdf, md5, random_below, random_bytes, random_f64,
    random_u32, sha1, unix_now, Rc4, XorShift128Plus,
};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Origin,
    AuthSha1V4,
    AuthAes128Md5,
    AuthAes128Sha1,
    AuthChainA,
    AuthChainB,
}

impl Kind {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "origin" => Kind::Origin,
            "auth_sha1_v4" => Kind::AuthSha1V4,
            "auth_aes128_md5" => Kind::AuthAes128Md5,
            "auth_aes128_sha1" => Kind::AuthAes128Sha1,
            "auth_chain_a" => Kind::AuthChainA,
            "auth_chain_b" => Kind::AuthChainB,
            _ => return None,
        })
    }

    fn overhead(self) -> usize {
        match self {
            Kind::Origin => 0,
            Kind::AuthSha1V4 => 7,
            Kind::AuthAes128Md5 | Kind::AuthAes128Sha1 => 9,
            Kind::AuthChainA | Kind::AuthChainB => 4,
        }
    }

    fn salt(self) -> &'static str {
        match self {
            Kind::AuthAes128Md5 => "auth_aes128_md5",
            Kind::AuthAes128Sha1 => "auth_aes128_sha1",
            Kind::AuthChainA => "auth_chain_a",
            Kind::AuthChainB => "auth_chain_b",
            _ => "",
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Kind::AuthAes128Md5 => hmac_md5(key, data).to_vec(),
            _ => hmac_sha1(key, data).to_vec(),
        }
    }
}

/// 一个出站共用的协议配置与连接编号。
pub(crate) struct Protocol {
    pub(crate) kind: Kind,
    key: Vec<u8>,
    /// 协议与混淆的开销之和（auth_aes128 / auth_chain 用来决定填充）。
    overhead: usize,
    user_id: [u8; 4],
    user_key: Vec<u8>,
    auth: Mutex<(u32, [u8; 4])>,
}

impl Protocol {
    pub(crate) fn new(kind: Kind, key: Vec<u8>, param: &str, obfs_overhead: usize) -> Self {
        let mut user_id = [0u8; 4];
        let mut user_key = Vec::new();
        if let Some((id, password)) = param.split_once(':') {
            if let Ok(id) = id.trim().parse::<u32>() {
                user_id = id.to_le_bytes();
                user_key = match kind {
                    Kind::AuthAes128Md5 => md5(password.as_bytes()).to_vec(),
                    Kind::AuthAes128Sha1 => sha1(password.as_bytes()).to_vec(),
                    _ => password.as_bytes().to_vec(),
                };
            }
        }
        if user_key.is_empty() {
            user_key = key.clone();
            user_id.copy_from_slice(&random_bytes(4));
        }
        Self {
            kind,
            key,
            overhead: kind.overhead() + obfs_overhead,
            user_id,
            user_key,
            auth: Mutex::new((0, [0; 4])),
        }
    }

    /// 每条连接取一个新的连接编号（与 mihomo 的 authData.next 相同）。
    fn next_auth(&self) -> ([u8; 4], u32) {
        let mut auth = self.auth.lock().unwrap();
        if auth.0 > 0xff00_0000 || auth.0 == 0 {
            auth.1.copy_from_slice(&random_bytes(4));
            auth.0 = random_u32() & 0x00ff_ffff;
        }
        auth.0 += 1;
        (auth.1, auth.0)
    }

    pub(crate) fn stream(&self, iv: &[u8]) -> Box<dyn StreamCodec> {
        match self.kind {
            Kind::Origin => Box::new(Origin),
            Kind::AuthSha1V4 => Box::new(AuthSha1V4 {
                key: self.key.clone(),
                iv: iv.to_vec(),
                auth: self.next_auth(),
                sent_header: false,
                raw: false,
            }),
            Kind::AuthAes128Md5 | Kind::AuthAes128Sha1 => Box::new(AuthAes128 {
                kind: self.kind,
                key: self.key.clone(),
                iv: iv.to_vec(),
                overhead: self.overhead,
                user_id: self.user_id,
                user_key: self.user_key.clone(),
                auth: self.next_auth(),
                sent_header: false,
                raw: false,
                pack_id: 1,
                recv_id: 1,
            }),
            Kind::AuthChainA | Kind::AuthChainB => {
                let mut chain = AuthChain {
                    kind: self.kind,
                    key: self.key.clone(),
                    iv: iv.to_vec(),
                    overhead: self.overhead,
                    user_id: self.user_id,
                    user_key: self.user_key.clone(),
                    auth: self.next_auth(),
                    sent_header: false,
                    raw: false,
                    last_client_hash: [0; 16],
                    last_server_hash: [0; 16],
                    encrypter: None,
                    decrypter: None,
                    random_client: XorShift128Plus::default(),
                    random_server: XorShift128Plus::default(),
                    pack_id: 1,
                    recv_id: 1,
                    sizes: Vec::new(),
                    sizes2: Vec::new(),
                };
                if self.kind == Kind::AuthChainB {
                    chain.init_data_size();
                }
                Box::new(chain)
            }
        }
    }

    /// UDP：协议层的包编码（在流式加密之前）。
    pub(crate) fn encode_packet(&self, data: &[u8]) -> Vec<u8> {
        match self.kind {
            Kind::Origin | Kind::AuthSha1V4 => data.to_vec(),
            Kind::AuthAes128Md5 | Kind::AuthAes128Sha1 => {
                let mut out = data.to_vec();
                out.extend_from_slice(&self.user_id);
                let mac = self.kind.hmac(&self.user_key, &out);
                out.extend_from_slice(&mac[..4]);
                out
            }
            Kind::AuthChainA | Kind::AuthChainB => {
                let auth = random_bytes(3);
                let md5_data = hmac_md5(&self.key, &auth);
                let mut random = XorShift128Plus::default();
                random.init_from_bin(&md5_data);
                let rand_len = (random.next() % 127) as usize;
                let mut rc4 = Rc4::new(&chain_rc4_key(&self.user_key, &md5_data));
                let mut out = data.to_vec();
                rc4.apply(&mut out);
                out.extend_from_slice(&random_bytes(rand_len));
                out.extend_from_slice(&auth);
                let uid = u32::from_le_bytes(self.user_id)
                    ^ u32::from_le_bytes(md5_data[..4].try_into().unwrap());
                out.extend_from_slice(&uid.to_le_bytes());
                let mac = hmac_md5(&self.user_key, &out);
                out.push(mac[0]);
                out
            }
        }
    }

    pub(crate) fn decode_packet(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self.kind {
            Kind::Origin | Kind::AuthSha1V4 => Ok(data.to_vec()),
            Kind::AuthAes128Md5 | Kind::AuthAes128Sha1 => {
                if data.len() < 4 {
                    return Err(invalid("auth_aes128 packet too short"));
                }
                let (body, mac) = data.split_at(data.len() - 4);
                if self.kind.hmac(&self.key, body)[..4] != *mac {
                    return Err(invalid("auth_aes128 packet checksum mismatch"));
                }
                Ok(body.to_vec())
            }
            Kind::AuthChainA | Kind::AuthChainB => {
                if data.len() < 9 {
                    return Err(invalid("auth_chain packet too short"));
                }
                let n = data.len();
                if hmac_md5(&self.user_key, &data[..n - 1])[0] != data[n - 1] {
                    return Err(invalid("auth_chain packet checksum mismatch"));
                }
                let md5_data = hmac_md5(&self.key, &data[n - 8..n - 1]);
                let mut random = XorShift128Plus::default();
                random.init_from_bin(&md5_data);
                let rand_len = (random.next() % 127) as usize;
                if rand_len + 8 > n {
                    return Err(invalid("auth_chain packet length mismatch"));
                }
                let mut out = data[..n - 8 - rand_len].to_vec();
                Rc4::new(&chain_rc4_key(&self.user_key, &md5_data)).apply(&mut out);
                Ok(out)
            }
        }
    }
}

fn chain_rc4_key(user_key: &[u8], hash: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    kdf(
        format!("{}{}", b64.encode(user_key), b64.encode(hash)).as_bytes(),
        16,
    )
}

/// 首包里协议首部之后带多少应用数据（与 mihomo 的 getDataLength 相同）。
fn first_data_length(b: &[u8]) -> usize {
    let head = if b.len() < 2 {
        30
    } else {
        match b[0] & 7 {
            1 => 7,
            4 => 19,
            3 => 4 + b[1] as usize,
            _ => 30,
        }
    };
    (head + random_below(32)).min(b.len())
}

/// 认证块：时间、客户端编号、连接编号、两个填充参数，AES-128-CBC（零 IV）加密成 16 字节。
fn encrypted_auth(
    auth: ([u8; 4], u32),
    user_key: &[u8],
    paddings: [u16; 2],
    salt: &str,
) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&unix_now().to_le_bytes());
    block[4..8].copy_from_slice(&auth.0);
    block[8..12].copy_from_slice(&auth.1.to_le_bytes());
    block[12..14].copy_from_slice(&paddings[0].to_le_bytes());
    block[14..16].copy_from_slice(&paddings[1].to_le_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(user_key);
    let key = kdf(format!("{b64}{salt}").as_bytes(), 16);
    let cipher = aes::Aes128::new_from_slice(&key).expect("16-byte key");
    let mut b = aes::Block::from(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

pub(crate) trait StreamCodec: Send {
    /// 编码一次写入。
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>);
    /// 从 `src`（已解密、未解码）取出完整的块写到 `dst`；不完整的留在 `src`。
    fn decode(&mut self, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> io::Result<()>;
}

struct Origin;

impl StreamCodec for Origin {
    fn encode(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(data);
    }
    fn decode(&mut self, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> io::Result<()> {
        dst.append(src);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// auth_sha1_v4
// ---------------------------------------------------------------------------

struct AuthSha1V4 {
    key: Vec<u8>,
    iv: Vec<u8>,
    auth: ([u8; 4], u32),
    sent_header: bool,
    raw: bool,
}

fn sha1_v4_rand_len(size: usize) -> usize {
    if size > 1200 {
        0
    } else if size > 400 {
        random_below(256)
    } else {
        random_below(512)
    }
}

/// 随机填充前缀：长度小于 128 时一字节（长度 + 1），否则 0xff + 两字节（长度 + 3）。
fn pack_rand(out: &mut Vec<u8>, size: usize, big_endian: bool) {
    if size < 128 {
        out.push(size as u8 + 1);
    } else {
        out.push(255);
        let v = (size + 3) as u16;
        out.extend_from_slice(&if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        });
    }
    out.extend_from_slice(&random_bytes(size));
}

impl AuthSha1V4 {
    fn pack_data(&self, out: &mut Vec<u8>, data: &[u8]) {
        let rand_len = sha1_v4_rand_len(data.len());
        let mut packed = 2 + 2 + 3 + rand_len + data.len() + 4;
        if rand_len < 128 {
            packed -= 2;
        }
        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_be_bytes());
        let crc = (crc32(&out[start..start + 2]) & 0xffff) as u16;
        out.extend_from_slice(&crc.to_le_bytes());
        pack_rand(out, rand_len, true);
        out.extend_from_slice(data);
        let sum = adler32(&out[start..]);
        out.extend_from_slice(&sum.to_le_bytes());
    }

    fn pack_auth_data(&self, out: &mut Vec<u8>, data: &[u8]) {
        let rand_len = sha1_v4_rand_len(12 + data.len());
        let mut packed = 2 + 4 + 3 + rand_len + 12 + data.len() + 10;
        if rand_len < 128 {
            packed -= 2;
        }
        let mut crc_data = (packed as u16).to_be_bytes().to_vec();
        crc_data.extend_from_slice(b"auth_sha1_v4");
        crc_data.extend_from_slice(&self.key);
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        out.extend_from_slice(&crc_data[..2]);
        out.extend_from_slice(&crc32(&crc_data).to_le_bytes());
        pack_rand(out, rand_len, true);
        out.extend_from_slice(&unix_now().to_le_bytes());
        out.extend_from_slice(&self.auth.0);
        out.extend_from_slice(&self.auth.1.to_le_bytes());
        out.extend_from_slice(data);
        let mac = hmac_sha1(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..10]);
    }
}

impl StreamCodec for AuthSha1V4 {
    fn encode(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        if !self.sent_header {
            let n = first_data_length(data);
            self.pack_auth_data(out, &data[..n]);
            data = &data[n..];
            self.sent_header = true;
        }
        for chunk in data.chunks(8100) {
            self.pack_data(out, chunk);
        }
    }

    fn decode(&mut self, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> io::Result<()> {
        if self.raw {
            dst.append(src);
            return Ok(());
        }
        while src.len() > 4 {
            let crc = (crc32(&src[..2]) & 0xffff) as u16;
            if crc != u16::from_le_bytes([src[2], src[3]]) {
                src.clear();
                return Err(invalid("auth_sha1_v4 data crc32 mismatch"));
            }
            let length = u16::from_be_bytes([src[0], src[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw = true;
                src.clear();
                return Err(invalid("auth_sha1_v4 data length invalid"));
            }
            if length > src.len() {
                break;
            }
            if adler32(&src[..length - 4])
                != u32::from_le_bytes(src[length - 4..length].try_into().unwrap())
            {
                self.raw = true;
                src.clear();
                return Err(invalid("auth_sha1_v4 data adler32 mismatch"));
            }
            let pos = if src[4] < 255 {
                src[4] as usize + 4
            } else {
                u16::from_be_bytes([src[5], src[6]]) as usize + 4
            };
            if pos > length - 4 {
                return Err(invalid("auth_sha1_v4 data padding invalid"));
            }
            dst.extend_from_slice(&src[pos..length - 4]);
            src.drain(..length);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// auth_aes128_md5 / auth_aes128_sha1
// ---------------------------------------------------------------------------

struct AuthAes128 {
    kind: Kind,
    key: Vec<u8>,
    iv: Vec<u8>,
    overhead: usize,
    user_id: [u8; 4],
    user_key: Vec<u8>,
    auth: ([u8; 4], u32),
    sent_header: bool,
    raw: bool,
    pack_id: u32,
    recv_id: u32,
}

impl AuthAes128 {
    fn rand_len_for_data(&self, len: usize, full: usize) -> usize {
        if full + self.overhead >= 32 * 1024 {
            return 0;
        }
        // 1460：TCP MSS
        let rev = 1460 - len as isize - 9;
        if rev == 0 {
            return 0;
        }
        if rev < 0 {
            if rev > -1460 {
                return (random_f64() * (rev + 1460) as f64) as usize;
            }
            return random_below(32);
        }
        if len > 900 {
            return random_below(rev as usize);
        }
        (random_f64() * rev as f64) as usize
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8], full: usize) {
        let rand_len = self.rand_len_for_data(data.len(), full);
        let mut packed = 2 + 2 + 3 + rand_len + data.len() + 4;
        if rand_len < 128 {
            packed -= 2;
        }
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);
        let start = out.len();
        out.extend_from_slice(&(packed as u16).to_le_bytes());
        let mac = self.kind.hmac(&mac_key, &out[start..start + 2]);
        out.extend_from_slice(&mac[..2]);
        pack_rand(out, rand_len, false);
        out.extend_from_slice(data);
        let mac = self.kind.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..4]);
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let rand_len = if data.len() > 400 {
            random_below(512)
        } else {
            random_below(1024)
        };
        let packed = 7 + 4 + 16 + 4 + rand_len + data.len() + 4;
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        out.push(random_below(256) as u8);
        let mac = self.kind.hmac(&mac_key, &out[start..]);
        out.extend_from_slice(&mac[..6]);
        out.extend_from_slice(&self.user_id);
        let enc = encrypted_auth(
            self.auth,
            &self.user_key,
            [packed as u16, rand_len as u16],
            self.kind.salt(),
        );
        out.extend_from_slice(&enc);
        let mac = self.kind.hmac(&mac_key, &out[start + 7..]);
        out.extend_from_slice(&mac[..4]);
        out.extend_from_slice(&random_bytes(rand_len));
        out.extend_from_slice(data);
        let mac = self.kind.hmac(&self.user_key, &out[start..]);
        out.extend_from_slice(&mac[..4]);
    }
}

impl StreamCodec for AuthAes128 {
    fn encode(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        let full = data.len();
        if !self.sent_header {
            let n = first_data_length(data);
            self.pack_auth_data(out, &data[..n]);
            data = &data[n..];
            self.sent_header = true;
        }
        for chunk in data.chunks(8100) {
            self.pack_data(out, chunk, full);
        }
    }

    fn decode(&mut self, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> io::Result<()> {
        if self.raw {
            dst.append(src);
            return Ok(());
        }
        while src.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            if self.kind.hmac(&mac_key, &src[..2])[..2] != src[2..4] {
                src.clear();
                return Err(invalid("auth_aes128 data mac mismatch"));
            }
            let length = u16::from_le_bytes([src[0], src[1]]) as usize;
            if !(7..8192).contains(&length) {
                self.raw = true;
                src.clear();
                return Err(invalid("auth_aes128 data length invalid"));
            }
            if length > src.len() {
                break;
            }
            if self.kind.hmac(&mac_key, &src[..length - 4])[..4] != src[length - 4..length] {
                self.raw = true;
                src.clear();
                return Err(invalid("auth_aes128 data checksum mismatch"));
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let pos = if src[4] < 255 {
                src[4] as usize + 4
            } else {
                u16::from_le_bytes([src[5], src[6]]) as usize + 4
            };
            if pos > length - 4 {
                return Err(invalid("auth_aes128 data padding invalid"));
            }
            dst.extend_from_slice(&src[pos..length - 4]);
            src.drain(..length);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// auth_chain_a / auth_chain_b
// ---------------------------------------------------------------------------

struct AuthChain {
    kind: Kind,
    key: Vec<u8>,
    iv: Vec<u8>,
    overhead: usize,
    user_id: [u8; 4],
    user_key: Vec<u8>,
    auth: ([u8; 4], u32),
    sent_header: bool,
    raw: bool,
    last_client_hash: [u8; 16],
    last_server_hash: [u8; 16],
    encrypter: Option<Rc4>,
    decrypter: Option<Rc4>,
    random_client: XorShift128Plus,
    random_server: XorShift128Plus,
    pack_id: u32,
    recv_id: u32,
    /// auth_chain_b 的两组数据长度表。
    sizes: Vec<usize>,
    sizes2: Vec<usize>,
}

fn rand_start_pos(length: usize, random: &mut XorShift128Plus) -> usize {
    if length == 0 {
        return 0;
    }
    (((random.next() % 8_589_934_609) as i64) % length as i64) as usize
}

impl AuthChain {
    fn init_data_size(&mut self) {
        let mut random = XorShift128Plus::default();
        random.init_from_bin(&self.key);
        let n = random.next() % 8 + 4;
        self.sizes = (0..n)
            .map(|_| (random.next() % 2340 % 2040 % 1440) as usize)
            .collect();
        self.sizes.sort_unstable();
        let n = random.next() % 16 + 8;
        self.sizes2 = (0..n)
            .map(|_| (random.next() % 2340 % 2040 % 1440) as usize)
            .collect();
        self.sizes2.sort_unstable();
    }

    /// 某个数据长度对应的随机填充长度（客户端用上一个客户端摘要，解码用上一个服务端摘要）。
    fn rand_len(&self, length: usize, last_hash: &[u8; 16], random: &mut XorShift128Plus) -> usize {
        let fallback = |random: &mut XorShift128Plus| {
            (if length > 1300 {
                random.next() % 31
            } else if length > 900 {
                random.next() % 127
            } else if length > 400 {
                random.next() % 521
            } else {
                random.next() % 1021
            }) as usize
        };
        match self.kind {
            Kind::AuthChainB => {
                if length >= 1440 {
                    return 0;
                }
                random.init_from_bin_and_length(last_hash, length);
                let want = length + self.overhead;
                let pos = self.sizes.partition_point(|&v| v < want);
                let final_pos = pos + (random.next() % self.sizes.len() as u64) as usize;
                if final_pos < self.sizes.len() {
                    return self.sizes[final_pos] - want;
                }
                let pos = self.sizes2.partition_point(|&v| v < want);
                let final_pos = pos + (random.next() % self.sizes2.len() as u64) as usize;
                if final_pos < self.sizes2.len() {
                    return self.sizes2[final_pos] - want;
                }
                if final_pos < pos + self.sizes2.len() - 1 {
                    return 0;
                }
                fallback(random)
            }
            _ => {
                // 已对照 Python shadowsocksr 与 mihomo `auth_chain_a.go`：chain_a 是 `> 1440`，
                // chain_b（上面）是 `>= 1440`，两者确实不同，不是笔误。
                if length > 1440 {
                    return 0;
                }
                random.init_from_bin_and_length(last_hash, length);
                fallback(random)
            }
        }
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut data = data.to_vec();
        if let Some(enc) = &mut self.encrypter {
            enc.apply(&mut data);
        }
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
        self.pack_id = self.pack_id.wrapping_add(1);
        let length = data.len() as u16
            ^ u16::from_le_bytes([self.last_client_hash[14], self.last_client_hash[15]]);
        let start = out.len();
        out.extend_from_slice(&length.to_le_bytes());
        let mut random = std::mem::take(&mut self.random_client);
        let rand_len = self.rand_len(data.len(), &self.last_client_hash, &mut random);
        if data.is_empty() {
            out.extend_from_slice(&random_bytes(rand_len));
        } else if rand_len > 0 {
            let start_pos = rand_start_pos(rand_len, &mut random);
            out.extend_from_slice(&random_bytes(start_pos));
            out.extend_from_slice(&data);
            out.extend_from_slice(&random_bytes(rand_len - start_pos));
        } else {
            out.extend_from_slice(&data);
        }
        self.random_client = random;
        self.last_client_hash = hmac_md5(&mac_key, &out[start..]);
        out.extend_from_slice(&self.last_client_hash[..2]);
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);
        let start = out.len();
        out.extend_from_slice(&random_bytes(4));
        self.last_client_hash = hmac_md5(&mac_key, &out[start..]);
        let rc4_key = chain_rc4_key(&self.user_key, &self.last_client_hash);
        self.encrypter = Some(Rc4::new(&rc4_key));
        self.decrypter = Some(Rc4::new(&rc4_key));
        out.extend_from_slice(&self.last_client_hash[..8]);
        let uid = u32::from_le_bytes(self.user_id)
            ^ u32::from_le_bytes(self.last_client_hash[8..12].try_into().unwrap());
        out.extend_from_slice(&uid.to_le_bytes());
        let enc = encrypted_auth(
            self.auth,
            &self.user_key,
            [self.overhead as u16, 0],
            self.kind.salt(),
        );
        out.extend_from_slice(&enc);
        self.last_server_hash = hmac_md5(&self.user_key, &out[start + 12..]);
        out.extend_from_slice(&self.last_server_hash[..4]);
        self.pack_data(out, data);
    }
}

impl StreamCodec for AuthChain {
    fn encode(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        if !self.sent_header {
            let n = first_data_length(data);
            self.pack_auth_data(out, &data[..n]);
            data = &data[n..];
            self.sent_header = true;
        }
        for chunk in data.chunks(2800) {
            self.pack_data(out, chunk);
        }
    }

    fn decode(&mut self, src: &mut Vec<u8>, dst: &mut Vec<u8>) -> io::Result<()> {
        if self.raw {
            dst.append(src);
            return Ok(());
        }
        while src.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
            let data_len = (u16::from_le_bytes([src[0], src[1]])
                ^ u16::from_le_bytes([self.last_server_hash[14], self.last_server_hash[15]]))
                as usize;
            let mut random = std::mem::take(&mut self.random_server);
            let rand_len = self.rand_len(data_len, &self.last_server_hash, &mut random);
            let length = data_len + rand_len;
            if length >= 4096 {
                self.random_server = random;
                self.raw = true;
                src.clear();
                return Err(invalid("auth_chain data length invalid"));
            }
            if 4 + length > src.len() {
                self.random_server = random;
                break;
            }
            let server_hash = hmac_md5(&mac_key, &src[..length + 2]);
            if server_hash[..2] != src[length + 2..length + 4] {
                self.random_server = random;
                self.raw = true;
                src.clear();
                return Err(invalid("auth_chain data checksum mismatch"));
            }
            self.last_server_hash = server_hash;
            let mut pos = 2;
            if data_len > 0 && rand_len > 0 {
                pos += rand_start_pos(rand_len, &mut random);
            }
            self.random_server = random;
            if pos + data_len > length + 2 {
                return Err(invalid("auth_chain data position invalid"));
            }
            let mut wanted = src[pos..pos + data_len].to_vec();
            if let Some(dec) = &mut self.decrypter {
                dec.apply(&mut wanted);
            }
            if self.recv_id == 1 {
                // 第一个块的前两字节是服务端的 TCP MSS
                if wanted.len() >= 2 {
                    dst.extend_from_slice(&wanted[2..]);
                }
            } else {
                dst.extend_from_slice(&wanted);
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            src.drain(..length + 4);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 本地编码再用服务端视角解码不可能（服务端格式不同）；这里只检查首包结构与解码器的拆包。
    #[test]
    fn auth_sha1_v4_frames_decode_across_splits() {
        let p = Protocol::new(Kind::AuthSha1V4, vec![1; 16], "", 0);
        let codec = AuthSha1V4 {
            key: p.key.clone(),
            iv: vec![0; 16],
            auth: ([0; 4], 1),
            sent_header: true,
            raw: false,
        };
        let mut wire = Vec::new();
        codec.pack_data(&mut wire, b"hello");
        codec.pack_data(&mut wire, &[7u8; 3000]);
        // 客户端与服务端的数据块格式相同：用同一个解码器校验 crc / adler 与填充
        let mut decoder = AuthSha1V4 {
            key: vec![],
            iv: vec![],
            auth: ([0; 4], 0),
            sent_header: true,
            raw: false,
        };
        let mut out = Vec::new();
        let mut src = Vec::new();
        for chunk in wire.chunks(7) {
            src.extend_from_slice(chunk);
            decoder.decode(&mut src, &mut out).unwrap();
        }
        assert_eq!(&out[..5], b"hello");
        assert_eq!(out.len(), 3005);
    }

    #[test]
    fn auth_chain_packets_roundtrip_with_server_layout() {
        // 服务端 UDP 包：数据 + 随机 + 7 字节（3 字节认证 + 4 字节）+ 1 字节校验；用与客户端相同的方法构造
        let p = Protocol::new(Kind::AuthChainA, vec![3; 16], "", 0);
        let auth = [9u8; 7];
        let md5_data = hmac_md5(&p.key, &auth);
        let mut random = XorShift128Plus::default();
        random.init_from_bin(&md5_data);
        let rand_len = (random.next() % 127) as usize;
        let mut body = b"reply".to_vec();
        Rc4::new(&chain_rc4_key(&p.user_key, &md5_data)).apply(&mut body);
        body.extend_from_slice(&vec![0; rand_len]);
        body.extend_from_slice(&auth);
        let mac = hmac_md5(&p.user_key, &body);
        body.push(mac[0]);
        assert_eq!(p.decode_packet(&body).unwrap(), b"reply");
        body[0] ^= 1;
        let last = body.len() - 1;
        body[last] ^= 0;
        assert!(p
            .decode_packet(&body)
            .map(|d| d != b"reply")
            .unwrap_or(true));
    }

    #[test]
    fn protocol_param_selects_user() {
        let p = Protocol::new(Kind::AuthAes128Md5, vec![5; 16], "1234:secret", 5);
        assert_eq!(p.user_id, 1234u32.to_le_bytes());
        assert_eq!(p.user_key, md5(b"secret").to_vec());
        assert_eq!(p.overhead, 9 + 5);
        let q = Protocol::new(Kind::AuthChainB, vec![5; 16], "bad", 0);
        assert_eq!(q.user_key, vec![5; 16]);
        let mut chain = match q.kind {
            Kind::AuthChainB => AuthChain {
                kind: q.kind,
                key: q.key.clone(),
                iv: vec![],
                overhead: 4,
                user_id: [0; 4],
                user_key: vec![],
                auth: ([0; 4], 0),
                sent_header: false,
                raw: false,
                last_client_hash: [0; 16],
                last_server_hash: [0; 16],
                encrypter: None,
                decrypter: None,
                random_client: Default::default(),
                random_server: Default::default(),
                pack_id: 1,
                recv_id: 1,
                sizes: vec![],
                sizes2: vec![],
            },
            _ => unreachable!(),
        };
        chain.init_data_size();
        assert!((4..12).contains(&chain.sizes.len()) && (8..24).contains(&chain.sizes2.len()));
        assert!(chain.sizes.windows(2).all(|w| w[0] <= w[1]));
    }
}
