//! QUIC Initial 包解密与 ClientHello 重组（RFC 9001 §5、RFC 9369）。

use std::collections::BTreeMap;

use ring::aead::quic::{HeaderProtectionKey, AES_128};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf;

use crate::{client_hello_sni, Sniff};

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// CRYPTO 流重组的上限。
const MAX_CRYPTO: usize = 64 * 1024;

struct Keys {
    key: LessSafeKey,
    iv: [u8; 12],
    hp: HeaderProtectionKey,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand_label(prk: &hkdf::Prk, label: &[u8], len: usize) -> Vec<u8> {
    let full = [b"tls13 ".as_slice(), label].concat();
    let len_bytes = (len as u16).to_be_bytes();
    let label_len = [full.len() as u8];
    let info: [&[u8]; 4] = [&len_bytes, &label_len, &full, &[0u8]];
    let mut out = vec![0u8; len];
    prk.expand(&info, Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF 长度合法");
    out
}

fn initial_keys(version: u32, dcid: &[u8]) -> Option<Keys> {
    let (salt, prefix): (&[u8], &[u8]) = match version {
        V1 => (&SALT_V1, b"quic "),
        V2 => (&SALT_V2, b"quicv2 "),
        _ => return None,
    };
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let client = expand_label(&initial, b"client in", 32);
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
    let label = |s: &[u8]| [prefix, s].concat();
    let key = expand_label(&client, &label(b"key"), 16);
    let iv = expand_label(&client, &label(b"iv"), 12);
    let hp = expand_label(&client, &label(b"hp"), 16);
    Some(Keys {
        key: LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &key).ok()?),
        iv: iv.try_into().ok()?,
        hp: HeaderProtectionKey::new(&AES_128, &hp).ok()?,
    })
}

fn varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(*pos..*pos + len)?;
    let mut v = (first & 0x3f) as u64;
    for &x in &bytes[1..] {
        v = (v << 8) | x as u64;
    }
    *pos += len;
    Some(v)
}

/// 逐个输入客户端发出的 UDP 数据报，直到解析出 SNI。
#[derive(Default)]
pub struct QuicSniffer {
    crypto: BTreeMap<u64, Vec<u8>>,
    total: usize,
    /// 第一个 Initial 包的目的连接 ID 与版本，后续 Initial 包必须一致。
    dcid: Option<(u32, Vec<u8>)>,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, datagram: &[u8]) -> Sniff {
        match self.process(datagram) {
            None => Sniff::NotMatch,
            Some(()) => self.try_parse(),
        }
    }

    /// 解析数据报中的所有 Initial 包；`None` 表示不是 QUIC Initial。
    fn process(&mut self, d: &[u8]) -> Option<()> {
        let mut offset = 0;
        let mut any = false;
        while offset < d.len() {
            let pkt = &d[offset..];
            let b0 = *pkt.first()?;
            if b0 & 0x80 == 0 {
                break; // 短包头
            }
            let version = u32::from_be_bytes(pkt.get(1..5)?.try_into().ok()?);
            let ty = (b0 >> 4) & 0x03;
            let is_initial = (version == V1 && ty == 0) || (version == V2 && ty == 1);
            let mut pos = 5;
            let dcid_len = *pkt.get(pos)? as usize;
            if dcid_len > 20 {
                return None;
            }
            let dcid = pkt.get(pos + 1..pos + 1 + dcid_len)?.to_vec();
            pos += 1 + dcid_len;
            let scid_len = *pkt.get(pos)? as usize;
            pos += 1 + scid_len;
            if is_initial {
                let token = varint(pkt, &mut pos)? as usize;
                pos += token;
            } else if version != V1 && version != V2 {
                return if any { Some(()) } else { None };
            }
            let length = varint(pkt, &mut pos)? as usize;
            let end = pos.checked_add(length)?;
            if end > pkt.len() {
                return None;
            }
            if is_initial {
                match &self.dcid {
                    Some((v, id)) if *v != version || *id != dcid => {}
                    _ => {
                        self.dcid = Some((version, dcid.clone()));
                        let keys = initial_keys(version, &dcid)?;
                        let plain = decrypt(&pkt[..end], pos, &keys)?;
                        self.frames(&plain)?;
                        any = true;
                    }
                }
            }
            offset += end;
        }
        any.then_some(())
    }

    fn frames(&mut self, p: &[u8]) -> Option<()> {
        let mut pos = 0;
        while pos < p.len() {
            let ty = varint(p, &mut pos)?;
            match ty {
                0x00 | 0x01 => {} // PADDING / PING
                0x02 | 0x03 => {
                    varint(p, &mut pos)?;
                    varint(p, &mut pos)?;
                    let ranges = varint(p, &mut pos)?;
                    varint(p, &mut pos)?;
                    for _ in 0..ranges {
                        varint(p, &mut pos)?;
                        varint(p, &mut pos)?;
                    }
                    if ty == 0x03 {
                        for _ in 0..3 {
                            varint(p, &mut pos)?;
                        }
                    }
                }
                0x06 => {
                    let off = varint(p, &mut pos)?;
                    let len = varint(p, &mut pos)? as usize;
                    let data = p.get(pos..pos + len)?;
                    pos += len;
                    if self.total + len > MAX_CRYPTO {
                        return None;
                    }
                    self.total += len;
                    self.crypto.insert(off, data.to_vec());
                }
                0x1c | 0x1d => return Some(()), // CONNECTION_CLOSE
                _ => return Some(()),           // Initial 中不应出现的帧：停止解析该包
            }
        }
        Some(())
    }

    fn try_parse(&self) -> Sniff {
        // 从偏移 0 开始拼出连续的数据
        let mut stream: Vec<u8> = Vec::new();
        for (&off, data) in &self.crypto {
            let off = off as usize;
            if off > stream.len() {
                break;
            }
            let end = off + data.len();
            if end > stream.len() {
                stream.extend_from_slice(&data[stream.len() - off..]);
            }
        }
        if stream.is_empty() {
            return Sniff::NeedMore;
        }
        client_hello_sni(&stream)
    }
}

/// 去除包头保护并解密，返回明文负载。`pn_offset` 为包号的起始位置。
fn decrypt(pkt: &[u8], pn_offset: usize, keys: &Keys) -> Option<Vec<u8>> {
    let sample = pkt.get(pn_offset + 4..pn_offset + 20)?;
    let mask = keys.hp.new_mask(sample).ok()?;
    let mut header = pkt.get(..pn_offset + 4)?.to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = (header[0] & 0x03) as usize + 1;
    header.truncate(pn_offset + pn_len);
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[pn_offset + i] as u64;
    }
    let mut nonce = keys.iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut payload = pkt.get(pn_offset + pn_len..)?.to_vec();
    let plain = keys
        .key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut payload,
        )
        .ok()?;
    Some(plain.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::client_hello;

    fn put_varint(out: &mut Vec<u8>, v: u64) {
        if v < 64 {
            out.push(v as u8);
        } else if v < 16384 {
            out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
        } else {
            out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
        }
    }

    /// 测试用：按 RFC 9001 构造并加密一个客户端 Initial 包。
    fn seal_initial(version: u32, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
        let keys = initial_keys(version, dcid).unwrap();
        let ty: u8 = if version == V2 { 1 } else { 0 };
        let mut payload = frames.to_vec();
        payload.resize(payload.len().max(1162), 0); // PADDING，客户端 Initial 至少 1200 字节
        let pn_len = 4usize;
        let mut header = vec![0xc0 | (ty << 4) | (pn_len as u8 - 1)];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // SCID 长度
        put_varint(&mut header, 0); // token
        put_varint(&mut header, (pn_len + payload.len() + 16) as u64);
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());
        let mut nonce = keys.iv;
        for (i, b) in (pn as u64).to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        keys.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&header),
                &mut payload,
            )
            .unwrap();
        let mut pkt = header;
        pkt.extend_from_slice(&payload);
        let mask = keys
            .hp
            .new_mask(&pkt[pn_offset + 4..pn_offset + 20])
            .unwrap();
        pkt[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            pkt[pn_offset + i] ^= mask[1 + i];
        }
        pkt
    }

    fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06];
        put_varint(&mut f, offset as u64);
        put_varint(&mut f, data.len() as u64);
        f.extend_from_slice(data);
        f
    }

    fn handshake_bytes(sni: &str) -> Vec<u8> {
        client_hello(sni)[5..].to_vec() // 去掉 TLS 记录头
    }

    #[test]
    fn rfc9001_client_initial_keys() {
        // RFC 9001 附录 A.1 的测试向量
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, &SALT_V1).extract(&dcid);
        let client =
            hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &expand_label(&initial, b"client in", 32));
        assert_eq!(
            expand_label(&client, b"quic key", 16),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            expand_label(&client, b"quic iv", 12),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            expand_label(&client, b"quic hp", 16),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn single_packet_v1_and_v2() {
        for version in [V1, V2] {
            let hs = handshake_bytes("quic.example");
            let pkt = seal_initial(version, &[1, 2, 3, 4, 5, 6, 7, 8], 0, &crypto_frame(0, &hs));
            let mut s = QuicSniffer::new();
            assert_eq!(
                s.push(&pkt),
                Sniff::Found("quic.example".into()),
                "version {version:x}"
            );
        }
    }

    #[test]
    fn split_across_packets_out_of_order() {
        let hs = handshake_bytes("split.example");
        let (a, b) = hs.split_at(hs.len() / 2);
        let dcid = [9u8; 8];
        // 第一个包：后半段在前、PING 与 PADDING 交错；第二个包：前半段
        let mut f1 = crypto_frame(a.len(), b);
        f1.push(0x01);
        f1.push(0x00);
        let p1 = seal_initial(V1, &dcid, 0, &f1);
        let p2 = seal_initial(V1, &dcid, 1, &crypto_frame(0, a));
        let mut s = QuicSniffer::new();
        assert_eq!(s.push(&p1), Sniff::NeedMore);
        assert_eq!(s.push(&p2), Sniff::Found("split.example".into()));
    }

    #[test]
    fn rejects_non_quic() {
        let mut s = QuicSniffer::new();
        assert_eq!(s.push(b"\x16\x03\x01 not quic"), Sniff::NotMatch);
        assert_eq!(s.push(&[0x40, 1, 2, 3]), Sniff::NotMatch, "短包头");
        let mut pkt = seal_initial(
            V1,
            &[1; 8],
            0,
            &crypto_frame(0, &handshake_bytes("a.example")),
        );
        let last = pkt.len() - 1;
        pkt[last] ^= 0xff; // 破坏认证标签
        assert_eq!(QuicSniffer::new().push(&pkt), Sniff::NotMatch);
    }

    /// 用真实的 QUIC 客户端（quinn）产生 Initial 包。
    #[tokio::test]
    async fn real_quinn_initial() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(oryn_tls::quic_client_config(&[b"h3"], true).unwrap());
        let connecting = endpoint.connect(addr, "real.quic.example").unwrap();
        let handle = tokio::spawn(async move {
            let _ = connecting.await;
        });
        let mut buf = vec![0u8; 2048];
        let mut s = QuicSniffer::new();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            for _ in 0..8 {
                let (n, _) = server.recv_from(&mut buf).await.unwrap();
                match s.push(&buf[..n]) {
                    Sniff::NeedMore => continue,
                    result => return result,
                }
            }
            Sniff::NeedMore
        })
        .await;
        handle.abort();
        let _ = handle.await;
        assert_eq!(result.unwrap(), Sniff::Found("real.quic.example".into()));
    }
}
