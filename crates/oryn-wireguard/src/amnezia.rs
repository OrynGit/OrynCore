//! AmneziaWG 1.0 的线上变形：握手前垃圾包、握手消息填充、消息类型替换。
//!
//! 变形只发生在外层 UDP 数据报上，包在 boringtun 之外：发送前对 boringtun 产出的标准 WireGuard
//! 消息变形，收到后先还原为标准消息再交给 boringtun。参数含义见 AmneziaWG 文档：
//!
//! | 参数 | 作用 |
//! |---|---|
//! | `jc` / `jmin` / `jmax` | 每次握手前发送 `jc` 个随机内容的垃圾包，长度在 `jmin..=jmax` |
//! | `s1` / `s2` | 握手发起 / 响应消息前面填充的随机字节数 |
//! | `h1`–`h4` | 握手发起 / 握手响应 / Cookie 应答 / 数据消息的类型值（默认 1–4 即标准值） |

use oryn_config::AmneziaSpec;

use crate::dns::random_u64;

const INIT: u32 = 1;
const RESPONSE: u32 = 2;
const COOKIE: u32 = 3;
const DATA: u32 = 4;
const INIT_LEN: usize = 148;
const RESPONSE_LEN: usize = 92;
const COOKIE_LEN: usize = 64;
/// 数据消息最短长度（16 字节首部 + 16 字节认证标签）。
const DATA_MIN: usize = 32;

#[derive(Clone, Copy)]
pub struct Amnezia {
    spec: AmneziaSpec,
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&random_u64().to_le_bytes());
    }
    out.truncate(len);
    out
}

impl Amnezia {
    pub fn new(spec: AmneziaSpec) -> Self {
        Self { spec }
    }

    fn header(&self, kind: u32) -> u32 {
        self.spec.h[(kind - 1) as usize]
    }

    /// 发送：返回要依次发出的数据报（握手发起前先有垃圾包）。无法识别的消息原样返回。
    pub fn outgoing(&self, message: &[u8]) -> Vec<Vec<u8>> {
        let Some(kind) = standard_kind(message) else {
            return vec![message.to_vec()];
        };
        let mut out = Vec::new();
        if kind == INIT {
            let span = usize::from(self.spec.jmax.saturating_sub(self.spec.jmin)) + 1;
            for _ in 0..self.spec.jc {
                let len = usize::from(self.spec.jmin) + (random_u64() as usize) % span;
                out.push(random_bytes(len));
            }
        }
        let padding = match kind {
            INIT => usize::from(self.spec.s1),
            RESPONSE => usize::from(self.spec.s2),
            _ => 0,
        };
        let mut wire = random_bytes(padding);
        let start = wire.len();
        wire.extend_from_slice(message);
        wire[start..start + 4].copy_from_slice(&self.header(kind).to_le_bytes());
        out.push(wire);
        out
    }

    /// 接收：还原成标准 WireGuard 消息。垃圾包与无法识别的数据报返回 None。
    pub fn incoming(&self, datagram: &[u8]) -> Option<Vec<u8>> {
        let s1 = usize::from(self.spec.s1);
        let s2 = usize::from(self.spec.s2);
        // 带填充的握手消息按长度识别，再核对填充之后的类型值
        for (padding, kind, len) in [(s2, RESPONSE, RESPONSE_LEN), (s1, INIT, INIT_LEN)] {
            if padding > 0
                && datagram.len() == padding + len
                && self.type_at(datagram, padding) == Some(self.header(kind))
            {
                return Some(restore(&datagram[padding..], kind));
            }
        }
        let value = self.type_at(datagram, 0)?;
        let (kind, ok) = if value == self.header(DATA) {
            (DATA, datagram.len() >= DATA_MIN)
        } else if value == self.header(COOKIE) {
            (COOKIE, datagram.len() == COOKIE_LEN)
        } else if value == self.header(RESPONSE) && s2 == 0 {
            (RESPONSE, datagram.len() == RESPONSE_LEN)
        } else if value == self.header(INIT) && s1 == 0 {
            (INIT, datagram.len() == INIT_LEN)
        } else {
            return None;
        };
        ok.then(|| restore(datagram, kind))
    }

    fn type_at(&self, datagram: &[u8], at: usize) -> Option<u32> {
        let bytes = datagram.get(at..at + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }
}

fn restore(message: &[u8], kind: u32) -> Vec<u8> {
    let mut out = message.to_vec();
    out[0..4].copy_from_slice(&kind.to_le_bytes());
    out
}

/// boringtun 产出的标准消息类型。
fn standard_kind(message: &[u8]) -> Option<u32> {
    let kind = u32::from_le_bytes(message.get(0..4)?.try_into().ok()?);
    let len = message.len();
    match kind {
        INIT if len == INIT_LEN => Some(INIT),
        RESPONSE if len == RESPONSE_LEN => Some(RESPONSE),
        COOKIE if len == COOKIE_LEN => Some(COOKIE),
        DATA if len >= DATA_MIN => Some(DATA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> AmneziaSpec {
        AmneziaSpec {
            jc: 5,
            jmin: 40,
            jmax: 90,
            s1: 20,
            s2: 33,
            h: [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888],
        }
    }

    fn message(kind: u32, len: usize) -> Vec<u8> {
        let mut m = vec![0xAB; len];
        m[0..4].copy_from_slice(&kind.to_le_bytes());
        m[4] = 0;
        m
    }

    #[test]
    fn roundtrip_all_message_types() {
        let a = Amnezia::new(spec());
        for (kind, len) in [
            (INIT, INIT_LEN),
            (RESPONSE, RESPONSE_LEN),
            (COOKIE, COOKIE_LEN),
            (DATA, 32),
            (DATA, 1400),
        ] {
            let original = message(kind, len);
            let sent = a.outgoing(&original);
            let wire = sent.last().unwrap();
            // 类型值被替换，握手消息被填充
            let padding = match kind {
                INIT => 20,
                RESPONSE => 33,
                _ => 0,
            };
            assert_eq!(wire.len(), len + padding);
            assert_eq!(
                &wire[padding..padding + 4],
                &spec().h[(kind - 1) as usize].to_le_bytes()
            );
            assert_eq!(a.incoming(wire).unwrap(), original, "kind {kind} len {len}");
        }
    }

    #[test]
    fn junk_only_before_handshake_initiation() {
        let a = Amnezia::new(spec());
        let sent = a.outgoing(&message(INIT, INIT_LEN));
        assert_eq!(sent.len(), 1 + 5);
        for junk in &sent[..5] {
            assert!((40..=90).contains(&junk.len()), "{}", junk.len());
            // 垃圾包对接收端是不可识别的数据报
            assert!(a.incoming(junk).is_none());
        }
        for (kind, len) in [(RESPONSE, RESPONSE_LEN), (COOKIE, COOKIE_LEN), (DATA, 100)] {
            assert_eq!(a.outgoing(&message(kind, len)).len(), 1);
        }
    }

    #[test]
    fn rejects_standard_and_malformed_datagrams() {
        let a = Amnezia::new(spec());
        // 标准类型值（1–4）在自定义头部下不是合法消息
        for kind in 1..=4u32 {
            assert!(a.incoming(&message(kind, 200)).is_none(), "{kind}");
        }
        assert!(a.incoming(&[]).is_none());
        assert!(a.incoming(&[1, 2, 3]).is_none());
        // 长度不符的握手消息
        let wire = a.outgoing(&message(RESPONSE, RESPONSE_LEN)).pop().unwrap();
        assert!(a.incoming(&wire[..wire.len() - 1]).is_none());
        // 数据消息太短
        let mut short = message(DATA, 20);
        short[0..4].copy_from_slice(&spec().h[3].to_le_bytes());
        assert!(a.incoming(&short).is_none());
    }

    #[test]
    fn default_headers_without_padding_are_plain_wireguard() {
        let plain = AmneziaSpec {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s1: 0,
            s2: 0,
            h: [1, 2, 3, 4],
        };
        let a = Amnezia::new(plain);
        for (kind, len) in [
            (INIT, INIT_LEN),
            (RESPONSE, RESPONSE_LEN),
            (COOKIE, COOKIE_LEN),
            (DATA, 64),
        ] {
            let m = message(kind, len);
            let sent = a.outgoing(&m);
            assert_eq!(sent, vec![m.clone()]);
            assert_eq!(a.incoming(&m).unwrap(), m);
        }
    }
}
