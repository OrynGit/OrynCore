//! AnyTLS 填充方案，适配 anytls/sing-anytls padding/padding.go。
//! commit 0cc58ccbefd0ba91ddb73222641250165206234a（v0.0.8）。
//! Copyright (C) 2025 anytls <github.com/anytls>
//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use ring::rand::{SecureRandom, SystemRandom};
pub(super) const DEFAULT:&str="stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
pub(super) struct Scheme {
    stop: usize,
    sizes: HashMap<usize, Vec<Option<(usize, usize)>>>,
}
impl Scheme {
    /// 解析服务端推送的填充方案；规则与 sing-anytls 一致：行内没有 `=` 的忽略，
    /// 无法解析的区间忽略，`min > max` 时交换，`stop` 缺失或不是数字则整个方案无效。
    /// 与 sing-anytls 不同的是各项数值有上限（方案总长、`stop`、区间大小、每项条数），超出的部分按上限截断，
    /// 保证填充的内存和 CPU 有界。方案无效时返回 None，调用方保持原方案，**不能**因此关闭会话。
    pub(super) fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() > 4096 {
            return None;
        }
        let raw = std::str::from_utf8(raw).ok()?;
        let mut stop = None;
        let mut sizes = HashMap::new();
        for line in raw.split('\n') {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if k == "stop" {
                stop = v.parse::<usize>().ok().map(|n| n.min(64));
                continue;
            }
            let Ok(index) = k.parse::<usize>() else {
                continue;
            };
            if index > 64 {
                continue;
            }
            let mut parts = Vec::new();
            for part in v.split(',').take(16) {
                if part == "c" {
                    parts.push(None);
                    continue;
                }
                let Some((a, b)) = part.split_once('-') else {
                    continue;
                };
                let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) else {
                    continue;
                };
                let (a, b) = (a.min(b), a.max(b));
                if a == 0 {
                    continue;
                }
                parts.push(Some((a.min(4096), b.min(4096))));
            }
            sizes.insert(index, parts);
        }
        Some(Self { stop: stop?, sizes })
    }
    /// 第 `index` 次写入起不再填充。
    pub(super) fn stopped(&self, index: usize) -> bool {
        index >= self.stop
    }
    pub(super) fn encode(&self, index: usize, wire: Vec<u8>) -> io::Result<Vec<Vec<u8>>> {
        if index >= self.stop {
            return Ok(vec![wire]);
        }
        let Some(sizes) = self.sizes.get(&index) else {
            return Ok(vec![wire]);
        };
        let mut out = Vec::new();
        let mut wire = wire.as_slice();
        for size in sizes {
            let Some((min, max)) = size else {
                if wire.is_empty() {
                    break;
                }
                continue;
            };
            let mut random = [0; 2];
            SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| err("random source failed"))?;
            // 与 sing-anytls `GenerateRecordPayloadSizes` 一致：rand.Int(max-min) + min，即 [min, max)；
            // 写入序号同样从 1 起（pktCounter.Add(1)），方案里的 0 号条目参考实现也不会用到
            let n = if max == min {
                *min
            } else {
                min + (u16::from_be_bytes(random) as usize % (max - min))
            };
            let used = wire.len().min(n);
            let mut record = wire[..used].to_vec();
            wire = &wire[used..];
            let pad = n - used;
            if pad >= 7 || used == 0 {
                let payload = if used == 0 { n } else { pad - 7 };
                record.push(0);
                record.extend([0; 4]);
                record.extend((payload as u16).to_be_bytes());
                record.resize(record.len() + payload, 0);
            }
            out.push(record);
        }
        if !wire.is_empty() {
            out.push(wire.to_vec());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn untrusted_updates_are_bounded_and_keep_original_frames() {
        // 缺 stop、不是数字、方案过长：无效，调用方保持原方案
        for raw in ["1=2-3", "stop=x\n1=2-3", ""] {
            assert!(Scheme::parse(raw.as_bytes()).is_none(), "{raw:?}");
        }
        assert!(Scheme::parse(&[b'a'; 4097]).is_none());
        // 与 sing-anytls 一致的宽容：交换 min / max、忽略坏区间和没有 = 的行、不认识的键
        let s = Scheme::parse(b"stop=65\n\nnoise\nx=1\n1=4-2,bad,0-5,3-3\n2=1-99999").unwrap();
        assert_eq!(s.stop, 64);
        assert_eq!(s.sizes[&1], vec![Some((2, 4)), Some((3, 3))]);
        assert_eq!(s.sizes[&2], vec![Some((1, 4096))]);
        let s = Scheme::parse(b"stop=2\n1=20-20,c,30-30").unwrap();
        let wire = vec![2, 0, 0, 0, 1, 0, 3, 1, 2, 3];
        let records = s.encode(1, wire.clone()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(&records[0][..wire.len()], wire);
        assert_eq!(records[0].len(), 20);
        assert_eq!(s.encode(2, wire.clone()).unwrap(), vec![wire]);
    }
}
