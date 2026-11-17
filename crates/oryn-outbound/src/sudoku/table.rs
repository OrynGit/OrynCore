// 线格式移植自 MetaCubeX/mihomo transport/sudoku/obfs/sudoku/{grid,table,layout,ascii_mode,encode,packed}.go
// @ 88dcbf7f1614a67c3b36b848ee3592dfa92ada36。Copyright (C) MetaCubeX contributors.
// SPDX-License-Identifier: GPL-3.0-or-later
// Oryn 为 Extension 使用固定大小网格位集合；每字节保留至多 8 个合法谜面，不复制大哈希表。
use super::{bad, go_rng::GoRand};
use std::{
    io,
    sync::{Arc, OnceLock},
};
type Grid = [u8; 16];
struct Grids {
    grids: Vec<Grid>,
    masks: [[u64; 5]; 64],
}
fn grids() -> &'static Grids {
    static ALL: OnceLock<Grids> = OnceLock::new();
    ALL.get_or_init(|| {
        fn generate(at: usize, g: &mut Grid, out: &mut Vec<Grid>) {
            if at == 16 {
                out.push(*g);
                return;
            }
            let (row, col) = (at / 4, at % 4);
            for n in 1..=4 {
                if (0..4).any(|i| g[row * 4 + i] == n || g[i * 4 + col] == n) {
                    continue;
                }
                if (0..2)
                    .any(|r| (0..2).any(|c| g[((row / 2) * 2 + r) * 4 + (col / 2) * 2 + c] == n))
                {
                    continue;
                }
                g[at] = n;
                generate(at + 1, g, out);
                g[at] = 0;
            }
        }
        let mut out = Vec::with_capacity(288);
        generate(0, &mut [0; 16], &mut out);
        assert_eq!(out.len(), 288);
        let mut masks = [[0; 5]; 64];
        for (i, g) in out.iter().enumerate() {
            for (pos, val) in g.iter().enumerate() {
                masks[(usize::from(*val) - 1) * 16 + pos][i / 64] |= 1u64 << (i % 64);
            }
        }
        Grids { grids: out, masks }
    })
}
pub struct Mapping {
    pub puzzles: Vec<Vec<[u8; 4]>>,
    inverse: [u16; 288],
}
impl Mapping {
    pub fn new(seed: &str) -> Arc<Self> {
        let g = grids();
        let hash = ring::digest::digest(&ring::digest::SHA256, seed.as_bytes());
        let seed = i64::from_be_bytes(hash.as_ref()[..8].try_into().unwrap());
        let mut permutation: Vec<_> = (0..288).collect();
        GoRand::new(seed).shuffle(&mut permutation);
        let mut puzzles = Vec::with_capacity(256);
        let mut inverse = [256; 288];
        for (byte, index) in permutation[..256].iter().copied().enumerate() {
            inverse[index] = byte as u16;
            let grid = g.grids[index];
            let mut choices = Vec::with_capacity(8);
            'done: for a in 0..13 {
                for b in a + 1..14 {
                    for c in b + 1..15 {
                        for d in c + 1..16 {
                            let hints = [
                                (grid[a] - 1) * 16 + a as u8,
                                (grid[b] - 1) * 16 + b as u8,
                                (grid[c] - 1) * 16 + c as u8,
                                (grid[d] - 1) * 16 + d as u8,
                            ];
                            if unique(&hints).is_some() {
                                choices.push(hints);
                                if choices.len() == 8 {
                                    break 'done;
                                }
                            }
                        }
                    }
                }
            }
            assert!(!choices.is_empty());
            puzzles.push(choices);
        }
        Arc::new(Self { puzzles, inverse })
    }
    pub fn decode(&self, hints: &[u8; 4]) -> io::Result<u8> {
        let index = unique(hints).ok_or_else(|| bad("invalid Sudoku puzzle"))?;
        u8::try_from(self.inverse[index]).map_err(|_| bad("unmapped Sudoku puzzle"))
    }
}
fn unique(hints: &[u8; 4]) -> Option<usize> {
    let masks = &grids().masks;
    // 四个提示的位集合求交：解码每 4 个线上字节调用一次，是 Sudoku 下行的热点。
    // 固定 5 个字（288 个网格），去掉迭代器与提前返回分支，让编译器展开。
    let [a, b, c, d] = hints.map(|h| &masks[usize::from(h & 63)]);
    let mut found = 0u32;
    let mut index = 0usize;
    for word in 0..5 {
        let value = a[word] & b[word] & c[word] & d[word];
        found += value.count_ones();
        index |= (word * 64 + value.trailing_zeros() as usize) * usize::from(value != 0);
    }
    if found == 1 {
        Some(index)
    } else {
        None
    }
}
#[derive(Clone)]
pub struct Layout {
    pub encode: [u8; 64],
    pub decode: [Option<u8>; 256],
    pub pads: Vec<u8>,
    pub marker: u8,
}
impl Layout {
    pub fn new(ascii: bool, pattern: &str) -> Self {
        let cleaned = pattern.replace(' ', "");
        let pattern = cleaned.as_str();
        let mut encode = [0; 64];
        let mut pads = Vec::new();
        let marker;
        if ascii {
            for (group, b) in encode.iter_mut().enumerate() {
                *b = if group == 63 { 10 } else { 64 + group as u8 };
            }
            pads.extend(32..64);
            marker = 63;
        } else if pattern.is_empty() {
            for (group, b) in encode.iter_mut().enumerate() {
                *b = ((group as u8 & 0x30) << 1) | (group as u8 & 15);
            }
            for n in 0..8 {
                pads.push(0x80 + n);
                pads.push(0x10 + n);
            }
            marker = 0x80;
        } else {
            let bits = |symbol| {
                pattern
                    .bytes()
                    .enumerate()
                    .filter_map(move |(i, b)| (b == symbol).then_some(7 - i))
                    .collect::<Vec<_>>()
            };
            let x = bits(b'x');
            let p = bits(b'p');
            let v = bits(b'v');
            let mask = (1 << x[0]) | (1 << x[1]);
            for (group, b) in encode.iter_mut().enumerate() {
                let val = group >> 4;
                let pos = group & 15;
                *b = mask;
                *b |= (((val >> 1) & 1) as u8) << p[0];
                *b |= ((val & 1) as u8) << p[1];
                for (i, bit) in v.iter().enumerate() {
                    *b |= (((pos >> (3 - i)) & 1) as u8) << bit;
                }
            }
            for bit in x {
                for b in encode {
                    let pad = b & !(1 << bit);
                    if pad.count_ones() >= 5 && !pads.contains(&pad) {
                        pads.push(pad);
                    }
                }
            }
            pads.sort_unstable();
            marker = pads[0];
        }
        let mut decode = [None; 256];
        for (group, b) in encode.iter().enumerate() {
            decode[usize::from(*b)] = Some(group as u8);
        }
        Self {
            encode,
            decode,
            pads,
            marker,
        }
    }
}
pub struct Table {
    pub map: Arc<Mapping>,
    pub up: Layout,
    pub down: Layout,
    pub hint: u32,
}
impl Table {
    pub fn new(seed: &str, mode: &str, pattern: &str, map: Arc<Mapping>) -> Self {
        let up = mode == "prefer_ascii" || mode == "up_ascii_down_entropy";
        let down = mode == "prefer_ascii" || mode == "up_entropy_down_ascii";
        let material = [
            "sudoku-table-hint",
            seed,
            mode,
            if up { "" } else { pattern },
            if down { "" } else { pattern },
        ]
        .join("\0");
        let hash = ring::digest::digest(&ring::digest::SHA256, material.as_bytes());
        Self {
            map,
            up: Layout::new(up, pattern),
            down: Layout::new(down, pattern),
            hint: u32::from_be_bytes(hash.as_ref()[..4].try_into().unwrap()),
        }
    }
    pub fn encode(&self, input: &[u8], padding: u8) -> io::Result<Vec<u8>> {
        use rand::{Rng, SeedableRng};
        let mut out = Vec::with_capacity(input.len() * 6 + 1);
        // 填充长度、谜面选择和提示顺序只是线上形态的随机化，不是密钥材料（mihomo 用的也是 math/rand）：
        // 每次调用从线程本地 CSPRNG 取一个种子，再用 xoshiro 取数。每个明文字节要取 6 次以上随机数，
        // 逐次从 ChaCha 取在主机剖析里比编码本身还重。
        let mut rng = rand::rngs::SmallRng::from_rng(&mut rand::rng());
        let padded = padding > 0;
        let rate = u32::from(padding);
        for byte in input {
            if padded && rng.random_range(0..100u32) < rate {
                out.push(self.up.pads[rng.random_range(0..self.up.pads.len())]);
            }
            let choices = &self.map.puzzles[usize::from(*byte)];
            let mut puzzle = choices[rng.random_range(0..choices.len())];
            for i in (1..4).rev() {
                puzzle.swap(i, rng.random_range(0..=i));
            }
            for hint in puzzle {
                if padded && rng.random_range(0..100u32) < rate {
                    out.push(self.up.pads[rng.random_range(0..self.up.pads.len())]);
                }
                out.push(self.up.encode[usize::from(hint)]);
            }
        }
        Ok(out)
    }
}
pub struct Decoder {
    table: Arc<Table>,
    packed: bool,
    hints: [u8; 4],
    used: usize,
    bits: u32,
    count: u8,
}
impl Decoder {
    pub fn new(table: Arc<Table>, packed: bool) -> Self {
        Self {
            table,
            packed,
            hints: [0; 4],
            used: 0,
            bits: 0,
            count: 0,
        }
    }
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        for wire in input {
            let Some(group) = self.table.down.decode[usize::from(*wire)] else {
                if self.packed && *wire == self.table.down.marker {
                    self.bits = 0;
                    self.count = 0;
                }
                continue;
            };
            if self.packed {
                self.bits = (self.bits << 6) | u32::from(group);
                self.count += 6;
                if self.count >= 8 {
                    self.count -= 8;
                    out.push((self.bits >> self.count) as u8);
                    self.bits &= (1 << self.count) - 1;
                }
            } else {
                self.hints[self.used] = group;
                self.used += 1;
                if self.used == 4 {
                    out.push(self.table.map.decode(&self.hints)?);
                    self.used = 0;
                }
            }
        }
        Ok(())
    }
    pub fn incomplete(&self) -> bool {
        !self.packed && self.used != 0
    }
}
