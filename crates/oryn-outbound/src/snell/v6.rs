//! Snell v6 的记录层：default（流量画像）、unshaped（v4 式 AEAD，无填充）、unsafe-raw（不加密）。
//!
//! 移植自 sagernet/sing-snell snellv6（profile.go、salt.go、mixing.go、shaped.go、record.go、handshake.go），
//! commit 20f2eaec77c328b7eb7e937fa9c894ee9c8a0057。
//! Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>
//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! 画像（Profile）由 PSK 经 BLAKE2b-256 派生：记录前缀长度、填充长度与内容、首部 / 载荷与填充的交错方式、
//! 分块大小都是 PSK 与记录序号的确定函数，双方各自计算。Go 代码里的整数运算都是 64 位回绕，这里一律用 wrapping_*。
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{Blake2b, Digest};
use bytes::{Buf, BytesMut};

use super::{Aead, Frame, HEADER_CIPHER, HEADER_PLAIN, HEADER_VERSION, SALT, TAG};

/// v6 记录载荷长度上限（16 位长度字段）。
pub(super) const MAX_PAYLOAD: usize = 0xffff;

const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_V: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_V: u32 = 39;

const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

const NS_SEED_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_SEED_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_SEED_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SEED_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_SEED_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_SEED_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_SEED_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;
const MAX_EXTRA_PADDING: usize = 0x02da;
const SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;

const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

fn prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ u64::from(label).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let y = splitmix64(x);
    (y ^ (y >> 32)) as u32
}

fn pick(raw: u32, lo: usize, hi: usize) -> usize {
    lo + (u64::from(raw) % (hi - lo + 1) as u64) as usize
}

fn pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    lo + raw % (hi - lo + 1)
}

#[derive(Clone, Copy)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed: u64) -> u64 {
    let word = |i: usize| u64::from_le_bytes(secret[i..i + 8].try_into().unwrap());
    let mixed = u64::from(label).wrapping_mul(DOMAIN_MUL)
        ^ seed.wrapping_add(NAMESPACE_ADD)
        ^ word(0)
        ^ word(8).wrapping_add(GOLDEN_GAMMA)
        ^ word(16).rotate_left(17)
        ^ word(24).rotate_right(11);
    splitmix64(mixed)
}

impl Namespaces {
    fn new(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(secret, LABEL_PROFILE_ID, NS_SEED_PROFILE),
            prefix: derive_namespace(secret, LABEL_PADDING, NS_SEED_PREFIX),
            motif: derive_namespace(secret, LABEL_MOTIF, NS_SEED_MOTIF),
            salt: derive_namespace(secret, LABEL_SALT, NS_SEED_SALT),
            mix: derive_namespace(secret, LABEL_MIX_MODE, NS_SEED_MIX),
            chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_SEED_CHUNK),
            write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_SEED_WRITE),
        }
    }

    fn for_label(&self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN | LABEL_PREFIX_MAX
            | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => self.prefix,
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY | LABEL_CHUNK_INITIAL | LABEL_CHUNK_MAX | LABEL_CHUNK_STEP
            | LABEL_CHUNK_JITTER | LABEL_CHUNK_BUCKET | LABEL_CHUNK_SIZE | LABEL_CHUNK_JITTER_V => {
                self.chunk
            }
            LABEL_WRITE_POLICY | LABEL_WRITE_FIRST | LABEL_WRITE_BUCKET | LABEL_WRITE_SEQ
            | LABEL_WRITE_JITTER | LABEL_WRITE_TARGET | LABEL_WRITE_JITTER_V | LABEL_WRITE_NEXT => {
                self.write
            }
            _ => self.profile,
        }
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        prf32_fold(self.for_label(label), label, u64::from(a), u64::from(b))
    }

    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ u64::from(a)
                .wrapping_mul(DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(label).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        for chunk in output.chunks_mut(8) {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed).to_le_bytes();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        prf32_fold(self.for_label(label), label, 0, u64::from(domain))
    }
}

pub struct Profile {
    ns: Namespaces,
    generator: u32,
    pad_min: usize,
    pad_max: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: usize,
    prefix_max_record: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset_base: usize,
    mix_block: usize,
    chunk_policy: u32,
    chunk_initial: usize,
    first_record_cap: usize,
    chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    idle_reset_sec: u64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_seq: [usize; 8],
    write_jitter: usize,
    write_jitter_pct: usize,
    g1: usize,
    g2: usize,
    g3: usize,
    g4: usize,
    g5: usize,
    g6: usize,
    pub(super) salt_block_len: usize,
    mix_stride_handshake: usize,
    mix_rounds_handshake: u32,
}

impl Profile {
    pub fn new(psk: &[u8]) -> Self {
        let mut hasher = Blake2b::<blake2::digest::consts::U32>::new();
        hasher.update(PROFILE_SEED);
        hasher.update(psk);
        let secret: [u8; 32] = hasher.finalize().into();
        let ns = Namespaces::new(&secret);
        let pad_min = pick(ns.prf_static(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max =
            (pad_min + pick(ns.prf_static(LABEL_PAD_MAX, 0), 0xa0, 0x3c0)).min(MAX_EXTRA_PADDING);
        let prefix_max_hs = (pick(
            ns.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        ) + pick(
            ns.prf_static(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
            0x10,
            0xa0,
        ))
        .min(0x80);
        let prefix_min_hs = pick(
            ns.prf_static(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        )
        .min(prefix_max_hs);
        let salt_prefix_len = pick(
            ns.prf_static(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
            prefix_min_hs,
            prefix_max_hs,
        );
        let prefix_min_raw = pick(ns.prf_static(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max_record =
            (prefix_min_raw + pick(ns.prf_static(LABEL_PREFIX_MAX, 0), 0x10, 0xa0)).min(0x80);
        let prefix_min_record = prefix_min_raw.min(prefix_max_record);
        let chunk_initial =
            pick(ns.prf_static(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4).clamp(0x60, 0x05b4);
        let first_record_cap = pick(
            ns.prf_static(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
            0x100,
            0x300,
        )
        .min(chunk_initial.min(0x300))
        .max(0x100);
        let chunk_max = pick(ns.prf_static(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff).max(chunk_initial);
        let mut profile = Self {
            ns,
            generator: ns.prf_static(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(ns.prf_static(LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: pick_u32(ns.prf_static(LABEL_PAD_INTERVAL, 0), 2, 0x0b),
            small_limit: pick(ns.prf_static(LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: pick_u32(ns.prf_static(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(ns.prf_static(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record,
            prefix_max_record,
            mix_mode: ns.prf_static(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(ns.prf_static(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(ns.prf_static(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: pick(ns.prf_static(LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: pick(ns.prf_static(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: ns.prf_static(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: pick(ns.prf_static(LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68),
            chunk_jitter: pick(ns.prf_static(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6),
            idle_reset_sec: pick(ns.prf_static(LABEL_IDLE_RESET, 0), 0x0c, 0x5a) as u64,
            write_policy: ns.prf_static(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(ns.prf_static(LABEL_WRITE_FIRST, 0), 4, 8),
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
            write_jitter: pick(ns.prf_static(LABEL_WRITE_JITTER, 0), 0x08, 0x60),
            write_jitter_pct: pick(ns.prf_static(LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: pick(ns.prf_static(LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: pick(ns.prf_static(LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: pick(ns.prf_static(LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: pick(ns.prf_static(LABEL_GENERATOR, 4), 0x00, 0x09),
            g5: pick(ns.prf_static(LABEL_GENERATOR, 5), 0x01, 0x08),
            g6: pick(ns.prf_static(LABEL_GENERATOR, 6), 0x07, 0x17),
            salt_block_len: SALT + salt_prefix_len,
            mix_stride_handshake: pick(
                ns.prf_static(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
                0x11,
                0xfb,
            ),
            mix_rounds_handshake: pick_u32(
                ns.prf_static(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
                1,
                4,
            ),
        };
        for i in 0..8 {
            profile.chunk_buckets[i] = pick(
                ns.prf_static(LABEL_CHUNK_BUCKET, i as u32),
                0x1000,
                chunk_max,
            );
            profile.write_buckets[i] =
                pick(ns.prf_static(LABEL_WRITE_BUCKET, i as u32), 0x140, 0x05b4);
            profile.write_seq[i] = pick(ns.prf_static(LABEL_WRITE_SEQ, i as u32), 0x168, 0x05b4);
        }
        profile
    }

    fn record_prefix_len(&self, seq: u32) -> usize {
        pick(
            self.ns.prf32(LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        )
    }

    fn chunk_payload_limit(&self, seq: u32, chunk_size: usize) -> usize {
        let mut chunk_size = if chunk_size == 0 {
            self.chunk_initial
        } else {
            chunk_size
        };
        match self.chunk_policy {
            1 => {
                let index = self.ns.prf32(LABEL_CHUNK_SIZE, seq, chunk_size as u32) % 8;
                chunk_size = self.chunk_buckets[index as usize];
            }
            2 => {
                let raw = self.ns.prf32(LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                let jitter = (raw % (self.chunk_jitter as u32 * 2 + 1)) as isize
                    - self.chunk_jitter as isize;
                chunk_size = (chunk_size as isize + jitter) as usize;
            }
            _ => {}
        }
        chunk_size.min(self.chunk_max).max(0x40)
    }

    fn next_chunk_size(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            return self.chunk_initial;
        }
        (chunk_size + self.chunk_step).min(self.chunk_max)
    }

    fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        total_len: usize,
    ) -> usize {
        let mut padding = 0;
        if seq < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && seq.is_multiple_of(self.pad_interval))
        {
            padding = pick(
                self.ns.prf32(LABEL_PAYLOAD_PAD, seq, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let payload_tag = if payload_len > 0 { TAG } else { 0 };
        let frame_len =
            total_len + prefix_len + HEADER_CIPHER + padding + payload_len + payload_tag;
        let target = self.write_target(seq, frame_len);
        if target > frame_len as isize {
            padding += (target as usize - frame_len).min(MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding =
                self.first_record_padding_len(padding, prefix_len, salt_prefix_len, payload_len);
        }
        padding.min(0xffff)
    }

    fn write_target(&self, seq: u32, frame_len: usize) -> isize {
        if frame_len > 0x05b3 {
            return frame_len.min(0xffff) as isize;
        }
        let mut target: isize = if seq < self.write_first {
            self.write_seq[seq as usize] as isize
        } else {
            self.write_buckets
                [(self.ns.prf32(LABEL_WRITE_TARGET, seq, frame_len as u32) % 8) as usize]
                as isize
        };
        if self.write_policy == 2 {
            let raw = self.ns.prf32(LABEL_WRITE_JITTER_V, seq, 0);
            let jitter =
                (raw % (self.write_jitter as u32 * 2 + 1)) as isize - self.write_jitter as isize;
            target = (target + jitter).max(1);
        }
        let spread =
            MAX_EXTRA_PADDING.min((frame_len as u64 * self.write_jitter_pct as u64 / 100) as usize);
        if self.ns.prf32(LABEL_WRITE_TARGET, seq, spread as u32) & 1 == 0 {
            if target + spread as isize <= 0xffff {
                target += spread as isize;
            } else {
                target = 0xffff;
            }
        } else {
            let half = (spread >> 1) as isize;
            if target > half {
                target -= half;
            }
        }
        while target >= 0 && frame_len as isize > target {
            let index = self.ns.prf32(LABEL_WRITE_NEXT, seq, target as u32) % 8;
            let mut next = self.write_buckets[index as usize] as isize;
            if next <= target {
                next = target + self.pad_max as isize;
                if next > 0xffff {
                    return 0xffff;
                }
            }
            target = next;
        }
        target
    }

    fn first_record_padding_len(
        &self,
        padding: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        payload_len: usize,
    ) -> usize {
        let overhead = salt_prefix_len + prefix_len + padding;
        let threshold_input = if payload_len == 0 {
            payload_len + 0x27
        } else {
            payload_len + 0x37
        };
        let threshold = (threshold_input * 25).div_ceil(75).max(0xc0);
        if overhead >= threshold {
            return padding;
        }
        let mut target = threshold as isize - salt_prefix_len as isize - prefix_len as isize;
        let max_padding = (self.pad_max + MAX_EXTRA_PADDING) as isize;
        if max_padding <= target {
            target = max_padding;
        }
        if target > 0xfffe {
            return padding;
        }
        target.max(0) as usize
    }

    fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.ns.prf_bytes(LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bit_count = pick_u32(
                    self.ns.prf32(LABEL_BIT_PERCENT, seq, 0),
                    self.bit_min,
                    self.bit_max,
                );
                let scaled = bit_count as usize * 8;
                let mut rotate = 1;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                let row = rotate.max(1);
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte;
                    let raw = (value as usize).wrapping_add(index) as u8;
                    let table = BIT_ROTATE_TABLE[row * 16 + ((raw ^ value) & 0x0f) as usize];
                    *byte = table.rotate_left(((raw ^ (value >> 4)) & 7) as u32);
                }
            }
            1 => {
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte as usize;
                    let bucket = value % (self.g1 + self.g2 + self.g3);
                    *byte = if bucket < self.g1 {
                        pick(u32::from(value.wrapping_add(index) as u8), 0x20, 0x7e) as u8
                    } else if bucket < self.g1 + self.g2 {
                        pick(u32::from((value ^ index) as u8), 0x80, 0xbf) as u8
                    } else {
                        pick(
                            u32::from(value.wrapping_add(index.wrapping_mul(7)) as u8),
                            0xc0,
                            0xff,
                        ) as u8
                    };
                }
            }
            2 => {
                for (index, byte) in output.iter_mut().enumerate() {
                    let value = *byte as usize;
                    let low = ((value & 0x0f) + self.g4 + (index & 1)) % 10;
                    let high = (value + ((index & 3) << 4) + 0x30) & 0xf0;
                    *byte = (high | low) as u8;
                }
            }
            _ => {
                let mut motif = [0u8; 32];
                self.ns.prf_bytes(LABEL_MOTIF, seq, &mut motif);
                let motif_len = if self.g5 * 4 == 0 { 4 } else { self.g5 * 4 };
                let period = self.g6.max(5);
                let mut block_offset = 0;
                let mut motif_offset = 0;
                for (index, byte) in output.iter_mut().enumerate() {
                    if block_offset < period - 3 {
                        *byte = (((self.g5 + 3).wrapping_mul(index)) as u8)
                            ^ motif[motif_offset % motif.len()];
                    } else if block_offset < period - 1 {
                        *byte = 0x30 | (*byte % 10);
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len {
                        motif_offset = 0;
                    }
                }
            }
        }
    }

    /// 填充与载荷密文按位置交换。每轮都只交换同一下标的字节，所以再做一遍就复原。
    fn mix(&self, seq: u32, padding: &mut [u8], payload: &mut [u8]) {
        let n = padding.len().min(payload.len());
        if n == 0 {
            return;
        }
        let swap = |padding: &mut [u8], payload: &mut [u8], i: usize| {
            std::mem::swap(&mut padding[i], &mut payload[i])
        };
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 | 2 => {
                    let stride = (self.mix_stride + (round % 3) as usize).max(1);
                    if stride == 1 {
                        for i in 0..n {
                            swap(padding, payload, i);
                        }
                        continue;
                    }
                    let mut off = if self.mix_mode == 0 {
                        self.mix_offset_base % stride
                    } else {
                        ((u64::from(self.ns.prf32(LABEL_MIX_OFFSET, seq, round))
                            + self.mix_offset_base as u64)
                            % stride as u64) as usize
                    };
                    while off < n {
                        swap(padding, payload, off);
                        off += stride;
                    }
                }
                _ => {
                    let block = self.mix_block;
                    let mut off = (round & 1) as usize * block;
                    while off + block <= n {
                        for i in off..off + block {
                            swap(padding, payload, i);
                        }
                        off += block * 2;
                    }
                }
            }
        }
    }

    fn shuffle_perm(&self, length: usize) -> Vec<usize> {
        let mut out: Vec<usize> = (0..length).collect();
        let rounds = (self.mix_rounds_handshake as u8).max(1);
        for round in 0..u32::from(rounds) {
            let domain = MIX_HANDSHAKE_DOMAIN + round;
            for i in 0..length {
                let span = (length - i) as u64;
                let rdx = (i as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B);
                let rdi = self.ns.salt ^ SALT_NS_XOR;
                let rsi = u64::from(domain).wrapping_mul(COEF_A).wrapping_add(ADD_A);
                let y = splitmix64((rdx ^ rdi) ^ rsi);
                let raw = u64::from((y ^ (y >> 32)) as u32);
                let j = i + (raw % span) as usize;
                out.swap(i, j);
            }
        }
        out
    }

    fn salt_mask(&self, index: u32) -> u8 {
        let prf = prf32_fold(
            self.ns.salt,
            LABEL_MOTIF,
            u64::from(MIX_HANDSHAKE_DOMAIN),
            u64::from(index),
        );
        (index as u8).wrapping_mul(self.mix_stride_handshake as u8) ^ prf as u8
    }

    fn extract_salt(&self, block: &[u8]) -> [u8; SALT] {
        let perm = self.shuffle_perm(block.len());
        let mut out = [0u8; SALT];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self.salt_mask(i as u32) ^ block[perm[i]];
        }
        out
    }

    fn write_salt_block(&self, salt: &[u8; SALT], block: &mut [u8]) {
        let perm = self.shuffle_perm(block.len());
        for i in 0..SALT {
            block[perm[i]] = self.salt_mask(i as u32) ^ salt[i];
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn put_header(header: &mut [u8], padding: usize, payload: usize) {
    header[0] = HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload as u16).to_be_bytes());
}

/// default 模式的写端。
pub(super) struct ShapedWriter {
    profile: std::sync::Arc<Profile>,
    aead: Aead,
    salt: [u8; SALT],
    salt_sent: bool,
    seq: u32,
    chunk_size: usize,
    last_write: u64,
}

impl ShapedWriter {
    pub(super) fn new(profile: std::sync::Arc<Profile>, psk: &[u8]) -> io::Result<Self> {
        let salt = super::random_salt()?;
        Ok(Self {
            aead: Aead::new(psk, &salt)?,
            profile,
            salt,
            salt_sent: false,
            seq: 0,
            chunk_size: 0,
            last_write: 0,
        })
    }

    fn payload_limit(&mut self) -> usize {
        let now = now_unix();
        if self.last_write == 0 || now.saturating_sub(self.last_write) > self.profile.idle_reset_sec
        {
            self.chunk_size = self.profile.chunk_initial;
        }
        if self.chunk_size == 0 {
            self.chunk_size = self.profile.chunk_initial;
        }
        let mut limit = self.profile.chunk_payload_limit(self.seq, self.chunk_size);
        if self.seq == 0 {
            limit = limit.min(self.profile.first_record_cap);
        }
        self.chunk_size = self.profile.next_chunk_size(self.chunk_size);
        self.last_write = now;
        limit.clamp(1, MAX_PAYLOAD)
    }

    fn record(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let p = self.profile.clone();
        let prefix_len = p.record_prefix_len(self.seq);
        let (salt_block, salt_prefix) = if self.salt_sent {
            (0, 0)
        } else {
            (p.salt_block_len, p.salt_block_len - SALT)
        };
        let padding_len =
            p.padding_len(self.seq, payload.len(), prefix_len, salt_prefix, salt_block);
        if salt_block > 0 {
            let start = out.len();
            out.resize(start + salt_block, 0);
            p.fill_padding(0xffff_ffff, &mut out[start..]);
            p.write_salt_block(&self.salt, &mut out[start..]);
            self.salt_sent = true;
        }
        let prefix_start = out.len();
        out.resize(prefix_start + prefix_len, 0);
        p.fill_padding(self.seq, &mut out[prefix_start..]);
        let prefix = out[prefix_start..].to_vec();
        let mut header = [0u8; HEADER_PLAIN];
        put_header(&mut header, padding_len, payload.len());
        out.extend_from_slice(&self.aead.seal(&header, &prefix));
        let mut padding = vec![0u8; padding_len];
        p.fill_padding(self.seq, &mut padding);
        if payload.is_empty() {
            out.extend_from_slice(&padding);
        } else {
            let mut sealed = self.aead.seal(payload, &padding);
            p.mix(self.seq, &mut padding, &mut sealed);
            out.extend_from_slice(&padding);
            out.extend_from_slice(&sealed);
        }
        self.seq = self.seq.wrapping_add(1);
    }

    pub(super) fn stream(&mut self, mut data: &[u8], out: &mut Vec<u8>) {
        while !data.is_empty() {
            let take = data.len().min(self.payload_limit());
            self.record(&data[..take], out);
            data = &data[take..];
        }
    }

    /// UDP：整包一条记录，分块状态照常推进。
    pub(super) fn packet(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.payload_limit();
        self.record(data, out);
    }

    pub(super) fn zero(&mut self, out: &mut Vec<u8>) {
        self.payload_limit();
        self.record(&[], out);
    }
}

pub(super) struct ShapedReader {
    profile: std::sync::Arc<Profile>,
    aead: Option<Aead>,
    seq: u32,
    pending: Option<(usize, usize, u32)>,
}

impl ShapedReader {
    pub(super) fn new(profile: std::sync::Arc<Profile>) -> Self {
        Self {
            profile,
            aead: None,
            seq: 0,
            pending: None,
        }
    }

    pub(super) fn parse(&mut self, psk: &[u8], buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        let p = self.profile.clone();
        if self.aead.is_none() {
            if buf.len() < p.salt_block_len {
                return Ok(None);
            }
            let salt = p.extract_salt(&buf[..p.salt_block_len]);
            buf.advance(p.salt_block_len);
            self.aead = Some(Aead::new(psk, &salt)?);
        }
        let aead = self.aead.as_mut().unwrap();
        if self.pending.is_none() {
            let prefix_len = p.record_prefix_len(self.seq);
            if buf.len() < prefix_len + HEADER_CIPHER {
                return Ok(None);
            }
            let (prefix, rest) = buf[..prefix_len + HEADER_CIPHER].split_at(prefix_len);
            let header = aead
                .open(rest, prefix)
                .map_err(|_| invalid("snell: open shaped header"))?;
            if header[0] != HEADER_VERSION {
                return Err(invalid("snell: bad header version"));
            }
            let padding = u16::from_be_bytes([header[3], header[4]]) as usize;
            let payload = u16::from_be_bytes([header[5], header[6]]) as usize;
            buf.advance(prefix_len + HEADER_CIPHER);
            self.pending = Some((padding, payload, self.seq));
            self.seq = self.seq.wrapping_add(1);
        }
        let (padding_len, payload_len, seq) = self.pending.unwrap();
        if payload_len == 0 {
            if buf.len() < padding_len {
                return Ok(None);
            }
            buf.advance(padding_len);
            self.pending = None;
            return Ok(Some(Frame::Eof));
        }
        let need = padding_len + payload_len + TAG;
        if buf.len() < need {
            return Ok(None);
        }
        let mut padding = buf[..padding_len].to_vec();
        let mut sealed = buf[padding_len..need].to_vec();
        buf.advance(need);
        self.pending = None;
        p.mix(seq, &mut padding, &mut sealed);
        let plain = aead
            .open(&sealed, &padding)
            .map_err(|_| invalid("snell: open shaped payload"))?;
        Ok(Some(Frame::Data(plain)))
    }
}

/// unshaped 模式：盐 + 无填充的 v4 式记录，记录最大 0xffff。
pub(super) struct UnshapedWriter {
    aead: Aead,
    salt: Option<[u8; SALT]>,
}

impl UnshapedWriter {
    pub(super) fn new(psk: &[u8]) -> io::Result<Self> {
        let salt = super::random_salt()?;
        Ok(Self {
            aead: Aead::new(psk, &salt)?,
            salt: Some(salt),
        })
    }

    fn record(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        if let Some(salt) = self.salt.take() {
            out.extend_from_slice(&salt);
        }
        let mut header = [0u8; HEADER_PLAIN];
        put_header(&mut header, 0, payload.len());
        out.extend_from_slice(&self.aead.seal(&header, &[]));
        if !payload.is_empty() {
            out.extend_from_slice(&self.aead.seal(payload, &[]));
        }
    }

    pub(super) fn stream(&mut self, data: &[u8], out: &mut Vec<u8>) {
        for chunk in data.chunks(MAX_PAYLOAD) {
            self.record(chunk, out);
        }
    }

    pub(super) fn packet(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.record(data, out);
    }

    pub(super) fn zero(&mut self, out: &mut Vec<u8>) {
        self.record(&[], out);
    }
}

pub(super) struct UnshapedReader {
    aead: Option<Aead>,
    pending: Option<usize>,
}

impl UnshapedReader {
    pub(super) fn new() -> Self {
        Self {
            aead: None,
            pending: None,
        }
    }

    pub(super) fn parse(&mut self, psk: &[u8], buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        if self.aead.is_none() {
            if buf.len() < SALT {
                return Ok(None);
            }
            let salt: [u8; SALT] = buf[..SALT].try_into().unwrap();
            buf.advance(SALT);
            self.aead = Some(Aead::new(psk, &salt)?);
        }
        let aead = self.aead.as_mut().unwrap();
        if self.pending.is_none() {
            if buf.len() < HEADER_CIPHER {
                return Ok(None);
            }
            let header = aead
                .open(&buf[..HEADER_CIPHER], &[])
                .map_err(|_| invalid("snell: open record header"))?;
            buf.advance(HEADER_CIPHER);
            let (padding, payload) = parse_strict_header(&header)?;
            if padding != 0 {
                return Err(invalid("snell: unexpected padding in non-default record"));
            }
            if payload == 0 {
                return Ok(Some(Frame::Eof));
            }
            self.pending = Some(payload);
        }
        let payload = self.pending.unwrap();
        if buf.len() < payload + TAG {
            return Ok(None);
        }
        let plain = aead
            .open(&buf[..payload + TAG], &[])
            .map_err(|_| invalid("snell: open record payload"))?;
        buf.advance(payload + TAG);
        self.pending = None;
        Ok(Some(Frame::Data(plain)))
    }
}

/// unsafe-raw：明文首部 + 明文载荷。
pub(super) fn raw_record(payload: &[u8], out: &mut Vec<u8>) {
    let mut header = [0u8; HEADER_PLAIN];
    put_header(&mut header, 0, payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
}

pub(super) fn raw_parse(buf: &mut BytesMut) -> io::Result<Option<Frame>> {
    if buf.len() < HEADER_PLAIN {
        return Ok(None);
    }
    let (padding, payload) = parse_strict_header(&buf[..HEADER_PLAIN])?;
    if padding != 0 {
        return Err(invalid("snell: unexpected padding in non-default record"));
    }
    if payload == 0 {
        buf.advance(HEADER_PLAIN);
        return Ok(Some(Frame::Eof));
    }
    if buf.len() < HEADER_PLAIN + payload {
        return Ok(None);
    }
    let data = buf[HEADER_PLAIN..HEADER_PLAIN + payload].to_vec();
    buf.advance(HEADER_PLAIN + payload);
    Ok(Some(Frame::Data(data)))
}

fn parse_strict_header(header: &[u8]) -> io::Result<(usize, usize)> {
    if header[0] != HEADER_VERSION {
        return Err(invalid("snell: bad header version"));
    }
    if header[1] != 0 || header[2] != 0 {
        return Err(invalid("snell: reserved header octet is non-zero"));
    }
    Ok((
        u16::from_be_bytes([header[3], header[4]]) as usize,
        u16::from_be_bytes([header[5], header[6]]) as usize,
    ))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn roundtrip(writer: &mut ShapedWriter, reader: &mut ShapedReader, psk: &[u8], data: &[u8]) {
        let mut wire = Vec::new();
        writer.stream(data, &mut wire);
        let mut buf = BytesMut::from(&wire[..]);
        let mut got = Vec::new();
        while let Some(frame) = reader.parse(psk, &mut buf).unwrap() {
            match frame {
                Frame::Data(d) => got.extend_from_slice(&d),
                Frame::Eof => panic!("unexpected eof"),
            }
        }
        assert!(buf.is_empty());
        assert_eq!(got, data);
    }

    #[test]
    fn shaped_records_roundtrip() {
        for psk in [&b"psk"[..], b"another-pre-shared-key", b"x"] {
            let profile = Arc::new(Profile::new(psk));
            let mut writer = ShapedWriter::new(profile.clone(), psk).unwrap();
            let mut reader = ShapedReader::new(profile.clone());
            for size in [1usize, 10, 300, 1500, 20_000, 70_000] {
                let data: Vec<u8> = (0..size).map(|i| (i * 7) as u8).collect();
                roundtrip(&mut writer, &mut reader, psk, &data);
            }
            let mut wire = Vec::new();
            writer.zero(&mut wire);
            let mut buf = BytesMut::from(&wire[..]);
            assert!(matches!(
                reader.parse(psk, &mut buf).unwrap(),
                Some(Frame::Eof)
            ));
        }
    }

    #[test]
    fn salt_block_roundtrip_and_partial_input() {
        let profile = Profile::new(b"psk");
        let salt = [7u8; SALT];
        let mut block = vec![0u8; profile.salt_block_len];
        profile.fill_padding(0xffff_ffff, &mut block);
        profile.write_salt_block(&salt, &mut block);
        assert_eq!(profile.extract_salt(&block), salt);

        let profile = Arc::new(profile);
        let mut writer = ShapedWriter::new(profile.clone(), b"psk").unwrap();
        let mut wire = Vec::new();
        writer.stream(b"hello world", &mut wire);
        let mut reader = ShapedReader::new(profile);
        let mut buf = BytesMut::new();
        let mut got = None;
        // 逐字节喂入
        for byte in wire {
            buf.extend_from_slice(&[byte]);
            if let Some(frame) = reader.parse(b"psk", &mut buf).unwrap() {
                got = Some(frame);
            }
        }
        assert!(matches!(got, Some(Frame::Data(d)) if d == b"hello world"));
    }

    #[test]
    fn unshaped_and_raw_roundtrip() {
        let mut writer = UnshapedWriter::new(b"k").unwrap();
        let mut reader = UnshapedReader::new();
        let data = vec![9u8; 70_000];
        let mut wire = Vec::new();
        writer.stream(&data, &mut wire);
        writer.zero(&mut wire);
        let mut buf = BytesMut::from(&wire[..]);
        let mut got = Vec::new();
        loop {
            match reader.parse(b"k", &mut buf).unwrap() {
                Some(Frame::Data(d)) => got.extend_from_slice(&d),
                Some(Frame::Eof) => break,
                None => panic!("short"),
            }
        }
        assert_eq!(got, data);

        let mut wire = Vec::new();
        raw_record(b"abc", &mut wire);
        let mut buf = BytesMut::from(&wire[..]);
        assert!(matches!(raw_parse(&mut buf).unwrap(), Some(Frame::Data(d)) if d == b"abc"));
    }
}
