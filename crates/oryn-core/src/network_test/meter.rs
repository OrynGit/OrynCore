//! 一个方向的自动时长与自动连接数，行为参照 speedtest.net（只参考行为与参数）：
//! 每 500 ms 一个时间片，读数为去掉最快 2 片、再去掉其余最慢 1/3 后的平均（MST），且不低于全程平均；
//! 最长 15 秒，满 6 秒后读数稳定即提前结束；多线程时前半段按读数加连接。
//! 字节可以事后按一个时间段均摊记入（上传在服务端确认后才计入，与 Speedtest 网页端把样本按
//! 发出到收到回复的区间拆到各时间片相同）；读数只用「已确定」的时间片，即不会再有字节记入的部分。
//! 规则与常量见 docs/plan-network-test.md「自动时长与自动多线程」「长连接、大请求与准确延迟」。
//! 主 App 直连客户端 `OrynApp/Services/DirectNetworkTest.swift` 的 `SpeedMeter` 是同一套规则，改动需同步。

/// 每方向最多的时间片数（15 秒）。
pub(super) const MAX_TICKS: usize = 30;
/// 满 6 秒才允许提前结束。
const MIN_STOP_TICKS: usize = 12;
/// 最近 5 次读数（2.5 秒）的波动不超过 3% 视为稳定。
const STABLE_WINDOW: usize = 5;
const STABLE_TOLERANCE: f64 = 0.03;
/// 最近一次加连接后至少 2 秒才判断稳定。
const SETTLE_TICKS: usize = 4;
/// 只在前一半（7.5 秒）加连接。
const SCALE_TICKS: usize = MAX_TICKS / 2;
pub(super) const START_CONNECTIONS: usize = 4;
/// Speedtest 为 32；受 Extension 内存预算限制取 16。
pub(super) const MAX_CONNECTIONS: usize = 16;
/// 每条连接对应的读数（Speedtest 默认 750 kB/s）。
const MBPS_PER_CONNECTION: f64 = 6.0;
/// MST 至少需要的时间片数。
const MIN_MST_TICKS: usize = 4;
const KEPT_FRACTION: f64 = 2.0 / 3.0;

/// 每个时间片之后的决定。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Step {
    /// 进行中显示的读数（Mbit/s）。
    pub mbps: f64,
    /// 应保持的连接数（只增不减）。
    pub connections: usize,
    pub done: bool,
}

pub(super) struct Meter {
    tick_secs: f64,
    auto: bool,
    connections: usize,
    /// 最近一次加连接时已确定的时间片数。
    scaled_at: usize,
    /// 每个时间片累计的字节，可事后记入；超出上限的部分记入最后一片。
    buckets: [f64; MAX_TICKS],
    /// 已经过的时间片数。
    ticks: usize,
    /// 已确定的时间片数（不会再有字节记入）。
    settled: usize,
    /// `results[k - 1]` 是前 k 个已确定时间片的最终读数，用于判断稳定。
    results: Vec<f64>,
}

impl Meter {
    /// `auto` 为真时按读数增加连接；`connections` 是起始连接数。
    pub fn new(connections: usize, auto: bool, tick_secs: f64) -> Self {
        Self {
            tick_secs,
            auto,
            connections,
            scaled_at: 0,
            buckets: [0.0; MAX_TICKS],
            ticks: 0,
            settled: 0,
            results: Vec::with_capacity(MAX_TICKS),
        }
    }

    /// 把 `bytes` 按 `[from, to]`（距本方向开始的秒数）均摊记入各时间片。
    pub fn record(&mut self, bytes: u64, from: f64, to: f64) {
        let last = MAX_TICKS - 1;
        let slot = |t: f64| ((t.max(0.0) / self.tick_secs) as usize).min(last);
        let bytes = bytes as f64;
        if to <= from {
            self.buckets[slot(to)] += bytes;
            return;
        }
        let span = to - from;
        for index in slot(from)..=slot(to) {
            let start = index as f64 * self.tick_secs;
            let end = if index == last {
                f64::INFINITY
            } else {
                start + self.tick_secs
            };
            let overlap = to.min(end) - from.max(start);
            if overlap > 0.0 {
                self.buckets[index] += bytes * overlap / span;
            }
        }
    }

    /// 经过一个时间片。`settled` 是此刻之前不会再有字节记入的时间（秒）：下载为当前时间，
    /// 上传为仍在途的请求里最早的开始时间。
    pub fn tick(&mut self, settled: f64) -> Step {
        self.ticks += 1;
        let settled = ((settled.max(0.0) / self.tick_secs + 1e-6) as usize)
            .min(self.ticks)
            .min(MAX_TICKS);
        while self.settled < settled {
            self.settled += 1;
            let (average, mst) = self.estimate(self.settled);
            self.results
                .push(mst.map_or(average, |mst| mst.max(average)));
        }
        let (average, mst) = self.estimate(self.settled);
        // 进行中：越接近上限越偏向 MST，与 Speedtest 网页端相同。
        let mbps = match mst {
            Some(mst) if mst > average => {
                let ratio = self.settled as f64 / MAX_TICKS as f64;
                ratio * mst + (1.0 - ratio) * average
            }
            _ => average,
        };
        if self.auto && self.settled > 0 && self.settled <= SCALE_TICKS {
            let wanted = ((mbps / MBPS_PER_CONNECTION).round() as usize)
                .clamp(START_CONNECTIONS, MAX_CONNECTIONS);
            if wanted > self.connections {
                self.connections = wanted;
                self.scaled_at = self.settled;
            }
        }
        Step {
            mbps,
            connections: self.connections,
            done: self.ticks >= MAX_TICKS || self.stable(),
        }
    }

    /// 方向结束时的读数：已确定部分的 `max(MST, 平均)`，片数不足 MST 时为平均。
    pub fn result(&self) -> f64 {
        self.results.last().copied().unwrap_or(0.0)
    }

    fn rate(&self, index: usize) -> f64 {
        self.buckets[index] * 8.0 / self.tick_secs / 1_000_000.0
    }

    /// 前 `count` 个时间片的平均与 MST（去掉最快 2 片，再去掉其余最慢的 1/3，取剩下的平均）。
    fn estimate(&self, count: usize) -> (f64, Option<f64>) {
        if count == 0 {
            return (0.0, None);
        }
        let mut rates: Vec<f64> = (0..count).map(|i| self.rate(i)).collect();
        let average = rates.iter().sum::<f64>() / count as f64;
        if count < MIN_MST_TICKS {
            return (average, None);
        }
        rates.sort_by(|a, b| b.total_cmp(a));
        let rest = &rates[2..];
        let dropped = ((rest.len() as f64) * (1.0 - KEPT_FRACTION)).floor() as usize;
        let kept = &rest[..rest.len() - dropped];
        (average, Some(kept.iter().sum::<f64>() / kept.len() as f64))
    }

    fn stable(&self) -> bool {
        if self.settled < MIN_STOP_TICKS || self.settled - self.scaled_at < SETTLE_TICKS {
            return false;
        }
        let window = &self.results[self.results.len() - STABLE_WINDOW..];
        let max = window.iter().copied().fold(0.0, f64::max);
        let min = window.iter().copied().fold(f64::INFINITY, f64::min);
        max > 0.0 && (max - min) / max <= STABLE_TOLERANCE
    }

    /// 测试用：本时间片内传了 `bytes`，此刻全部确定。
    #[cfg(test)]
    fn tick_bytes(&mut self, bytes: u64) -> Step {
        let now = self.ticks as f64 * self.tick_secs;
        self.record(bytes, now, now + self.tick_secs);
        self.tick(now + self.tick_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 0.5 秒的时间片里传 `mbps` 对应的字节数。
    fn bytes(mbps: f64) -> u64 {
        (mbps * 1_000_000.0 / 8.0 * 0.5) as u64
    }

    fn run(meter: &mut Meter, rates: impl IntoIterator<Item = f64>) -> Option<(usize, Step)> {
        for (index, rate) in rates.into_iter().enumerate() {
            let step = meter.tick_bytes(bytes(rate));
            if step.done {
                return Some((index + 1, step));
            }
        }
        None
    }

    #[test]
    fn steady_rate_stops_after_minimum_time() {
        let mut meter = Meter::new(1, false, 0.5);
        let (ticks, _) = run(&mut meter, std::iter::repeat(100.0)).unwrap();
        assert_eq!(ticks, MIN_STOP_TICKS);
        assert!((meter.result() - 100.0).abs() < 0.01);
    }

    #[test]
    fn unsettled_rate_runs_to_the_cap() {
        let mut meter = Meter::new(1, false, 0.5);
        // 读数一直在爬升，永远不稳定
        let (ticks, _) = run(&mut meter, (1..).map(|i| 10.0 * i as f64)).unwrap();
        assert_eq!(ticks, MAX_TICKS);
    }

    #[test]
    fn result_drops_fastest_and_slow_start_slices() {
        let mut meter = Meter::new(1, false, 0.5);
        // 慢启动 2 片、一个偏快的片，其余稳定在 100
        let mut rates = vec![10.0, 40.0, 150.0];
        rates.extend(std::iter::repeat(100.0).take(9));
        for rate in rates {
            meter.tick_bytes(bytes(rate));
        }
        // 12 片：去掉最快的 150 和一个 100，其余 10 片去掉最慢 3 片（10、40、100）
        assert!((meter.result() - 100.0).abs() < 0.01, "{}", meter.result());
        // 全程平均被慢启动拉低，不作为读数
        assert!((meter.estimate(12).0 - 91.67).abs() < 0.01);
    }

    #[test]
    fn result_never_drops_below_the_average() {
        // 一个大尖峰让全程平均高于 MST：与 Speedtest 相同，读数取平均
        let mut meter = Meter::new(1, false, 0.5);
        let mut rates = vec![10.0, 40.0, 400.0];
        rates.extend(std::iter::repeat(100.0).take(9));
        for rate in rates {
            meter.tick_bytes(bytes(rate));
        }
        assert!((meter.result() - 112.5).abs() < 0.01);
    }

    #[test]
    fn falls_back_to_average_before_enough_slices() {
        let mut meter = Meter::new(1, false, 0.5);
        meter.tick_bytes(bytes(10.0));
        let step = meter.tick_bytes(bytes(30.0));
        assert!((step.mbps - 20.0).abs() < 0.01);
        assert!((meter.result() - 20.0).abs() < 0.01);
    }

    #[test]
    fn auto_mode_scales_with_speed_and_only_in_first_half() {
        let mut meter = Meter::new(START_CONNECTIONS, true, 0.5);
        let step = meter.tick_bytes(bytes(60.0));
        assert_eq!(step.connections, 10);
        // 慢下来也不减少
        assert_eq!(meter.tick_bytes(bytes(1.0)).connections, 10);
        let mut fast = Meter::new(START_CONNECTIONS, true, 0.5);
        assert_eq!(fast.tick_bytes(bytes(1000.0)).connections, MAX_CONNECTIONS);
        // 后半段不再增加
        let mut late = Meter::new(START_CONNECTIONS, true, 0.5);
        for _ in 0..SCALE_TICKS {
            late.tick_bytes(bytes(6.0));
        }
        assert_eq!(late.tick_bytes(bytes(10_000.0)).connections, START_CONNECTIONS);
    }

    #[test]
    fn slow_link_keeps_start_connections() {
        let mut meter = Meter::new(START_CONNECTIONS, true, 0.5);
        assert_eq!(meter.tick_bytes(bytes(5.0)).connections, START_CONNECTIONS);
        let mut single = Meter::new(1, false, 0.5);
        assert_eq!(single.tick_bytes(bytes(1000.0)).connections, 1);
    }

    #[test]
    fn recent_scaling_delays_the_stop() {
        let mut meter = Meter::new(START_CONNECTIONS, true, 0.5);
        // 读数一直小于 4 条连接的阈值，直到第 11 片才一下子加满
        for _ in 0..10 {
            meter.tick_bytes(bytes(12.0));
        }
        assert_eq!(meter.tick_bytes(bytes(5000.0)).connections, MAX_CONNECTIONS);
        // 刚加过连接：至少 SETTLE_TICKS 片之后才可能结束
        for _ in 0..SETTLE_TICKS - 1 {
            assert!(!meter.tick_bytes(bytes(12.0)).done);
        }
    }

    #[test]
    fn late_credit_is_spread_over_its_span() {
        let mut meter = Meter::new(1, false, 0.5);
        // 一个上传请求 0–2 秒共 2 MB，2 秒时才被确认：之前没有已确定的时间片，读数为 0
        for _ in 0..3 {
            assert_eq!(meter.tick(0.0).mbps, 0.0);
        }
        meter.record(2_000_000, 0.0, 2.0);
        // 确认后 4 个时间片各 0.5 MB，即 8 Mbit/s
        assert!((meter.tick(2.0).mbps - 8.0).abs() < 0.01);
    }

    #[test]
    fn unsettled_time_is_not_counted_and_does_not_look_stable() {
        let mut meter = Meter::new(1, false, 0.5);
        meter.record(1_000_000, 0.0, 1.0);
        // 1 秒起一直有请求未确认：只用前 2 片，不会因为读数不变就提前结束
        for _ in 0..MAX_TICKS - 1 {
            assert!(!meter.tick(1.0).done);
        }
        assert!(meter.tick(1.0).done, "到上限仍然结束");
        assert!((meter.result() - 8.0).abs() < 0.01);
    }

    #[test]
    fn idle_phase_never_counts_as_stable() {
        let mut meter = Meter::new(1, false, 0.5);
        let (ticks, step) = run(&mut meter, std::iter::repeat(0.0)).unwrap();
        assert_eq!((ticks, step.mbps), (MAX_TICKS, 0.0));
        assert_eq!(meter.result(), 0.0);
    }
}
