//! 固定速率的 Brutal。不做丢包补偿。速率可以在认证之后调低。

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;

use crate::BRUTAL_SEND_WINDOW as SEND_WINDOW;

pub struct BrutalFactory {
    pub rate: Arc<AtomicU64>,
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal {
            rate: self.rate.clone(),
            mtu: u64::from(current_mtu.max(1)),
            srtt: Duration::ZERO,
        })
    }
}

struct Brutal {
    rate: Arc<AtomicU64>,
    mtu: u64,
    srtt: Duration,
}

impl Brutal {
    /// 窗口 = 速率 × RTT × 2（与 Hysteria 的 Brutal 相同，乘数 2 留出 ACK 延迟的余量），
    /// 下限 10 个包：RTT 很小时（本机、局域网）按公式只有一个包的窗口，接收方的延迟 ACK
    /// 会让发送长时间停住；上限是 Brutal 连接的发送窗口（`BRUTAL_SEND_WINDOW`）。
    fn cwnd(&self) -> u64 {
        let rate = self.rate.load(Ordering::Relaxed).max(1);
        let floor = (self.mtu * 10).min(SEND_WINDOW);
        if self.srtt.is_zero() {
            return floor;
        }
        let bytes = (rate as f64 * self.srtt.as_secs_f64() * 2.0) as u64;
        bytes.clamp(floor, SEND_WINDOW)
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.srtt = rtt.get();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu.max(1));
    }

    fn window(&self) -> u64 {
        self.cwnd()
    }

    fn metrics(&self) -> ControllerMetrics {
        let rate = self.rate.load(Ordering::Relaxed);
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.cwnd();
        metrics.pacing_rate = Some(rate.saturating_mul(8));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Brutal {
            rate: self.rate.clone(),
            mtu: self.mtu,
            srtt: self.srtt,
        })
    }

    fn initial_window(&self) -> u64 {
        (self.mtu * 10).min(SEND_WINDOW)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// 发送端令牌桶：把线上发送压到 Brutal 速率。
///
/// quinn 的步调器按「窗口 × 1.25 ÷ RTT」放行，拥塞控制器无法直接指定速率；窗口又必须
/// 不小于几个包（否则延迟 ACK 会让发送停住），所以 RTT 很小时只靠窗口限不住速率
/// （局域网 0.4 ms 往返下 10 个包的窗口就约 240 Mbit/s）。在套接字的发送任务里按配置速率放行，
/// 队列满后 quinn 自然停发。突发上限取 10 ms 的量（不少于 10 个包），与参考实现的步调器相当。
pub(crate) struct Pacer {
    rate: Arc<AtomicU64>,
    tokens: f64,
    last: tokio::time::Instant,
}

const PACER_MIN_BURST: f64 = 10.0 * 1500.0;

impl Pacer {
    pub(crate) fn new(rate: Arc<AtomicU64>) -> Self {
        Self {
            rate,
            tokens: PACER_MIN_BURST,
            last: tokio::time::Instant::now(),
        }
    }

    /// 等到可以发送 `bytes` 字节。
    pub(crate) async fn wait(&mut self, bytes: usize) {
        let bytes = bytes as f64;
        loop {
            let rate = self.rate.load(Ordering::Relaxed).max(1) as f64;
            let burst = (rate * 0.01).max(PACER_MIN_BURST);
            let now = tokio::time::Instant::now();
            let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
            self.tokens = (self.tokens + rate * elapsed).min(burst);
            self.last = now;
            if self.tokens >= bytes {
                self.tokens -= bytes;
                return;
            }
            let wait = (bytes - self.tokens) / rate;
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pacer_holds_configured_rate() {
        // 2.5 MB/s（20 Mbit/s）下发 1000 个 1200 字节的包，耗时应接近 1.2 MB ÷ 2.5 MB/s
        let rate = Arc::new(AtomicU64::new(2_500_000));
        let mut pacer = Pacer::new(rate.clone());
        let start = tokio::time::Instant::now();
        for _ in 0..1000 {
            pacer.wait(1200).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        let expected = (1_200_000.0 - PACER_MIN_BURST) / 2_500_000.0;
        assert!(
            (elapsed - expected).abs() < 0.01,
            "elapsed {elapsed}, expected {expected}"
        );
        // 速率在认证后调低，立即生效
        rate.store(250_000, Ordering::Relaxed);
        let start = tokio::time::Instant::now();
        for _ in 0..100 {
            pacer.wait(1200).await;
        }
        let elapsed = start.elapsed().as_secs_f64();
        assert!((elapsed - 0.48).abs() < 0.02, "elapsed {elapsed}");
    }

    #[test]
    fn window_tracks_rate_and_caps() {
        let rate = Arc::new(AtomicU64::new(1_000_000));
        let brutal = Brutal {
            rate: rate.clone(),
            mtu: 1200,
            srtt: Duration::from_millis(100),
        };
        let window = brutal.window();
        assert!((1200..=SEND_WINDOW).contains(&window));
        assert_eq!(window, 200_000);
        // RTT 很小时不低于 10 个包
        let tiny = Brutal {
            rate: rate.clone(),
            mtu: 1200,
            srtt: Duration::from_micros(100),
        };
        assert_eq!(tiny.window(), 12_000);
        // 100 Mbit/s × 100 ms × 2 = 2.5 MB，不再被 1 MiB 截断
        rate.store(12_500_000, Ordering::Relaxed);
        assert_eq!(brutal.window(), 2_500_000);
        rate.store(50_000_000, Ordering::Relaxed);
        assert_eq!(brutal.window(), SEND_WINDOW);
    }
}
