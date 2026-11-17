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

#[cfg(test)]
mod tests {
    use super::*;

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
