//! ShadowQUIC 带宽扩展：协商成功前用普通拥塞控制，成功后切换已有 Brutal。
use crate::BrutalFactory;
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use std::{
    any::Any,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
pub struct NegotiatedFactory {
    pub fallback: Arc<dyn ControllerFactory + Send + Sync>,
    pub rate: Arc<AtomicU64>,
}
impl ControllerFactory for NegotiatedFactory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Negotiated {
            normal: self.fallback.clone().build(now, mtu),
            brutal: Arc::new(BrutalFactory {
                rate: self.rate.clone(),
            })
            .build(now, mtu),
            rate: self.rate.clone(),
        })
    }
}
struct Negotiated {
    normal: Box<dyn Controller>,
    brutal: Box<dyn Controller>,
    rate: Arc<AtomicU64>,
}
impl Negotiated {
    fn selected(&self) -> &dyn Controller {
        if self.rate.load(Ordering::Relaxed) > 0 {
            self.brutal.as_ref()
        } else {
            self.normal.as_ref()
        }
    }
}
impl Controller for Negotiated {
    fn on_sent(&mut self, now: Instant, bytes: u64, number: u64) {
        self.normal.on_sent(now, bytes, number);
        self.brutal.on_sent(now, bytes, number);
    }
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        limited: bool,
        rtt: &RttEstimator,
    ) {
        self.normal.on_ack(now, sent, bytes, limited, rtt);
        self.brutal.on_ack(now, sent, bytes, limited, rtt);
    }
    fn on_end_acks(&mut self, now: Instant, flight: u64, limited: bool, largest: Option<u64>) {
        self.normal.on_end_acks(now, flight, limited, largest);
        self.brutal.on_end_acks(now, flight, limited, largest);
    }
    fn on_congestion_event(&mut self, now: Instant, sent: Instant, persistent: bool, lost: u64) {
        self.normal.on_congestion_event(now, sent, persistent, lost);
        self.brutal.on_congestion_event(now, sent, persistent, lost);
    }
    fn on_mtu_update(&mut self, mtu: u16) {
        self.normal.on_mtu_update(mtu);
        self.brutal.on_mtu_update(mtu);
    }
    fn window(&self) -> u64 {
        self.selected().window()
    }
    fn metrics(&self) -> ControllerMetrics {
        self.selected().metrics()
    }
    fn initial_window(&self) -> u64 {
        self.selected().initial_window()
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            normal: self.normal.clone_box(),
            brutal: self.brutal.clone_box(),
            rate: self.rate.clone(),
        })
    }
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
