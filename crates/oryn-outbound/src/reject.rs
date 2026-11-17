use std::io;

use async_trait::async_trait;
use oryn_config::TargetAddr;

use crate::{BoxStream, Outbound, PacketConn};

pub struct RejectOutbound {
    tag: String,
}

impl RejectOutbound {
    pub fn new(tag: String) -> Self {
        RejectOutbound { tag }
    }
}

fn rejected() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule")
}

#[async_trait]
impl Outbound for RejectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn kind(&self) -> &'static str {
        "reject"
    }

    fn is_reject(&self) -> bool {
        true
    }

    async fn connect_tcp(&self, _target: &TargetAddr) -> io::Result<BoxStream> {
        Err(rejected())
    }

    async fn bind_udp(&self, _first_target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        Err(rejected())
    }
}
