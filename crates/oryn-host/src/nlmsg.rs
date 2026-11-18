//! rtnetlink 消息的编码与解析（纯数据，不做系统调用，因此可在任何平台上测试）。
//!
//! 只实现 Oryn 用到的几种消息：链路 up / MTU、地址、路由、策略规则，以及路由表 dump。
//! 布局见 Linux uapi `netlink.h`、`rtnetlink.h`、`fib_rules.h`；字段均为主机字节序。

pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_CREATE: u16 = 0x400;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const IFF_UP: u32 = 0x1;
pub const IFLA_MTU: u16 = 4;

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_FLAGS: u16 = 8;
pub const IFA_F_NODAD: u32 = 0x02;

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_TABLE: u16 = 15;
pub const RTPROT_STATIC: u8 = 4;
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RTN_UNICAST: u8 = 1;
pub const RT_TABLE_UNSPEC: u8 = 0;
pub const RT_TABLE_MAIN: u32 = 254;

pub const FRA_DST: u16 = 1;
pub const FRA_PRIORITY: u16 = 6;
pub const FRA_FWMARK: u16 = 10;
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
pub const FRA_TABLE: u16 = 15;
pub const FRA_FWMASK: u16 = 16;
pub const FR_ACT_TO_TBL: u8 = 1;
pub const FR_ACT_UNSPEC: u8 = 0;
pub const FIB_RULE_INVERT: u32 = 0x2;

pub const RTMGRP_LINK: u32 = 0x1;
pub const RTMGRP_IPV4_ROUTE: u32 = 0x40;
pub const RTMGRP_IPV6_ROUTE: u32 = 0x400;

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// 一条待发送的 netlink 消息。
pub struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    /// `header` 是消息类型对应的固定头（`ifinfomsg`、`ifaddrmsg`、`rtmsg`、`fib_rule_hdr`）。
    pub fn new(msg_type: u16, flags: u16, header: &[u8]) -> Msg {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(header);
        buf.resize(align4(buf.len()), 0);
        Msg { buf }
    }

    pub fn attr(mut self, attr_type: u16, data: &[u8]) -> Msg {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn attr_u32(self, attr_type: u16, value: u32) -> Msg {
        self.attr(attr_type, &value.to_ne_bytes())
    }

    /// 写入长度与序号，得到可发送的字节。
    pub fn finish(mut self, seq: u32) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        self.buf
    }
}

/// `ifinfomsg`：设置链路标志。
pub fn ifinfomsg(index: i32, flags: u32, change: u32) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h[12..16].copy_from_slice(&change.to_ne_bytes());
    h
}

/// `ifaddrmsg`。
pub fn ifaddrmsg(family: u8, prefix: u8, index: u32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = family;
    h[1] = prefix;
    h[4..8].copy_from_slice(&index.to_ne_bytes());
    h
}

/// `rtmsg`；表号大于 255 时 `rtm_table` 写 `RT_TABLE_UNSPEC`，真实表号放 `RTA_TABLE`。
pub fn rtmsg(family: u8, dst_len: u8, table: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = family;
    h[1] = dst_len;
    h[4] = u8::try_from(table).unwrap_or(RT_TABLE_UNSPEC);
    h[5] = RTPROT_STATIC;
    h[6] = RT_SCOPE_UNIVERSE;
    h[7] = RTN_UNICAST;
    h
}

/// `fib_rule_hdr`。
pub fn fib_rule_hdr(family: u8, dst_len: u8, action: u8, flags: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0] = family;
    h[1] = dst_len;
    h[7] = action;
    h[8..12].copy_from_slice(&flags.to_ne_bytes());
    h
}

/// 收到的一条消息：类型、序号、去掉 `nlmsghdr` 后的内容。
pub struct Received<'a> {
    pub msg_type: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// 依次取出缓冲区中的 netlink 消息；遇到截断或非法长度即停止。
pub fn messages(mut buf: &[u8]) -> impl Iterator<Item = Received<'_>> {
    std::iter::from_fn(move || {
        if buf.len() < NLMSG_HDRLEN {
            return None;
        }
        let len = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || len > buf.len() {
            return None;
        }
        let msg = Received {
            msg_type: u16::from_ne_bytes(buf[4..6].try_into().unwrap()),
            seq: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            payload: &buf[NLMSG_HDRLEN..len],
        };
        buf = &buf[align4(len).min(buf.len())..];
        Some(msg)
    })
}

/// `NLMSG_ERROR` 的错误码（负 errno；0 为确认）。
pub fn error_code(payload: &[u8]) -> Option<i32> {
    payload.get(0..4).map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
}

/// 依次取出属性 `(类型, 数据)`。
pub fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if buf.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes(buf[0..2].try_into().unwrap()) as usize;
        if len < 4 || len > buf.len() {
            return None;
        }
        // 去掉 NLA_F_NESTED / NLA_F_NET_BYTEORDER 标志位
        let ty = u16::from_ne_bytes(buf[2..4].try_into().unwrap()) & 0x3fff;
        let data = &buf[4..len];
        buf = &buf[align4(len).min(buf.len())..];
        Some((ty, data))
    })
}

pub fn attr_u32(data: &[u8]) -> Option<u32> {
    data.get(0..4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

/// 路由 dump 中的一条路由（只取用到的字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteInfo {
    pub family: u8,
    pub dst_len: u8,
    pub route_type: u8,
    pub table: u32,
    pub oif: Option<u32>,
    pub priority: u32,
}

pub fn parse_route(payload: &[u8]) -> Option<RouteInfo> {
    let h = payload.get(0..12)?;
    let mut info = RouteInfo {
        family: h[0],
        dst_len: h[1],
        route_type: h[7],
        table: h[4] as u32,
        oif: None,
        priority: 0,
    };
    for (ty, data) in attrs(&payload[12..]) {
        match ty {
            RTA_TABLE => info.table = attr_u32(data)?,
            RTA_OIF => info.oif = attr_u32(data),
            RTA_PRIORITY => info.priority = attr_u32(data)?,
            _ => {}
        }
    }
    Some(info)
}

/// 主表里的默认路由中选出跃点最小的出接口，跳过 `exclude`（隧道自身）。
pub fn pick_default_interface(routes: &[RouteInfo], exclude: Option<u32>) -> Option<u32> {
    routes
        .iter()
        .filter(|r| r.dst_len == 0 && r.table == RT_TABLE_MAIN && r.route_type == RTN_UNICAST)
        .filter_map(|r| r.oif.filter(|i| Some(*i) != exclude).map(|i| (r.priority, i)))
        .min()
        .map(|(_, i)| i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_rule_message_with_aligned_attributes() {
        let bytes = Msg::new(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK, &fib_rule_hdr(AF_INET, 0, FR_ACT_TO_TBL, FIB_RULE_INVERT))
            .attr_u32(FRA_PRIORITY, 9002)
            .attr_u32(FRA_FWMARK, 2022)
            .attr(FRA_DST, &[10, 0, 0])
            .finish(7);
        assert_eq!(bytes.len() % 4, 0);
        let msgs: Vec<_> = messages(&bytes).collect();
        assert_eq!(msgs.len(), 1);
        assert_eq!((msgs[0].msg_type, msgs[0].seq), (RTM_NEWRULE, 7));
        let attrs: Vec<_> = attrs(&msgs[0].payload[12..]).collect();
        assert_eq!(attrs[0], (FRA_PRIORITY, &9002u32.to_ne_bytes()[..]));
        assert_eq!(attrs[1], (FRA_FWMARK, &2022u32.to_ne_bytes()[..]));
        assert_eq!(attrs[2], (FRA_DST, &[10u8, 0, 0][..]));
        assert_eq!(u32::from_ne_bytes(msgs[0].payload[8..12].try_into().unwrap()), FIB_RULE_INVERT);
    }

    #[test]
    fn parses_routes_and_picks_lowest_metric_default() {
        let route = |table: u32, dst_len: u8, oif: u32, prio: u32| {
            let msg = Msg::new(RTM_NEWROUTE, 0, &rtmsg(AF_INET, dst_len, table))
                .attr_u32(RTA_TABLE, table)
                .attr_u32(RTA_OIF, oif)
                .attr_u32(RTA_PRIORITY, prio)
                .finish(1);
            let payload = messages(&msg).next().unwrap().payload.to_vec();
            parse_route(&payload).unwrap()
        };
        let routes = [
            route(254, 0, 3, 600),
            route(254, 0, 2, 100),
            route(2022, 0, 9, 0),
            route(254, 24, 4, 0),
            route(254, 0, 9, 0),
        ];
        assert_eq!(routes[2].table, 2022);
        assert_eq!(pick_default_interface(&routes, Some(9)), Some(2));
        assert_eq!(pick_default_interface(&routes[2..4], Some(9)), None);
    }

    #[test]
    fn truncated_input_stops_iteration() {
        let bytes = Msg::new(NLMSG_DONE, 0, &[]).finish(1);
        assert_eq!(messages(&bytes[..10]).count(), 0);
        let mut bad = bytes.clone();
        bad[0..4].copy_from_slice(&1000u32.to_ne_bytes());
        assert_eq!(messages(&bad).count(), 0);
        assert_eq!(attrs(&[8, 0, 1, 0, 1]).count(), 0);
    }
}
