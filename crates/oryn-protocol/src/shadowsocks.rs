//! 复用 MIT shadowsocks-rust 的协议层，不使用其 DNS / 拨号与会话管理。
use oryn_config::TargetAddr;
pub use shadowsocks::relay::socks5::Address;
pub use shadowsocks::relay::{
    tcprelay::{proxy_stream::ProxyServerStream, ProxyClientStream},
    udprelay::{crypto_io, options::UdpSocketControlData},
};
pub use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context,
};
use std::io;

pub fn address(target: &TargetAddr) -> io::Result<Address> {
    match target {
        TargetAddr::Ip(a) => Ok(Address::SocketAddress(*a)),
        TargetAddr::Domain(d, p) if !d.is_empty() && d.len() <= 255 => {
            Ok(Address::DomainNameAddress(d.clone(), *p))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks invalid domain length",
        )),
    }
}
pub fn target(addr: Address) -> TargetAddr {
    match addr {
        Address::SocketAddress(a) => TargetAddr::Ip(a),
        Address::DomainNameAddress(d, p) => TargetAddr::Domain(d, p),
    }
}
pub fn config(server: &TargetAddr, cipher: &str, password: &str) -> io::Result<ServerConfig> {
    let method = cipher.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported Shadowsocks cipher",
        )
    })?;
    let server = match server {
        TargetAddr::Ip(a) => shadowsocks::config::ServerAddr::SocketAddr(*a),
        TargetAddr::Domain(d, p) => shadowsocks::config::ServerAddr::DomainName(d.clone(), *p),
    };
    ServerConfig::new(server, password, method).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    #[test]
    fn udp_authentication_and_addresses() {
        for (cipher, password) in [
            ("aes-128-gcm", "password"),
            ("aes-256-gcm", "password"),
            ("chacha20-ietf-poly1305", "password"),
            ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
            (
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
            (
                "2022-blake3-chacha20-poly1305",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        ] {
            let target = TargetAddr::Ip("[2001:db8::1]:53".parse().unwrap());
            let config = config(
                &TargetAddr::Ip("127.0.0.1:8388".parse().unwrap()),
                cipher,
                password,
            )
            .unwrap();
            let context = Context::new(ServerType::Local);
            let mut control = UdpSocketControlData::default();
            control.client_session_id = 7;
            control.server_session_id = 9;
            control.packet_id = 42;
            let mut packet = BytesMut::new();
            crypto_io::encrypt_server_payload(
                &context,
                config.method(),
                config.key(),
                &address(&target).unwrap(),
                &control,
                b"payload",
                &mut packet,
            );
            let mut corrupt = packet.to_vec();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(
                crypto_io::decrypt_server_payload(
                    &context,
                    config.method(),
                    config.key(),
                    &mut corrupt
                )
                .is_err(),
                "{cipher}"
            );
            let (n, addr, received) = crypto_io::decrypt_server_payload(
                &context,
                config.method(),
                config.key(),
                &mut packet,
            )
            .unwrap();
            assert_eq!(&packet[..n], b"payload");
            assert_eq!(super::target(addr), target);
            if cipher.starts_with("2022-") {
                let c = received.unwrap();
                assert_eq!(
                    (c.client_session_id, c.server_session_id, c.packet_id),
                    (7, 9, 42)
                );
            }
        }
    }

    #[tokio::test]
    async fn cipher_none_tcp_and_udp_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for password in ["", "unused-secret"] {
            let cfg = config(
                &TargetAddr::Ip("127.0.0.1:8388".parse().unwrap()),
                "none",
                password,
            )
            .unwrap();
            let target = TargetAddr::Domain("example.com".into(), 80);

            // UDP 往返（明文无认证标签）
            let context = Context::new(ServerType::Local);
            let control = UdpSocketControlData::default();
            let mut packet = BytesMut::new();
            crypto_io::encrypt_server_payload(
                &context,
                cfg.method(),
                cfg.key(),
                &address(&target).unwrap(),
                &control,
                b"ping",
                &mut packet,
            );
            let (n, addr, _) =
                crypto_io::decrypt_server_payload(&context, cfg.method(), cfg.key(), &mut packet)
                    .unwrap();
            assert_eq!(&packet[..n], b"ping");
            assert_eq!(super::target(addr), target);

            // TCP 往返
            let (client_io, server_io) = tokio::io::duplex(4096);
            let mut client = ProxyClientStream::from_stream(
                Context::new_shared(ServerType::Local),
                client_io,
                &cfg,
                address(&target).unwrap(),
            );
            let mut server = ProxyServerStream::from_stream(
                Context::new_shared(ServerType::Server),
                server_io,
                cfg.method(),
                cfg.key(),
            );
            client.write_all(b"hello").await.unwrap();
            client.flush().await.unwrap();
            let got_addr = server.handshake().await.unwrap();
            assert_eq!(super::target(got_addr), target);
            let mut buf = [0u8; 5];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            server.write_all(b"world").await.unwrap();
            server.flush().await.unwrap();
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"world");
        }
    }
}
