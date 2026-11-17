//! Trojan 请求与 UDP 帧；TLS / WS 由下层提供。
use crate::{proto_err, socks5};
use oryn_config::TargetAddr;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn request(password: &str, target: &TargetAddr, udp: bool) -> io::Result<Vec<u8>> {
    use sha2::Digest;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut out = Vec::with_capacity(320);
    for b in digest {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.push(if udp { 3 } else { 1 });
    socks5::encode_addr(target, &mut out)?;
    out.extend_from_slice(b"\r\n");
    Ok(out)
}
pub fn encode_udp(target: &TargetAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let len =
        u16::try_from(payload.len()).map_err(|_| proto_err("Trojan UDP payload too large"))?;
    let mut out = Vec::with_capacity(payload.len() + 262);
    socks5::encode_addr(target, &mut out)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(payload);
    Ok(out)
}
pub async fn read_udp<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut [u8],
) -> io::Result<(usize, TargetAddr)> {
    let addr = socks5::read_addr(s).await?;
    let len = s.read_u16().await? as usize;
    let mut crlf = [0; 2];
    s.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        return Err(proto_err("Trojan UDP invalid delimiter"));
    }
    let n = crate::vless::read_payload(s, len, buf).await?;
    Ok((n, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};
    #[tokio::test]
    async fn request_and_udp_boundaries() {
        let target = TargetAddr::Domain("example.com".into(), 53);
        let request = request("password", &target, true).unwrap();
        assert_eq!(
            &request[..56],
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert_eq!(&request[56..60], &[13, 10, 3, 3]);
        let a = encode_udp(&target, b"abcdef").unwrap();
        let b = encode_udp(&TargetAddr::Ip("[::1]:53".parse().unwrap()), b"next").unwrap();
        let (mut r, mut w) = duplex(1024);
        w.write_all(&a).await.unwrap();
        w.write_all(&b).await.unwrap();
        let mut small = [0; 3];
        assert_eq!(read_udp(&mut r, &mut small).await.unwrap(), (3, target));
        assert_eq!(&small, b"abc");
        let mut next = [0; 4];
        assert_eq!(read_udp(&mut r, &mut next).await.unwrap().0, 4);
        assert_eq!(&next, b"next");
        assert!(encode_udp(&TargetAddr::Domain("x".into(), 1), &vec![0; 65536]).is_err());
    }
}
