use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq, Eq)]
pub enum Socks5Command {
    Connect {
        target: String,
    },
    /// UDP ASSOCIATE：附带客户端请求里给出的（可为 0 的）客户端 UDP 地址
    UdpAssociate {
        client_udp: Option<SocketAddr>,
    },
}

pub struct Socks5Handshake;

/// SOCKS5 回复码
const REP_SUCCESS: u8 = 0x00;
const REP_COMMAND_UNSUPPORTED: u8 = 0x07;
const REP_ADDRESS_UNSUPPORTED: u8 = 0x08;

impl Socks5Handshake {
    /// 完成无认证 SOCKS5 协商并返回要执行的命令。
    ///
    /// 修复：旧实现对 UDP ASSOCIATE **完全不回响应**就返回 Ok，调用方随后直接
    /// drop 连接；客户端把「服务器无故断开」理解为代理不可用，进而连 TCP 都放弃。
    /// 现在要么回正确的 BND.ADDR（真做转发），要么回 0x07（命令不支持）。
    pub async fn handle(stream: &mut TcpStream) -> io::Result<Socks5Command> {
        // 1. 方法协商
        let mut ver_buf = [0u8; 2];
        stream.read_exact(&mut ver_buf).await?;
        if ver_buf[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SOCKS version: {}", ver_buf[0]),
            ));
        }

        let nmethods = ver_buf[1] as usize;
        if nmethods == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 greeting with zero methods",
            ));
        }
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        if !methods.contains(&0x00) {
            // 0xFF = 无可用方法，必须让客户端明确知道而不是假装成功
            stream.write_all(&[0x05, 0xFF]).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client requires authentication but no-auth was not offered",
            ));
        }
        stream.write_all(&[0x05, 0x00]).await?;

        // 2. 请求
        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;
        if req_header[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS5 request version",
            ));
        }

        let cmd = req_header[1];
        let atyp = req_header[3];

        let target_host: String = match atyp {
            0x01 => {
                let mut ip = [0u8; 4];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                format!("{}:{}", Ipv4Addr::from(ip), u16::from_be_bytes(port))
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let domain_len = len[0] as usize;
                if domain_len == 0 {
                    Self::reply(stream, REP_ADDRESS_UNSUPPORTED, &socks5_ipv4_zero()).await?;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "empty SOCKS5 domain"));
                }
                let mut domain = vec![0u8; domain_len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 domain name")
                })?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                format!("{}:{}", domain, u16::from_be_bytes(port))
            }
            0x04 => {
                let mut ip = [0u8; 16];
                stream.read_exact(&mut ip).await?;
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await?;
                let v6 = Ipv6Addr::from(ip);
                format!("[{}]:{}", v6, u16::from_be_bytes(port))
            }
            other => {
                Self::reply(stream, REP_ADDRESS_UNSUPPORTED, &socks5_ipv4_zero()).await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 ATYP: {other}"),
                ));
            }
        };

        let client_udp: Option<SocketAddr> = target_host
            .parse()
            .ok()
            .filter(|a: &SocketAddr| !a.ip().is_unspecified() && a.port() != 0);

        match cmd {
            0x01 => {
                Self::reply(stream, REP_SUCCESS, &socks5_ipv4_zero()).await?;
                Ok(Socks5Command::Connect { target: target_host })
            }
            0x03 => {
                // UDP ASSOCIATE：BND.ADDR 必须告诉客户端往哪发数据报。
                // 我们让客户端继续用它原本的 UDP 目标（本代理监听地址），
                // 所以回填本连接的本地地址，端口与本 TCP 监听端口一致。
                let bnd = stream.local_addr().unwrap_or_else(|_| ([127, 0, 0, 1], 1080).into());
                Self::reply(stream, REP_SUCCESS, &socks5_addr_bytes(bnd)).await?;
                Ok(Socks5Command::UdpAssociate { client_udp })
            }
            _ => {
                Self::reply(stream, REP_COMMAND_UNSUPPORTED, &socks5_ipv4_zero()).await?;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 CMD: {cmd}"),
                ))
            }
        }
    }

    async fn reply(stream: &mut TcpStream, rep: u8, bnd: &[u8]) -> io::Result<()> {
        let mut out = vec![0x05, rep, 0x00];
        out.extend_from_slice(bnd);
        stream.write_all(&out).await?;
        stream.flush().await
    }
}

/// ATYP=1 + 0.0.0.0:0（RFC 1928 允许的占位 BND 地址）
fn socks5_ipv4_zero() -> Vec<u8> {
    vec![0x01, 0, 0, 0, 0, 0, 0]
}

/// 按实际本地地址族编码 BND.ADDR
fn socks5_addr_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut out = vec![0x01];
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = vec![0x04];
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
            out
        }
    }
}

/// SOCKS5 UDP 关联的请求帧：RSV(2) FRAG(1) ATYP + ADDR + PORT + DATA
pub struct Socks5UdpRequest {
    pub target: SocketAddr,
    pub data: Vec<u8>,
}

/// 解析 SOCKS5 UDP relay 报文（RFC 1928）。老式实现没有分段支持，非零 FRAG 直接拒绝。
pub fn parse_socks5_udp(packet: &[u8]) -> io::Result<Socks5UdpRequest> {
    if packet.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short SOCKS5 UDP datagram"));
    }
    // 线上格式：RSV(2 字节) + FRAG(1 字节) + ATYP + ADDR + PORT + DATA
    if packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 fragmentation not supported (FRAG={})", packet[2]),
        ));
    }
    let (target, consumed) = match packet[3] {
        0x01 => {
            if packet.len() < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv4 UDP header",
                ));
            }
            let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            (SocketAddr::from((ip, port)), 10)
        }
        0x03 => {
            let len = packet[4] as usize;
            let end = 5 + len + 2;
            if packet.len() < end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated domain UDP header",
                ));
            }
            let domain = String::from_utf8(packet[5..5 + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 domain"))?;
            let port = u16::from_be_bytes([packet[5 + len], packet[5 + len + 1]]);
            // UDP 路径不做域名解析（客户端通常已解析；真要解析交给服务端隧道）
            (
                SocketAddr::new(
                    domain.parse::<std::net::IpAddr>().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("SOCKS5 UDP domain not an IP: {domain}"),
                        )
                    })?,
                    port,
                ),
                end,
            )
        }
        0x04 => {
            if packet.len() < 22 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated IPv6 UDP header",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&packet[4..20]);
            let port = u16::from_be_bytes([packet[20], packet[21]]);
            (SocketAddr::from((Ipv6Addr::from(ip), port)), 22)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 UDP ATYP: {other}"),
            ));
        }
    };
    Ok(Socks5UdpRequest { target, data: packet[consumed..].to_vec() })
}

/// 把响应封装成 SOCKS5 UDP relay 报文
pub fn wrap_socks5_udp(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match target {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// 按 ATYP 读取变长回复（BND 地址族取决于代理本地地址）
    async fn read_reply(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        let tail_len: usize = match head[3] {
            0x01 => 6,
            0x04 => 18,
            0x03 => {
                // ATYP=3 时第 5 字节才是域名长度，必须单独读，不能索引 head
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await.unwrap();
                1 + dlen[0] as usize + 2
            }
            _ => 0,
        };
        if tail_len == 0 {
            return head.to_vec();
        }
        let mut tail = vec![0u8; tail_len];
        stream.read_exact(&mut tail).await.unwrap();
        let mut out = head.to_vec();
        out.extend_from_slice(&tail);
        out
    }

    async fn pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let a = TcpStream::connect(addr).await?;
        let (b, _) = listener.accept().await?;
        Ok((a, b))
    }

    #[tokio::test]
    async fn connect_handshake_succeeds() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x05, 0x00]);

        client.write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]).await.unwrap();
        let rep = read_reply(&mut client).await;
        assert_eq!(&rep[0..3], &[0x05, 0x00, 0x00]);
        assert_eq!(rep[3], 0x01);
        assert_eq!(rep.len(), 10);

        let cmd = h.await.unwrap().unwrap();
        assert_eq!(cmd, Socks5Command::Connect { target: "1.2.3.4:443".to_string() });
    }

    /// 关键回归：UDP ASSOCIATE 必须收到成功响应而不是 EOF
    #[tokio::test]
    async fn udp_associate_replies_bnd_addr() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();

        // CMD=3, ATYP=1, 0.0.0.0:0
        client.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();

        let rep = tokio::time::timeout(std::time::Duration::from_secs(2), read_reply(&mut client))
            .await
            .expect("must reply, not silently close");
        assert_eq!(&rep[0..2], &[0x05, REP_SUCCESS], "UDP ASSOCIATE rejected: {rep:?}");
        assert!(rep.len() >= 10);

        let cmd = h.await.unwrap().unwrap();
        assert!(matches!(cmd, Socks5Command::UdpAssociate { .. }));
    }

    #[tokio::test]
    async fn unsupported_command_gets_reply_07() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        // CMD=2 (BIND)
        client.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let rep = read_reply(&mut client).await;
        assert_eq!(rep[1], REP_COMMAND_UNSUPPORTED);
        assert!(h.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn bad_atyp_gets_reply_08() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00, 0x7F, 0, 0, 0, 0, 0, 0]).await.unwrap();
        // ATYP 不被支持时回复仍带一个占位 BND（0x01 族），read_reply 处理其长度
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_ADDRESS_UNSUPPORTED);
        assert!(h.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn auth_required_is_refused_not_faked() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });
        // 只提 GSSAPI(0x01)，没提 no-auth
        client.write_all(&[0x05, 0x01, 0x01]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x05, 0xFF]);
        assert!(h.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn domain_and_ipv6_targets_are_normalized() {
        let (mut client, mut proxy) = pair().await.unwrap();
        let h = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy).await });
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();

        let mut req: Vec<u8> = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let rep = read_reply(&mut client).await;
        assert_eq!(rep[1], REP_SUCCESS);
        let cmd = h.await.unwrap().unwrap();
        assert_eq!(cmd, Socks5Command::Connect { target: "example.com:443".into() });

        // IPv6
        let (mut client2, mut proxy2) = pair().await.unwrap();
        let h2 = tokio::spawn(async move { Socks5Handshake::handle(&mut proxy2).await });
        client2.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut a2 = [0u8; 2];
        client2.read_exact(&mut a2).await.unwrap();
        let mut req2: Vec<u8> = vec![0x05, 0x01, 0x00, 0x04];
        req2.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        req2.extend_from_slice(&8443u16.to_be_bytes());
        client2.write_all(&req2).await.unwrap();
        let rep2 = read_reply(&mut client2).await;
        assert_eq!(rep2[1], REP_SUCCESS);
        match h2.await.unwrap().unwrap() {
            Socks5Command::Connect { target } => assert_eq!(target, "[2001:db8::1]:8443"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn udp_frame_parse_v4_roundtrip() {
        let mut pkt = vec![0, 0, 0, 0x01];
        pkt.extend_from_slice(&[8, 8, 8, 8]);
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(b"dnsquery");
        let r = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(r.target, "8.8.8.8:53".parse().unwrap());
        assert_eq!(r.data, b"dnsquery");

        let wrapped = wrap_socks5_udp(r.target, &r.data);
        assert_eq!(wrapped, pkt);
    }

    #[test]
    fn frag_offset_is_per_rfc1928() {
        // RSV(0,0) FRAG(0) ATYP=1 ...
        let mut ok = vec![0x00, 0x00, 0x00, 0x01];
        ok.extend_from_slice(&[9, 9, 9, 9]);
        ok.extend_from_slice(&53u16.to_be_bytes());
        ok.extend_from_slice(b"z");
        assert!(parse_socks5_udp(&ok).is_ok());
        // FRAG=1（分片）必须被拒
        let mut frag = ok.clone();
        frag[2] = 1;
        assert!(parse_socks5_udp(&frag).is_err());
        // RSV 非零不强制拒绝（宽松兼容实现），但 ATYP 必须合法
        let mut rsv = ok.clone();
        rsv[0] = 0xAA;
        assert!(parse_socks5_udp(&rsv).is_ok());
    }

    #[test]
    fn udp_frame_parse_v6_and_errors() {
        let mut pkt = vec![0, 0, 0, 0x04];
        let mut ip = [0u8; 16];
        ip[0] = 0x20;
        ip[15] = 0x01;
        pkt.extend_from_slice(&ip);
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(b"quic");
        let r = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(r.target, "[2000::1]:443".parse().unwrap());
        assert_eq!(&r.data, b"quic");
        // 往返一致
        assert_eq!(wrap_socks5_udp(r.target, &r.data), pkt);

        // FRAG != 0 必须拒绝（index 2）
        let frag = vec![0, 0, 1, 0x01, 1, 1, 1, 1, 0, 53, b'x'];
        assert!(parse_socks5_udp(&frag).is_err());
        assert!(parse_socks5_udp(&[0, 0]).is_err());
        // 截断
        assert!(parse_socks5_udp(&[0, 0, 0, 0x01, 1, 2, 3]).is_err());
        assert!(parse_socks5_udp(&[0, 0, 0, 0x04, 1, 2]).is_err());
        // 域名（非 IP）在 UDP 路径不支持
        let mut d = vec![0, 0, 0, 0x03, 3];
        d.extend_from_slice(b"foo");
        d.extend_from_slice(&53u16.to_be_bytes());
        assert!(parse_socks5_udp(&d).is_err());
        assert!(parse_socks5_udp(&[0, 0, 0, 0x09, 0, 0]).is_err());
    }

    #[test]
    fn bnd_encoder_matches_family() {
        let v4 = socks5_addr_bytes("1.2.3.4:443".parse().unwrap());
        assert_eq!(v4[0], 0x01);
        assert_eq!(v4.len(), 7);
        let v6 = socks5_addr_bytes("[2001:db8::1]:443".parse().unwrap());
        assert_eq!(v6[0], 0x04);
        assert_eq!(v6.len(), 19);
        assert_eq!(socks5_ipv4_zero(), vec![0x01, 0, 0, 0, 0, 0, 0]);
    }
}
