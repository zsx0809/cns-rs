use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio_util::codec::{Decoder, Encoder};

/// httpUDP 数据报文强类型抽象
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub peer: SocketAddr,
    pub payload: Bytes,
}

/// httpUDP 协议帧编解码器
///
/// 帧格式：`[2 字节小端序 pkg_len] [pkg_len 字节帧体]`
/// 帧体：`[flag0][flag1=0][flag2=0][addr_type] [IP] [2 字节大端序 port] [payload]`
#[derive(Default, Debug)]
pub struct HttpUdpCodec {
    /// 已丢弃的坏帧计数，便于上层观测（不再刷日志）
    pub error_count: u64,
}

/// 单帧体最大长度（2 字节小端长度前缀的硬上限）
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;
/// IPv4/IPv6 帧头字节数
pub const HEADER_LEN_V4: usize = 10;
pub const HEADER_LEN_V6: usize = 22;
/// 最大可承载载荷（以最长的 IPv6 头计）
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - HEADER_LEN_V6;

impl HttpUdpCodec {
    pub fn new() -> Self {
        Self { error_count: 0 }
    }
}

impl Decoder for HttpUdpCodec {
    type Item = UdpPacket;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // 至少需要 2 字节来获取包长度
        if src.len() < 2 {
            return Ok(None);
        }

        // 小端序获取后续帧长度
        let pkg_len = u16::from_le_bytes([src[0], src[1]]) as usize;
        let total_frame_len = 2 + pkg_len;

        // 长度下限校验（IPv4 头 10 字节），坏长度直接丢整帧以保持字节流对齐
        if pkg_len < 10 {
            self.error_count += 1;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid httpUDP packet length: {pkg_len}"),
            ));
        }

        // 如果缓冲区尚未收齐完整帧，预留空间等待更多数据
        if src.len() < total_frame_len {
            src.reserve(total_frame_len - src.len());
            return Ok(None);
        }

        // 校验基本长度边界（IPv4 头部至少 10 字节）
        // 消费 2 字节长度前缀
        src.advance(2);

        // 提取整个帧体
        let mut frame_body = src.split_to(pkg_len);

        // 协议规范：字节 [1, 2] 必须为 0, 0
        if frame_body[1] != 0 || frame_body[2] != 0 {
            self.error_count += 1;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Malformed httpUDP frame magic flags",
            ));
        }

        let address_type = frame_body[3];
        let peer = match address_type {
            1 => {
                // IPv4: [4 字节 flag] [4 字节 IP] [2 字节 Port] = 10 字节头
                if frame_body.len() < 10 {
                    self.error_count += 1;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Truncated IPv4 httpUDP header",
                    ));
                }
                let ip = Ipv4Addr::new(frame_body[4], frame_body[5], frame_body[6], frame_body[7]);
                let port = u16::from_be_bytes([frame_body[8], frame_body[9]]);
                frame_body.advance(10);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            3 => {
                // IPv6: [4 字节 flag] [16 字节 IP] [2 字节 Port] = 22 字节头
                if frame_body.len() < 22 {
                    self.error_count += 1;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Truncated IPv6 httpUDP header",
                    ));
                }
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&frame_body[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                let port = u16::from_be_bytes([frame_body[20], frame_body[21]]);
                frame_body.advance(22);
                SocketAddr::new(IpAddr::V6(ip), port)
            }
            other => {
                self.error_count += 1;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported address type: {other}"),
                ));
            }
        };

        Ok(Some(UdpPacket { peer, payload: frame_body.freeze() }))
    }
}

impl Encoder<UdpPacket> for HttpUdpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: UdpPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        let header_len = match item.peer {
            SocketAddr::V4(_) => 10,
            SocketAddr::V6(_) => 22,
        };

        // 修复：旧实现 `as u16` 静默截断超长载荷，写出坏帧污染整条字节流
        let pkg_len = payload_len
            .checked_add(header_len)
            .filter(|v| *v <= MAX_FRAME_LEN)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("httpUDP frame too large: {payload_len} + {header_len} bytes"),
                )
            })?;

        dst.reserve(2 + pkg_len);
        // 2 字节小端序长度
        dst.put_u16_le(pkg_len as u16);
        match item.peer {
            SocketAddr::V4(v4) => {
                // 4 字节标识: [0, 0, 0, 1]
                dst.put_slice(&[0, 0, 0, 1]);
                // 4 字节 IPv4
                dst.put_slice(&v4.ip().octets());
                // 2 字节大端序 Port
                dst.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                // 4 字节标识: [0, 0, 0, 3]
                dst.put_slice(&[0, 0, 0, 3]);
                // 16 字节 IPv6
                dst.put_slice(&v6.ip().octets());
                // 2 字节大端序 Port
                dst.put_u16(v6.port());
            }
        }
        // 载荷
        dst.put_slice(&item.payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_ipv4_roundtrip() {
        let mut codec = HttpUdpCodec::new();
        let peer: SocketAddr = "1.2.3.4:8080".parse().unwrap();
        let payload = Bytes::from_static(b"PING UDP 12345");

        let packet = UdpPacket { peer, payload: payload.clone() };

        let mut buf = BytesMut::new();
        codec.encode(packet.clone(), &mut buf).unwrap();

        // 验证编码后的小端序长度和头
        assert_eq!(buf[0], (payload.len() + 10) as u8);
        assert_eq!(buf[1], 0);

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.peer, peer);
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_codec_ipv6_roundtrip() {
        let mut codec = HttpUdpCodec::new();
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let payload = Bytes::from_static(b"DNS QUERY PAYLOAD");

        let packet = UdpPacket { peer, payload: payload.clone() };

        let mut buf = BytesMut::new();
        codec.encode(packet.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.peer, peer);
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_waits_for_more_bytes() {
        let mut codec = HttpUdpCodec::new();
        let peer: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let mut buf = BytesMut::new();
        codec
            .encode(UdpPacket { peer, payload: Bytes::from_static(b"0123456789") }, &mut buf)
            .unwrap();

        // 逐字节喂入，除最后一字节外都应返回 None（而不是报错）
        let full = buf.clone();
        for keep in 0..full.len() {
            let mut partial = BytesMut::from(&full[..keep]);
            let res = codec.decode(&mut partial).unwrap();
            assert!(res.is_none(), "keep={keep} should be incomplete");
        }
    }

    #[test]
    fn test_decode_rejects_too_short_frame_len() {
        let mut codec = HttpUdpCodec::new();
        let mut buf = BytesMut::from(&[3u8, 0, 0, 0, 0, 1][..]);
        assert!(codec.decode(&mut buf).is_err());
        assert_eq!(codec.error_count, 1);
    }

    #[test]
    fn test_decode_rejects_bad_flags_and_addr_type() {
        let mut codec = HttpUdpCodec::new();
        let peer: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let mut buf = BytesMut::new();
        codec.encode(UdpPacket { peer, payload: Bytes::from_static(b"hello") }, &mut buf).unwrap();
        // 帧体布局: [len_lo][len_hi][f0][f1=0][f2=0][addr_type][ip4][port2][payload]
        buf[5] = 4; // 破坏保留标志位 f2
        assert!(codec.decode(&mut buf).is_err());

        let mut buf2 = BytesMut::new();
        // pkg_len=12，帧体 addr_type=7（未定义），补齐到 2+12=14 字节
        buf2.extend_from_slice(&[12, 0, 0, 0, 0, 7, 1, 2, 3, 4, 0, 53, 0xAA, 0xBB]);
        assert!(codec.decode(&mut buf2).is_err());

        let mut buf3 = BytesMut::new();
        // pkg_len=15 但 addr_type=3 需要 22 字节头 → 截断
        buf3.extend_from_slice(&[
            15, 0, 0, 0, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        ]);
        // 21 字节 < 2 + 15 = 17? 否，已收齐 → 应报截断错误
        assert!(codec.decode(&mut buf3).is_err());
    }

    #[test]
    fn test_encode_rejects_oversized_payload() {
        let mut codec = HttpUdpCodec::new();
        let peer: SocketAddr = "[::1]:53".parse().unwrap();
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD_LEN + 1]);
        let mut buf = BytesMut::new();
        assert!(codec.encode(UdpPacket { peer, payload: big }, &mut buf).is_err());

        // 边界内最大载荷（IPv6 头 22 字节）必须成功
        let ok = Bytes::from(vec![0u8; MAX_PAYLOAD_LEN]);
        let mut buf = BytesMut::new();
        codec.encode(UdpPacket { peer, payload: ok }, &mut buf).unwrap();
        assert_eq!(buf.len(), 2 + MAX_FRAME_LEN);
    }

    #[test]
    fn test_multiple_frames_stream() {
        let mut codec = HttpUdpCodec::new();
        let mut buf = BytesMut::new();
        let peers: Vec<SocketAddr> = vec![
            "1.1.1.1:53".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
            "[2001:db8::7]:9999".parse().unwrap(),
        ];
        for (i, peer) in peers.iter().enumerate() {
            codec
                .encode(
                    UdpPacket {
                        peer: *peer,
                        payload: Bytes::from(format!("payload-{i}").into_bytes()),
                    },
                    &mut buf,
                )
                .unwrap();
        }
        for (i, peer) in peers.iter().enumerate() {
            let pkt = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(pkt.peer, *peer);
            assert_eq!(pkt.payload, Bytes::from(format!("payload-{i}").into_bytes()));
        }
        assert!(buf.is_empty());
    }
}

/// 把 IPv4-mapped IPv6 地址（`::ffff:a.b.c.d`）还原为纯 IPv4。
///
/// 必要性：服务端为了同时转发 v4/v6 目标，UDP 侧绑定 `[::]:0` 双栈 socket。
/// Linux 在这种 socket 上 `recv_from` 会把 IPv4 对端报告成 `::ffff:127.0.0.1`，
/// 若原样写回 httpUDP 帧就变成 addr_type=3（IPv6），而客户端明明发的是 IPv4 目标。
/// 在只路由 IPv4 的免流隧道里，这会让回包被判成非法地址族而丢弃。
pub use crate::net_addr::{canonicalize_addr, canonicalize_ip};


#[cfg(test)]
mod canonicalize_tests {
    use super::*;

    #[test]
    fn mapped_v6_becomes_v4() {
        let mapped: SocketAddr = "[::ffff:203.0.113.7]:44344".parse().unwrap();
        let canon = canonicalize_addr(mapped);
        assert!(canon.is_ipv4(), "{canon} should be IPv4");
        assert_eq!(canon.port(), 44344);
        assert_eq!(canon.to_string(), "203.0.113.7:44344");
    }

    #[test]
    fn real_v6_and_v4_are_unchanged() {
        for s in ["[2001:db8::1]:53", "8.8.8.8:53", "[::1]:80"] {
            let a: SocketAddr = s.parse().unwrap();
            assert_eq!(canonicalize_addr(a).to_string(), s);
        }
    }

    #[test]
    fn encode_decode_preserves_canonical_family() {
        let mut codec = HttpUdpCodec::new();
        let peer = canonicalize_addr("[::ffff:127.0.0.1]:53".parse().unwrap());
        let mut buf = BytesMut::new();
        codec.encode(UdpPacket { peer, payload: Bytes::from_static(b"hi") }, &mut buf).unwrap();
        // addr_type 必须是 1（IPv4）
        assert_eq!(buf[5], 1, "frame must declare IPv4 for a mapped address");
        let back = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(back.peer, peer);
    }
}
