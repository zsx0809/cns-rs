use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// httpUDP 数据报文强类型抽象
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub peer: SocketAddr,
    pub payload: Bytes,
}

/// httpUDP 协议帧编解码器
/// 负责在 TCP 字节流与 UdpPacket 之间进行零拷贝转换
#[derive(Default, Debug)]
pub struct HttpUdpCodec;

impl HttpUdpCodec {
    pub fn new() -> Self {
        Self
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

        // 如果缓冲区尚未收齐完整帧，返回等待更多数据
        if src.len() < total_frame_len {
            src.reserve(total_frame_len - src.len());
            return Ok(None);
        }

        // 校验基本长度边界（IPv4 头部至少 10 字节）
        if pkg_len < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid httpUDP packet length: {}", pkg_len),
            ));
        }

        // 消费 2 字节长度前缀
        src.advance(2);

        // 提取整个帧体
        let mut frame_body = src.split_to(pkg_len);

        // 协议规范：字节 [1, 2] 必须为 0, 0
        if frame_body[1] != 0 || frame_body[2] != 0 {
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
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Truncated IPv4 httpUDP header",
                    ));
                }
                let ip = Ipv4Addr::new(
                    frame_body[4],
                    frame_body[5],
                    frame_body[6],
                    frame_body[7],
                );
                let port = u16::from_be_bytes([frame_body[8], frame_body[9]]);
                frame_body.advance(10);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            3 => {
                // IPv6: [4 字节 flag] [16 字节 IP] [2 字节 Port] = 22 字节头
                if frame_body.len() < 22 {
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
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported address type: {}", other),
                ));
            }
        };

        Ok(Some(UdpPacket {
            peer,
            payload: frame_body.freeze(),
        }))
    }
}

impl Encoder<UdpPacket> for HttpUdpCodec {
    type Error = io::Error;

    fn encode(&mut self, item: UdpPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        match item.peer {
            SocketAddr::V4(v4) => {
                let pkg_len = (payload_len + 10) as u16;
                dst.reserve(2 + 10 + payload_len);
                // 2 字节小端序长度
                dst.put_u16_le(pkg_len);
                // 4 字节标识: [0, 0, 0, 1]
                dst.put_slice(&[0, 0, 0, 1]);
                // 4 字节 IPv4
                dst.put_slice(&v4.ip().octets());
                // 2 字节大端序 Port
                dst.put_u16(v4.port());
                // 载荷
                dst.put_slice(&item.payload);
            }
            SocketAddr::V6(v6) => {
                let pkg_len = (payload_len + 22) as u16;
                dst.reserve(2 + 22 + payload_len);
                // 2 字节小端序长度
                dst.put_u16_le(pkg_len);
                // 4 字节标识: [0, 0, 0, 3]
                dst.put_slice(&[0, 0, 0, 3]);
                // 16 字节 IPv6
                dst.put_slice(&v6.ip().octets());
                // 2 字节大端序 Port
                dst.put_u16(v6.port());
                // 载荷
                dst.put_slice(&item.payload);
            }
        }
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

        let packet = UdpPacket {
            peer,
            payload: payload.clone(),
        };

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

        let packet = UdpPacket {
            peer,
            payload: payload.clone(),
        };

        let mut buf = BytesMut::new();
        codec.encode(packet.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.peer, peer);
        assert_eq!(decoded.payload, payload);
        assert!(buf.is_empty());
    }
}
