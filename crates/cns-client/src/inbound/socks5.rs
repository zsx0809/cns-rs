use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq, Eq)]
pub enum Socks5Command {
    Connect { target: String },
    UdpAssociate,
}

pub struct Socks5Handshake;

impl Socks5Handshake {
    pub async fn handle(stream: &mut TcpStream) -> io::Result<Socks5Command> {
        // 1. 协商认证方法
        let mut ver_buf = [0u8; 2];
        stream.read_exact(&mut ver_buf).await?;
        if ver_buf[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SOCKS version: {}", ver_buf[0]),
            ));
        }

        let nmethods = ver_buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        // 响应无需认证 (0x00)
        stream.write_all(&[0x05, 0x00]).await?;

        // 2. 读取请求详情
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

        let target_host = match atyp {
            0x01 => {
                // IPv4 (4 字节)
                let mut ip_buf = [0u8; 4];
                stream.read_exact(&mut ip_buf).await?;
                let ip = Ipv4Addr::from(ip_buf);

                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);

                format!("{}:{}", ip, port)
            }
            0x03 => {
                // 域名 (1 字节长度 + 字符串)
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                let domain_len = len_buf[0] as usize;

                let mut domain_buf = vec![0u8; domain_len];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 domain name")
                })?;

                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);

                format!("{}:{}", domain, port)
            }
            0x04 => {
                // IPv6 (16 字节)
                let mut ip_buf = [0u8; 16];
                stream.read_exact(&mut ip_buf).await?;
                let ip = Ipv6Addr::from(ip_buf);

                let mut port_buf = [0u8; 2];
                stream.read_exact(&mut port_buf).await?;
                let port = u16::from_be_bytes(port_buf);

                format!("[{}]:{}", ip, port)
            }
            other => {
                // 回复地址类型不支持
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 ATYP: {}", other),
                ));
            }
        };

        match cmd {
            0x01 => {
                // CONNECT
                // 响应成功：0x05, 0x00(SUCCESS), 0x00(RSV), 0x01(IPv4), 0,0,0,0, 0,0
                stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                Ok(Socks5Command::Connect { target: target_host })
            }
            0x03 => {
                // UDP ASSOCIATE
                Ok(Socks5Command::UdpAssociate)
            }
            _ => {
                stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 CMD: {}", cmd),
                ))
            }
        }
    }
}
