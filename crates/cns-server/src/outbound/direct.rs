use cns_core::transport::tune_tcp_stream;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpStream, UdpSocket};

pub struct DirectOutbound;

impl DirectOutbound {
    /// 建立到目标 TCP 服务器的直连，并注入优化参数
    pub async fn dial_tcp(target: &str) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(target).await?;
        tune_tcp_stream(&stream);
        Ok(stream)
    }

    /// 创建用于转发 UDP 的直连本地套接字
    pub async fn bind_udp(prefer_v6: bool) -> io::Result<UdpSocket> {
        let bind_addr: SocketAddr = if prefer_v6 {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        cns_core::transport::create_tuned_udp_socket(bind_addr)
    }
}
