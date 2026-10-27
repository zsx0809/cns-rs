use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::debug;

/// 创建经过全链路高性能调优的 TCP 监听器
pub fn create_tcp_listener(addr: SocketAddr, enable_tfo: bool) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // 双栈支持
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(false);
    }

    // 端口复用
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        if let Err(e) = socket.set_reuse_port(true) {
            debug!("Failed to set SO_REUSEPORT: {}", e);
        }
    }

    // TCP Fast Open (0-RTT 握手)
    if enable_tfo {
        #[cfg(target_os = "linux")]
        {
            // 在 Linux 上队列长度推荐 1024
            if let Err(e) = socket.set_tcp_fastopen(1024) {
                warn!("Failed to enable TCP_FASTOPEN: {}. Continuing without TFO.", e);
            }
        }
    }

    // 缓冲区优化（调至 4MB，保证跨国高带宽不丢包）
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    // 绑定并监听
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(4096)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// 针对已建立的 TCP 连接注入最佳吞吐与延迟参数
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY: {}", e);
    }
}

/// 创建带 4MB 缓冲的非阻塞 UDP Socket
pub fn create_tuned_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(false);
    }

    let _ = socket.set_reuse_address(true);
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}
