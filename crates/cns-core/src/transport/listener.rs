use crate::transport::mss;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::debug;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::io::AsRawFd;

/// 监听器构建参数。默认值面向「手机免流 + 128MB 小鸡」两类目标做统一调优。
#[derive(Debug, Clone, Copy)]
pub struct ListenOptions {
    /// TCP_FASTOPEN 队列长度 > 0 时启用（服务端 0-RTT）
    pub enable_tfo: bool,
    /// true = 纯 IPv6 监听；false(默认) = v6 socket 同时接受 IPv4-mapped 连接（真双栈）
    pub ipv6_only: bool,
    /// IP_TRANSPARENT / IPV6_TRANSPARENT，透明代理必需；非 root 失败时静默降级
    pub transparent: bool,
    pub recv_buffer: usize,
    pub send_buffer: usize,
    pub backlog: u32,
    /// 目标链路 MTU（字节），0 = 不钳制。
    ///
    /// 实际下发的 `TCP_MAXSEG` 由地址族决定：IPv4 = MTU−40，IPv6 = MTU−60
    /// （见 `mss::mss_for_mtu`）。同一个 `[::]:port` 监听既吃 v4 又吃 v6，
    /// 所以取**更保守的 v6 口径**，避免 v4 侧算出 1310 而 v6 侧真实需求只有 1290。
    ///
    /// 必须在 bind/listen **之前**设置：内核在建链时快照一次，之后再设只影响
    /// 后续新连接，而 MTU 黑洞杀的正是首包之后的大包 —— 设晚了等于没设。
    /// 这台内核没有 `xt_TCPMSS`（`iptables -j TCPMSS` 报 No chain/target/match），
    /// 所以这是唯一的 MSS 落点，详见 `transport::mss` 的模块注释。
    pub tun_mtu: u16,
}

impl Default for ListenOptions {
    fn default() -> Self {
        Self {
            enable_tfo: true,
            ipv6_only: false,
            transparent: true,
            recv_buffer: 4 * 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
            backlog: 4096,
            // 默认不钳制：由部署方按现场链路 MTU 显式给值（客户端从 tun_mtu 推）
            tun_mtu: 0,
        }
    }
}

/// 把配置里的监听字符串展开成实际要绑定的地址列表。
///
/// * `":1254"` / `"*:1254"` → 优先 `"[::]:1254"`（双栈），失败再回退 `0.0.0.0:1254`
/// * `"0.0.0.0:1254"` / `"[::]:1254"` → 原样
/// * 其它 → 原样解析，解析失败返回错误交给上层报错（不静默改端口）
pub fn expand_listen_spec(spec: &str) -> Vec<SocketAddr> {
    let s = spec.trim();
    let mut out = Vec::new();
    if s.starts_with(':') || s.starts_with("*:") {
        let port_part = s.trim_start_matches([':', '*']);
        if let Ok(v6) = format!("[::]:{port_part}").parse::<SocketAddr>() {
            out.push(v6);
        }
        if let Ok(v4) = format!("0.0.0.0:{port_part}").parse::<SocketAddr>() {
            out.push(v4);
        }
    } else if let Ok(addr) = s.parse::<SocketAddr>() {
        out.push(addr);
    }
    out
}

/// 创建经过全链路调优的 TCP 监听器
pub fn create_tcp_listener(addr: SocketAddr, opts: ListenOptions) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // 关键修复：默认 **不** 设置 IPV6_V6ONLY，让单个 [::]:port 同时吃 IPv4 与 IPv6。
    // 旧实现无条件 set_only_v6(true)，导致移动网络大量 IPv4-only 客户端永远连不上。
    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(opts.ipv6_only);
    }

    socket.set_reuse_address(true)?;
    // 透明代理**不能**开 SO_REUSEPORT。本机实测：现网实例已经占着 0.0.0.0:7750，
    // 新起的第二个客户端照样 bind 成功、日志干净地正常启动，而内核会把新连接
    // 轮转分给两个实例 —— 用户看到的是「一半网页打不开 / 偶发连不上」这种查不出来的
    // 故障，因为两边的日志都正常。关掉它之后第二个实例 bind 失败，配合启动期检查
    // 直接拒绝运行，把静默分流变成一条明确的报错。
    //
    // 服务端仍需要它：双栈监听时 `[::]:port`（不设 V6ONLY）与 `0.0.0.0:port` 同时给出
    // 必须靠 SO_REUSEPORT 才能共存，所以按 `opts.transparent` 区分。
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if !opts.transparent {
        if let Err(e) = socket.set_reuse_port(true) {
            debug!("SO_REUSEPORT unavailable: {e}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if opts.transparent {
        unsafe {
            let one: libc::c_int = 1;
            const IPV6_TRANSPARENT_OPT: libc::c_int = 75;
            match addr {
                SocketAddr::V4(_) => {
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_IP,
                        libc::IP_TRANSPARENT,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&one) as libc::socklen_t,
                    );
                    if ret == 0 {
                        debug!("IPv4 IP_TRANSPARENT enabled");
                    } else {
                        debug!("IPv4 IP_TRANSPARENT rejected: {}", io::Error::last_os_error());
                    }
                }
                SocketAddr::V6(_) => {
                    let ret = libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        IPV6_TRANSPARENT_OPT,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&one) as libc::socklen_t,
                    );
                    if ret == 0 {
                        debug!("IPv6 IPV6_TRANSPARENT enabled");
                    } else {
                        debug!("IPv6 IPV6_TRANSPARENT rejected: {}", io::Error::last_os_error());
                    }
                    if !opts.ipv6_only {
                        let _ = libc::setsockopt(
                            socket.as_raw_fd(),
                            libc::SOL_IP,
                            libc::IP_TRANSPARENT,
                            &one as *const _ as *const libc::c_void,
                            std::mem::size_of_val(&one) as libc::socklen_t,
                        );
                    }
                }
            }
        }
    }

    if opts.enable_tfo {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        unsafe {
            let qlen: libc::c_int = 1024;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &qlen as *const _ as *const libc::c_void,
                std::mem::size_of_val(&qlen) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_FASTOPEN listen unavailable: {}", io::Error::last_os_error());
            }
        }
    }

    if opts.recv_buffer > 0 {
        let _ = socket.set_recv_buffer_size(opts.recv_buffer);
    }
    if opts.send_buffer > 0 {
        let _ = socket.set_send_buffer_size(opts.send_buffer);
    }

    // MSS 钳制必须在 bind/listen 之前：内核在建链时快照一次 TCP_MAXSEG，
    // accept 出的子 socket 才继承得到。设晚了只影响之后的新连接，而 MTU 黑洞
    // 杀的正是首包之后的大包 —— 等于没设。
    //
    // 双栈监听（`[::]:port` 同时吃 v4 与 v6）取 **v6 口径**（MTU−60）：
    // 同一个 socket 无法对两个族分别设定，宁可让 v4 也用小 MSS。
    if opts.tun_mtu != 0 {
        let mss = mss::mss_for_mtu(opts.tun_mtu, matches!(addr, SocketAddr::V6(_)));
        match mss::apply_mss_to_listener(socket.as_raw_fd(), mss) {
            Ok(()) => debug!("TCP_MAXSEG={} (mtu {}) on {addr}", mss, opts.tun_mtu),
            Err(e) => {
                // 不是致命错误：黑洞仍可由 tcp_mtu_probing 兜底，但必须留下痕迹。
                // 这台内核没有 xt_TCPMSS，iptables 那条路是不通的。
                debug!("TCP_MAXSEG unavailable on {addr}: {e}");
            }
        }
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(opts.backlog as i32)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// 针对已建立连接注入吞吐/延迟/保活参数。
///
/// 免流场景下基站与光猫的 NAT 表项老化才是「假连接」主因，所以必须开 TCP keepalive，
/// 而不是靠上层 15 秒硬超时切断。
pub fn tune_tcp_stream(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("TCP_NODELAY failed: {e}");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        );
        for (opt, val, name) in [
            (libc::TCP_KEEPIDLE, 30i32, "KEEPIDLE"),
            (libc::TCP_KEEPINTVL, 10i32, "KEEPINTVL"),
            (libc::TCP_KEEPCNT, 6i32, "KEEPCNT"),
        ] {
            let ret = libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                opt,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_{name} unavailable: {}", io::Error::last_os_error());
            }
        }
    }
}

/// 客户端出站连接：在 connect 前打开 `TCP_FASTOPEN_CONNECT`，
/// 让首写携带 SYN 数据，真正拿到 0-RTT（旧实现只在服务端开了 TFO，客户端从未使用）。
pub async fn connect_tfo(addr: SocketAddr, enable_tfo: bool) -> io::Result<TcpStream> {
    connect_tfo_mss(addr, enable_tfo, 0).await
}

/// 带 MSS 钳制的出站连接。
///
/// `tun_mtu` 非 0 时按 `mss_for_mtu` 推导 MSS，并且**必须在 `connect()` 之前**
/// 写到 fd 上 —— Linux 只在连接建立前认 `TCP_MAXSEG`，connect 之后再设会被静默
/// 忽略（`tests::setting_mss_after_connect_does_not_raise_it_back` 把这条语义钉住了）。
pub async fn connect_tfo_mss(
    addr: SocketAddr,
    enable_tfo: bool,
    tun_mtu: u16,
) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    let _ = socket.set_nodelay(true);

    if tun_mtu != 0 {
        let mss = mss::mss_for_mtu(tun_mtu, matches!(addr, SocketAddr::V6(_)));
        if let Err(e) = mss::set_tcp_maxseg(socket.as_raw_fd(), mss) {
            debug!("pre-connect TCP_MAXSEG={mss} failed on {addr}: {e}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    if enable_tfo {
        unsafe {
            let on: libc::c_int = 1;
            let ret = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN_CONNECT,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of_val(&on) as libc::socklen_t,
            );
            if ret != 0 {
                debug!("TCP_FASTOPEN_CONNECT unavailable: {}", io::Error::last_os_error());
            }
        }
    }

    let stream = socket.connect(addr).await?;
    tune_tcp_stream(&stream);
    Ok(stream)
}

/// 解析 `host:port` 并对所有候选地址做快速回退连接（IPv6 优先，失败立即试 IPv4）。
pub async fn connect_any(target: &str, enable_tfo: bool) -> io::Result<TcpStream> {
    connect_any_mss(target, enable_tfo, 0).await
}

/// `connect_any` 的带 MSS 版：`tun_mtu` 非 0 时对每个候选地址都在 connect 前钳制。
pub async fn connect_any_mss(
    target: &str,
    enable_tfo: bool,
    tun_mtu: u16,
) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no address resolved for {target}"),
        ));
    }

    let mut last_err = io::Error::other("connect failed");
    for addr in addrs {
        match connect_tfo_mss(addr, enable_tfo, tun_mtu).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// 创建带大缓冲的非阻塞 UDP Socket
pub fn create_tuned_udp_socket(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if let SocketAddr::V6(_) = addr {
        // UDP 出站默认双栈，便于 v6 源地址回包
        let _ = socket.set_only_v6(false);
    }

    let _ = socket.set_reuse_address(true);
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// 创建支持 TPROXY 透明代理与原始目的地址捕获的 UDP 监听 Socket
pub fn create_udp_tproxy_socket(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    let _ = socket.set_reuse_port(true);

    if let SocketAddr::V6(_) = addr {
        let _ = socket.set_only_v6(true);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        let fd = socket.as_raw_fd();
        let one: libc::c_int = 1;
        const IPV6_TRANSPARENT_OPT: libc::c_int = 75;
        const IPV6_RECVORIGDSTADDR_OPT: libc::c_int = 74;
        const IPV6_RECVPKTINFO_OPT: libc::c_int = 37;

        match addr {
            SocketAddr::V4(_) => {
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_TRANSPARENT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_RECVORIGDSTADDR,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_IP,
                    libc::IP_PKTINFO,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
            }
            SocketAddr::V6(_) => {
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IPV6_TRANSPARENT_OPT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IPV6_RECVORIGDSTADDR_OPT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    IPV6_RECVPKTINFO_OPT,
                    &one as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&one) as libc::socklen_t,
                );
            }
        }
    }

    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_wildcard_yields_v6_then_v4() {
        let list = expand_listen_spec(":1254");
        assert_eq!(list.len(), 2);
        assert!(list[0].is_ipv6());
        assert_eq!(list[0].port(), 1254);
        assert!(list[1].is_ipv4());
        assert_eq!(list[1].port(), 1254);
    }

    #[test]
    fn expand_explicit_addr_is_single() {
        let list = expand_listen_spec("127.0.0.1:8080");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn expand_bad_spec_is_empty() {
        assert!(expand_listen_spec("not-an-addr").is_empty());
    }

    #[tokio::test]
    async fn dualstack_listener_accepts_ipv4_client() {
        // 回归测试：曾经的 set_only_v6(true) 让 IPv4 客户端连不上
        let opts = ListenOptions { transparent: false, enable_tfo: false, ..Default::default() };
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let listener = create_tcp_listener(addr, opts).unwrap();
        let bound = listener.local_addr().unwrap();

        let connect_to: SocketAddr = format!("127.0.0.1:{}", bound.port()).parse().unwrap();
        let std_stream = std::net::TcpStream::connect(connect_to);
        assert!(
            std_stream.is_ok(),
            "IPv4 client must reach the dual-stack listener: {:?}",
            std_stream.err()
        );
    }
}
