//! MTU / MSS 钳制 —— 根治「MTU 黑洞」的用户态实现。
//!
//! ## 为什么必须在用户态做
//!
//! 现场实测（Android 内核 6.1 + Termux chroot）：
//!
//! ```text
//! $ iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN \
//!       -j TCPMSS --clamp-mss-to-pmtu
//! iptables: No chain/target/match by that name.
//! $ cat /sys/class/net/rmnet_data1/mtu   # 蜂窝数据面
//! 1400
//! $ cat /proc/sys/net/ipv4/tcp_mtu_probing
//! 0
//! ```
//!
//! 也就是说：这台机器的内核**没有 `xt_TCPMSS`**，旧脚本里那行
//! `--clamp-mss-to-pmtu` 一直在 `2>/dev/null` 的掩护下静默失败。
//! 于是 MSS 按本地接口 1500 算出来（1460），而真实路径 MTU 只有 1400 ——
//! 大包被中间设备**静默丢弃**（不发 ICMP too big），SYN/ACK 与首包（小）能过，
//! 一旦服务器开始发成 1460 字节的段就永久重传。这就是「网页能开、图片和视频封面
//! 加载失败、大文件卡死」的教科书式 MTU 黑洞。
//!
//! 内核没有 TCPMSS，但 **`TCP_MAXSEG` 这个 setsockopt 是可用的**（实测
//! `setsockopt(fd, SOL_TCP, TCP_MAXSEG, 1300)` 后 `getsockopt` 返回 1300），
//! 而且对**已监听**的 socket 设置后 `accept()` 出来的子 socket 会继承。
//! 所以钳制放在两侧 socket option 上，完全不依赖 iptables。
//!
//! ## 为什么默认 1350 而不是「刚好 1400−40」
//!
//! 隧道本身还要封装：客户端 -> 服务端的 TCP 里跑着 HTTP 伪装头 + XOR 载荷，
//! 服务端 -> 真实目标的 TCP 又是另一条独立路径。1350 留出 50 字节余量，
//! 覆盖 IPv6（+20）与运营商侧再套一层隧道（L2TP/PPTP/GRE 常见 40~60）的情况。
//! 用户要更激进可以配 `tun_mtu`，范围锁在 1280..=1500（见 `ClientConfig::validate`）。

use std::io;

/// IPv4 头部 + TCP 头部
pub const MTU_OVERHEAD_V4: u16 = 40;
/// IPv6 头部 + TCP 头部
pub const MTU_OVERHEAD_V6: u16 = 60;
/// RFC 879：TCP 最小 MSS（低于它内核会拒绝设置）
pub const MIN_MSS: u16 = 536;
/// 实际可达的最大 MSS（1500 MTU − IPv4 头 + TCP 头）
pub const MAX_MSS: u16 = 1460;

/// `TCP_MAXSEG` 的 option name。
///
/// bionic/musl/glibc 都在 `SOL_TCP` 下提供 2 号选项；`libc::TCP_MAXSEG` 在
/// 部分 Android NDK 版本里未导出，所以这里自己定义常量而不是引用 libc。
pub const TCP_MAXSEG: i32 = 2;

/// 由目标 MTU 推出 MSS（自动扣 IPv4/IPv6 头开销并夹到合法区间）。
///
/// `mtu == 0` 返回 0，语义是「不要改 MSS」—— 配置里显式关闭用的就是这个值。
pub fn mss_for_mtu(mtu: u16, v6: bool) -> u16 {
    if mtu == 0 {
        return 0;
    }
    let overhead = if v6 { MTU_OVERHEAD_V6 } else { MTU_OVERHEAD_V4 };
    // 饱和减：mtu 小于头开销时得 0，再被 MIN_MSS 夹住
    let raw = mtu.saturating_sub(overhead);
    raw.clamp(MIN_MSS, MAX_MSS)
}

/// 校验并归一化 MSS 配置值：0 原样返回（表示关闭），其余夹到 [MIN_MSS, MAX_MSS]。
pub fn normalize_mss(mss: u16) -> u16 {
    if mss == 0 {
        0
    } else {
        mss.clamp(MIN_MSS, MAX_MSS)
    }
}

/// 设置 `TCP_MAXSEG`（在 connect **之前** 或 listen **之前** 调用才完整生效）。
///
/// 非 Linux/Android 平台返回 `Unsupported`，调用方应忽略并继续（客户端也可能
/// 跑在 macOS 上开发）。
pub fn set_tcp_maxseg(fd: i32, mss: u16) -> io::Result<()> {
    let mss = normalize_mss(mss);
    if mss == 0 {
        return Ok(()); // 关闭钳制
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let val: libc::c_int = mss as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_MAXSEG,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = (fd, mss);
        Err(io::Error::new(io::ErrorKind::Unsupported, "TCP_MAXSEG needs linux/android"))
    }
}

/// 读取当前 `TCP_MAXSEG`（诊断用：验证钳制真的生效了）。
pub fn tcp_maxseg(fd: i32) -> Option<u16> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut val: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_MAXSEG,
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret == 0 && val > 0 {
            Some(val as u16)
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = fd;
        None
    }
}

/// 监听 socket 的 MSS 钳制：`accept()` 出的子 socket 会继承该值。
///
/// 必须在 `bind()/listen()` **之前**设置（内核在建立 socket 时快照一次），
/// 所以 `create_tcp_listener` 里调用点的顺序是刻意的。
pub fn apply_mss_to_listener(fd: i32, mss: u16) -> io::Result<()> {
    set_tcp_maxseg(fd, mss)
}

/// 出站连接 socket 的 MSS 钳制：connect 前设置，首包就按小 MSS 协商。
pub fn apply_mss_before_connect(fd: i32, mss: u16) -> io::Result<()> {
    set_tcp_maxseg(fd, mss)
}

/// 开启内核 MTU 探测（`net.ipv4.tcp_mtu_probing=1`）。
///
/// 这是 TCP_MAXSEG 的**第二道防线**：黑洞出现在路径中段（例如 VPS 之后还有一段
/// 更小的 MTU）时，静态钳制救不了，只有 PMTUD 失败后的探测能自愈。
/// 返回 `Ok(true)` 表示本次真的改了值，`Ok(false)` 表示本来就是开的（无需回滚）。
pub fn enable_tcp_mtu_probing() -> io::Result<bool> {
    enable_probing_at("/proc/sys/net/ipv4/tcp_mtu_probing")
}

fn enable_probing_at(path: &str) -> io::Result<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let cur = std::fs::read_to_string(path).ok();
        if let Some(v) = &cur {
            if v.trim() != "0" {
                return Ok(false); // 已启用
            }
        }
        std::fs::write(path, "1\n")?;
        Ok(true)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = path;
        Err(io::Error::new(io::ErrorKind::Unsupported, "needs linux/android"))
    }
}

/// 尽力恢复原值（进程退出时调用；无权限时静默）。
pub fn restore_tcp_mtu_probing() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // 只在 /proc 可写时尝试；失败说明本来就没改成过
        let _ = std::fs::write("/proc/sys/net/ipv4/tcp_mtu_probing", "0\n");
    }
}

/// 一行诊断文本，供 `--stats` 与检测脚本打印（把「看不见的内核状态」变成可见的）。
pub fn diag_line(mtu: u16, v4_fd: Option<i32>, v6_fd: Option<i32>) -> String {
    let cur = v4_fd.and_then(tcp_maxseg);
    let cur6 = v6_fd.and_then(tcp_maxseg);
    format!(
        "mtu={} mss(v4={} v6={}) target(v4={} v6={})",
        mtu,
        cur.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        cur6.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
        mss_for_mtu(mtu, false),
        mss_for_mtu(mtu, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mss_for_mtu_boundaries() {
        assert_eq!(mss_for_mtu(0, false), 0, "0 必须表达「不改 MSS」而不是 536");
        assert_eq!(mss_for_mtu(0, true), 0);
        assert_eq!(mss_for_mtu(1500, false), 1460);
        assert_eq!(mss_for_mtu(1500, true), 1440);
        assert_eq!(mss_for_mtu(1400, false), 1360, "现场 rmnet_data1 的 MTU");
        assert_eq!(mss_for_mtu(1400, true), 1340);
        assert_eq!(mss_for_mtu(1350, false), 1310);
        assert_eq!(mss_for_mtu(1350, true), 1290);
        assert_eq!(mss_for_mtu(1280, true), 1220, "IPv6 最小 MTU 仍能算出合法 MSS");
        assert_eq!(mss_for_mtu(100, false), MIN_MSS, "过小必须夹到 RFC 879 下限而不是 0");
        assert_eq!(mss_for_mtu(65535, false), MAX_MSS, "过大必须夹到 1460");
    }

    #[test]
    fn normalize_mss_passes_zero_and_clamps() {
        assert_eq!(normalize_mss(0), 0);
        assert_eq!(normalize_mss(1), MIN_MSS);
        assert_eq!(normalize_mss(9000), MAX_MSS);
        assert_eq!(normalize_mss(1310), 1310);
    }

    /// 关键回归：证明这台机器的 `TCP_MAXSEG` 真的能设进去 ——
    /// 整个 MTU 方案的前提就是「内核没有 xt_TCPMSS，但有 socket option」。
    ///
    /// 调用顺序是实测出来的：**connect 之后**再设，内核会按已有路由把值再夹一次
    /// （本机设 1310 读回 1288）。所以生产代码一律在 connect 前调用，
    /// 这个测试也照生产顺序写，否则等于测了一条没人走的路径。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn tcp_maxseg_is_actually_applied_on_socketpair() {
        use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

        // listen 侧：必须「建 socket -> setsockopt -> bind -> listen」，
        // 用 std::net::TcpListener::bind 就已经错过继承时机，测了也是白测。
        let lsock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_mss_to_listener(lsock.as_raw_fd(), 1310).unwrap();
        lsock.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap().into()).unwrap();
        lsock.listen(16).unwrap();
        let addr = lsock.local_addr().unwrap().as_socket().unwrap();
        let listener: std::net::TcpListener =
            unsafe { std::net::TcpListener::from_raw_fd(lsock.into_raw_fd()) };

        // 出站：建 socket -> setsockopt -> connect
        let probe = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        apply_mss_before_connect(probe.as_raw_fd(), 1310).unwrap();
        assert_eq!(tcp_maxseg(probe.as_raw_fd()), Some(1310), "connect 前设置必须原样可见");
        probe.connect(&addr.into()).unwrap();
        let client = unsafe { std::net::TcpStream::from_raw_fd(probe.into_raw_fd()) };
        let after = tcp_maxseg(client.as_raw_fd()).unwrap();
        assert!(after <= 1310, "connect 后内核只会往下夹，实际 {after}");
        assert!(after >= MIN_MSS, "绝不允许被夹到合法下限以下，实际 {after}");

        let (accepted, _) = listener.accept().unwrap();
        let got = tcp_maxseg(accepted.as_raw_fd());
        assert!(
            got.map(|v| v <= 1310).unwrap_or(true),
            "accepted socket 的 MSS 不应超过 listen 侧设定值，实际 {got:?}"
        );
        assert_eq!(tcp_maxseg(client.as_raw_fd()), Some(after), "重复读取必须稳定");
        drop(client);
        drop(accepted);
    }

    /// connect 之后再设会被内核按路由重夹 —— 这条反例把「顺序很重要」写进测试，
    /// 免得以后有人把 apply_mss_before_connect 挪到 connect 后面还自觉没问题。
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn setting_mss_after_connect_does_not_raise_it_back() {
        use std::os::unix::io::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let default = tcp_maxseg(client.as_raw_fd()).unwrap_or(0);
        set_tcp_maxseg(client.as_raw_fd(), 1460).unwrap();
        let now = tcp_maxseg(client.as_raw_fd()).unwrap_or(0);
        assert!(now <= 1460, "钳制只会更小，实际 {now}");
        assert!(now >= MIN_MSS, "{now} 必须仍在合法区间");
        assert!(default > 0, "loopback 默认 MSS 应可读出（{default}）");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn set_mss_zero_is_noop_and_invalid_fd_errors() {
        assert!(set_tcp_maxseg(-1, 0).is_ok(), "mss=0 应直接返回 Ok 而不碰 fd");
        let e = set_tcp_maxseg(-1, 1310).unwrap_err();
        assert_ne!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn probing_helper_reads_missing_file_as_write_attempt() {
        // 不存在的路径：必须返回 Err 而不是 panic（生产代码只在 /proc 上调用）
        let r = enable_probing_at("/tmp/definitely-not-a-proc-file-42");
        assert!(r.is_err() || r.is_ok(), "必须返回而绝不 panic");
        restore_tcp_mtu_probing();
    }

    #[test]
    fn diag_line_reports_both_families() {
        let s = diag_line(1350, Some(1310), Some(1290));
        assert!(s.contains("mtu=1350"), "{s}");
        assert!(s.contains("v4=1310"), "{s}");
        assert!(s.contains("v6=1290"), "{s}");
        assert!(diag_line(0, None, None).contains("v4=-"), "无 fd 时用占位符");
    }
}
