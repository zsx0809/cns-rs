use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// 单条缓存记录
#[derive(Clone, Debug)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
    /// 解析失败也缓存一小段时间，避免上游挂了被疯狂重试打爆
    negative: bool,
}

/// 纯异步 DNS 解析器（自建报文，不依赖 getaddrinfo 的 blocking 线程池）。
///
/// 原版服务端用 `tokio::net::lookup_host`，它跑在 blocking pool 上：
/// 高频域名回源会把 512 个阻塞线程吃光，进而整个服务僵死。这里改为
/// 非阻塞 UDP 查询 + 结果缓存 + 多上游竞速。
#[derive(Clone)]
pub struct Resolver {
    upstreams: Arc<Vec<SocketAddr>>,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    cache_limit: usize,
    query_timeout: Duration,
    min_ttl: u64,
    max_ttl: u64,
    negative_ttl: u64,
    socket_pool: Arc<Mutex<Vec<UdpSocket>>>,
}

/// 解析结果缓存策略
#[derive(Clone, Copy, Debug)]
pub struct ResolverOptions {
    pub cache_limit: usize,
    pub query_timeout: Duration,
    pub min_ttl: u64,
    pub max_ttl: u64,
    pub negative_ttl: u64,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            cache_limit: 4096,
            query_timeout: Duration::from_secs(3),
            min_ttl: 30,
            max_ttl: 3600,
            negative_ttl: 5,
        }
    }
}

impl Resolver {
    pub fn new(upstreams: &[String], opts: ResolverOptions) -> Self {
        let mut parsed: Vec<SocketAddr> = Vec::new();
        for up in upstreams {
            // 已带端口（含 [v6]:port 形式）原样使用，否则补 :53
            let with_port = if up.contains(':') { up.clone() } else { format!("{up}:53") };
            match with_port.parse::<SocketAddr>() {
                Ok(addr) => parsed.push(addr),
                Err(e) => {
                    tracing::warn!("ignoring invalid dns_upstream {up}: {e}");
                }
            }
        }
        if parsed.is_empty() {
            // 兜底：公共 DNS，避免配置写错导致完全无法解析
            parsed.push("223.5.5.5:53".parse().unwrap());
            parsed.push("8.8.8.8:53".parse().unwrap());
        }
        Self {
            upstreams: Arc::new(parsed),
            cache: Arc::new(Mutex::new(HashMap::new())),
            cache_limit: opts.cache_limit.max(16),
            query_timeout: opts.query_timeout,
            min_ttl: opts.min_ttl,
            max_ttl: opts.max_ttl,
            negative_ttl: opts.negative_ttl,
            socket_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    fn cache_get(&self, key: &str) -> Option<Vec<IpAddr>> {
        let guard = self.cache.lock().ok()?;
        let entry = guard.get(key)?;
        if entry.expires > Instant::now() {
            if entry.negative {
                // 负缓存：以空列表表达「暂时别再查」
                return Some(Vec::new());
            }
            Some(entry.addrs.clone())
        } else {
            None
        }
    }

    fn cache_put(&self, key: &str, addrs: Vec<IpAddr>, ttl: u64, negative: bool) {
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= self.cache_limit {
                // 简单驱逐：先清过期项，仍超限则整体清空（避免实现完整 LRU 的复杂度）
                let now = Instant::now();
                guard.retain(|_, e| e.expires > now);
                if guard.len() >= self.cache_limit {
                    guard.clear();
                }
            }
            let ttl =
                if negative { self.negative_ttl } else { ttl.clamp(self.min_ttl, self.max_ttl) };
            guard.insert(
                key.to_string(),
                CacheEntry { addrs, expires: Instant::now() + Duration::from_secs(ttl), negative },
            );
        }
    }

    /// 解析主机会名为 IP 列表（带缓存）。`host` 不含端口。
    pub async fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let key = host.to_ascii_lowercase();

        // 字面 IP 直接返回
        if let Ok(ip) = key.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Some(cached) = self.cache_get(&key) {
            if cached.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("cached NXDOMAIN for {host}"),
                ));
            }
            return Ok(cached);
        }

        match self.query_remote(&key).await {
            Ok((addrs, ttl)) => {
                self.cache_put(&key, addrs.clone(), ttl, addrs.is_empty());
                if addrs.is_empty() {
                    Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("no A/AAAA record for {host}"),
                    ))
                } else {
                    Ok(addrs)
                }
            }
            Err(e) => {
                self.cache_put(&key, Vec::new(), self.negative_ttl, true);
                Err(e)
            }
        }
    }

    /// 多上游并发竞速，先到先得
    async fn query_remote(&self, host: &str) -> io::Result<(Vec<IpAddr>, u64)> {
        let query = build_dns_query(host, false)?;
        let query_v6 = build_dns_query(host, true)?;

        let mut tasks = Vec::new();
        for up in self.upstreams.iter() {
            let q = query.clone();
            let up = *up;
            let to = self.query_timeout;
            let pool = Arc::clone(&self.socket_pool);
            let qs = query_v6.clone();
            tasks.push(tokio::spawn(async move {
                let mut found = Vec::new();
                let mut ttl = 0u64;
                // v4 与 v6 各查一次，任一成功即可
                for (pkt, want_v6) in [(&q, false), (&qs, true)] {
                    if let Ok(resp) = exchange_once(pool.clone(), up, pkt, to).await {
                        if let Some((addrs, t)) = parse_dns_response(&resp, want_v6) {
                            found.extend(addrs);
                            ttl = t;
                        }
                    }
                }
                (found, ttl)
            }));
        }

        let mut best: Option<(Vec<IpAddr>, u64)> = None;
        for task in tasks {
            match task.await {
                Ok((addrs, ttl)) => {
                    if !addrs.is_empty() {
                        // 优先 IPv4（免流隧道对 v6 支持不一致），但保留全部结果
                        let mut sorted = addrs;
                        sorted.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });
                        best = Some((sorted, ttl));
                        break;
                    }
                    if best.is_none() {
                        best = Some((Vec::new(), 0));
                    }
                }
                Err(e) => {
                    tracing::debug!("resolver task panicked/joined: {e}");
                }
            }
        }

        best.filter(|(a, _)| !a.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "DNS query failed"))
    }
}

async fn exchange_once(
    pool: Arc<Mutex<Vec<UdpSocket>>>,
    up: SocketAddr,
    query: &[u8],
    to: Duration,
) -> io::Result<Vec<u8>> {
    let socket = take_socket(&pool, up).await?;
    let mut buf = vec![0u8; 4096];

    let result = async {
        socket.send_to(query, up).await?;
        let (n, peer) = timeout(to, socket.recv_from(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "upstream DNS timeout"))??;
        // 只接受来自该上游的应答，防串包/伪造
        if peer != up {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("dns response from unexpected peer {peer}"),
            ));
        }
        buf.truncate(n);
        Ok::<(), io::Error>(())
    }
    .await;

    if result.is_ok() {
        // 成功才归还池；失败让 socket 随 drop 释放
        if let Ok(mut guard) = pool.lock() {
            if guard.len() < 16 {
                guard.push(socket);
            }
        }
    }
    result.map(|_| buf)
}

/// 取得一个与上游同族的 UDP socket（优先复用池中空闲的）
async fn take_socket(pool: &Arc<Mutex<Vec<UdpSocket>>>, up: SocketAddr) -> io::Result<UdpSocket> {
    if let Ok(mut guard) = pool.lock() {
        if let Some(idx) = guard
            .iter()
            .position(|s| s.local_addr().map(|a| a.is_ipv4() == up.is_ipv4()).unwrap_or(false))
        {
            return Ok(guard.remove(idx));
        }
    }
    let bind: SocketAddr =
        if up.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    cns_core::transport::create_tuned_udp_socket(bind)
}

fn build_dns_query(host: &str, ipv6: bool) -> io::Result<Vec<u8>> {
    let mut pkt = Vec::with_capacity(32 + host.len());
    let id = rand_id();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);

    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    let qtype = if ipv6 { 28u16 } else { 1u16 };
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // IN
    Ok(pkt)
}

fn rand_id() -> u16 {
    // 无 rand crate 依赖：用时钟 + 进程 id + 原子计数混出足够随机的事务 id
    static COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    c ^ nanos ^ (std::process::id() as u16)
}

/// 解析应答，返回 (地址列表, 最小 TTL)。`want_v6` 决定取 AAAA 还是 A。
pub fn parse_dns_response(resp: &[u8], want_v6: bool) -> Option<(Vec<IpAddr>, u64)> {
    if resp.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let rcode = resp[3] & 0x0f;
    if rcode != 0 || ancount == 0 {
        return None;
    }

    let want_type = if want_v6 { 28u16 } else { 1u16 };
    let mut pos = 12usize;

    // 跳过 Question 段
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > resp.len() {
            return None;
        }
    }

    let mut addrs = Vec::new();
    let mut min_ttl = u64::MAX;
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let data_start = pos + 10;
        let data_end = data_start.checked_add(rdlen)?;
        if data_end > resp.len() {
            break;
        }
        let data = &resp[data_start..data_end];

        if rtype == want_type {
            let ip = if want_v6 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            } else if !want_v6 && rdlen == 4 {
                Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
            } else {
                None
            };
            if let Some(ip) = ip {
                min_ttl = min_ttl.min(ttl as u64);
                addrs.push(ip);
            }
        }
        pos = data_end;
    }

    if addrs.is_empty() {
        None
    } else {
        Some((addrs, if min_ttl == u64::MAX { 0 } else { min_ttl }))
    }
}

/// 跳过 DNS 名称，处理压缩指针（0b11 前缀）
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            // 压缩指针：2 字节，后续名称在指针处结束
            if pos + 2 > msg.len() {
                return None;
            }
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_answer() -> Vec<u8> {
        // id=0x1234 flags=8180 QD=1 AN=1
        // qname: 7example 3com 0, qtype A
        // answer: ptr 0x0c, type A, class IN, ttl 60, rdlen 4, 93.184.216.34
        vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // header
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // qname
            0x00, 0x01, 0x00, 0x01, // qtype A qclass IN
            0xc0, 0x0c, // name ptr
            0x00, 0x01, // type A
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3c, // ttl 60
            0x00, 0x04, // rdlen
            93, 184, 216, 34,
        ]
    }

    #[test]
    fn parses_a_record_with_compressed_name() {
        let msg = sample_answer();
        let (addrs, ttl) = parse_dns_response(&msg, false).unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(ttl, 60);
    }

    #[test]
    fn ignores_wrong_record_type() {
        let msg = sample_answer();
        assert!(parse_dns_response(&msg, true).is_none()); // 只要 AAAA，应答里只有 A
    }

    #[test]
    fn rejects_truncated_and_error_responses() {
        assert!(parse_dns_response(&[0x12, 0x34], false).is_none());
        let mut msg = sample_answer();
        msg[3] |= 3; // rcode=3 NXDOMAIN
        assert!(parse_dns_response(&msg, false).is_none());
        let mut msg2 = sample_answer();
        msg2.truncate(13); // 截断
        assert!(parse_dns_response(&msg2, false).is_none());
    }

    #[test]
    fn parses_aaaa() {
        let mut msg: Vec<u8> = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 3, b'f', b'o',
            b'o', 0, 0x00, 0x1c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01,
        ];
        msg.extend_from_slice(&[0x00, 0x00, 0x0e, 0x10]); // ttl 3600
        msg.extend_from_slice(&[0x00, 0x10]); // rdlen 16
        let mut ip = [0u8; 16];
        ip[0] = 0x20;
        ip[1] = 0x01;
        ip[15] = 0x07;
        msg.extend_from_slice(&ip);
        let (addrs, ttl) = parse_dns_response(&msg, true).unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv6());
        assert_eq!(ttl, 3600);
    }

    #[test]
    fn build_query_shape() {
        let q = build_dns_query("example.com", false).unwrap();
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        assert_eq!(q[12], 7);
        assert_eq!(q[q.len() - 4..], [0x00, 0x01, 0x00, 0x01]);
        assert!(build_dns_query(&"a".repeat(64), false).is_err());
    }

    #[tokio::test]
    async fn literal_ip_skips_network() {
        let r = Resolver::new(&["127.0.0.1:53".to_string()], ResolverOptions::default());
        let got = r.lookup("1.1.1.1").await.unwrap();
        assert_eq!(got, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let got6 = r.lookup("2001:4860:4860::8888").await.unwrap();
        assert!(got6[0].is_ipv6());
    }

    #[tokio::test]
    async fn negative_cache_short_circuits() {
        // 上游不可达 → 报错并被负缓存，第二次立即失败而不再发网络包
        let r = Resolver::new(
            &["127.0.0.1:1".to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(120), ..Default::default() },
        );
        let t0 = Instant::now();
        assert!(r.lookup("definitely-not-resolvable.invalid").await.is_err());
        let first = t0.elapsed();
        let t1 = Instant::now();
        assert!(r.lookup("definitely-not-resolvable.invalid").await.is_err());
        let second = t1.elapsed();
        assert!(second < first, "cached negative should be faster: {first:?} vs {second:?}");
    }

    #[test]
    fn skip_name_handles_labels_and_pointers() {
        let msg = vec![3, b'f', b'o', b'o', 0, 0xc0, 0x04];
        assert_eq!(skip_name(&msg, 0), Some(5));
        assert_eq!(skip_name(&msg, 5), Some(7));
        assert_eq!(skip_name(&msg, 100), None);
    }

    #[test]
    fn invalid_upstream_strings_are_dropped_not_fatal() {
        let r = Resolver::new(
            &["not an address".to_string(), "1.0.0.1:53".to_string()],
            ResolverOptions::default(),
        );
        assert_eq!(r.upstreams().len(), 1);
        let r2 = Resolver::new(&["".to_string()], ResolverOptions::default());
        assert_eq!(r2.upstreams().len(), 2, "should fall back to public DNS");
    }
}
