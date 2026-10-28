use crate::outbound::resolver::Resolver;
use crate::outbound::Guard;
use bytes::{Buf, BytesMut};
use cns_core::crypto::CuteBiCipher;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};
use tracing::debug;

/// DNS 报文上限
const MAX_DNS_MSG: usize = 4096;
/// 单会话最多服务的查询数，防单连接长期独占
const MAX_QUERIES_PER_SESSION: usize = 64;
/// 竞速时对备用上游的让后窗口基数（毫秒），给首选上游一个优先机会
const RACE_BACKOFF_MS: u64 = 30;

/// httpDNS（`dn=`）快速响应。
///
/// 原版语义：`GET /vip.py?dn=host` → `ip,ttl`。旧实现用 `lookup_host`
/// （getaddrinfo，跑在 blocking 线程池上），高频回源会吃光 512 个阻塞线程。
/// 现在走自建异步 [Resolver]（带缓存、纯非阻塞）。
pub async fn handle_http_dns<W>(
    mut client: W,
    domain: &str,
    is_ipv6: bool,
    resolver: &Resolver,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = match resolver.lookup(domain).await {
        Ok(addrs) => addrs
            .iter()
            .find(|ip| ip.is_ipv6() == is_ipv6)
            .or_else(|| addrs.first())
            .map(|ip| format!("{ip},60")),
        Err(_) => None,
    };

    let response = match body {
        Some(ip_ttl) => format!(
            "HTTP/1.0 200 OK\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-Length: {}\r\n\r\n{}",
            ip_ttl.len(),
            ip_ttl
        ),
        None => httpdns_failure(),
    };

    client.write_all(response.as_bytes()).await?;
    let _ = timeout(Duration::from_secs(1), client.shutdown()).await;
    Ok(())
}

fn httpdns_failure() -> String {
    "HTTP/1.0 404 Not Found\r\nConnection: Close\r\nServer: CuteBi Linux Network httpDNS, (%>w<%)\r\nContent-type: text/plain\r\n\r\nDNS Lookup Failed".to_string()
}

/// 已 `connect` 到某上游的 UDP socket 缓存。
///
/// connect 后内核只投递该对端的包，天然防串包/防伪造应答，同时省掉每次查询
/// socket()/close() 的系统调用风暴。旧实现每查询每上游各新建一个 socket 且
/// 落败方永久 await → fd 泄漏直至 EMFILE。
type SocketMap = std::collections::HashMap<SocketAddr, Vec<std::sync::Arc<UdpSocket>>>;

#[derive(Clone, Default)]
struct UpstreamSockets(Arc<Mutex<SocketMap>>);

impl UpstreamSockets {
    async fn take(&self, up: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        if let Some(sock) =
            self.0.lock().ok().and_then(|mut m| m.get_mut(&up).and_then(|v| v.pop()))
        {
            return Ok(sock);
        }

        let bind: SocketAddr =
            if up.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let sock = cns_core::transport::create_tuned_udp_socket(bind)?;
        // connect 失败（如上游是 v6 但本机无 v6）直接向上报错，由竞速层忽略该上游
        sock.connect(up).await?;
        Ok(Arc::new(sock))
    }

    fn put(&self, up: SocketAddr, sock: Arc<UdpSocket>) {
        if let Ok(mut m) = self.0.lock() {
            let v = m.entry(up).or_default();
            if v.len() < 4 {
                v.push(sock);
            }
        }
    }

    #[cfg(test)]
    fn cached(&self) -> usize {
        self.0.lock().map(|m| m.values().map(|v| v.len()).sum()).unwrap_or(0)
    }
}

/// DNS TCP-over-UDP 会话：把 TCP 流按 `[2 字节大端长度][DNS 报文]` 逐个拆开，
/// 转成 UDP 打到真实 DNS 上游，再按同格式回写。
///
/// 关键修复：
/// * **收发两个方向各自维护连续游标**。旧实现对每个响应都从游标 0 重新混淆，
///   只在「一条连接一个查询」时正确；客户端复用连接发第二个查询就解不开。
/// * **支持粘包多查询**（Android netd 常连着发 A + AAAA）。
/// * **竞速任务带超时并 abort 落败方**，不再悬挂 fd。
/// * **上游经 SSRF 守卫**，且不再被客户端任意指定为内网地址。
pub async fn handle_dns_tcp_over_udp<C>(
    mut client: C,
    dns_server: &str,
    cipher: CuteBiCipher,
    idle_timeout: Duration,
    initial_data: Vec<u8>,
    guard: Guard,
    fallback_upstreams: &[String],
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut upstreams = resolve_dns_upstream(dns_server, guard).await?;
    // 客户端指定的上游不可用（或被守卫拒绝）时，回落到服务端配置的备用列表
    if upstreams.is_empty() {
        upstreams = resolve_dns_upstream_list(fallback_upstreams).await?;
    }
    if upstreams.is_empty() {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "no usable DNS upstream"));
    }

    let sockets = UpstreamSockets::default();
    let mut in_buf = BytesMut::with_capacity(512);
    in_buf.extend_from_slice(&initial_data);

    let mut in_sub = 0usize; // 客户端 -> 服务端方向密钥流游标
    let mut out_sub = 0usize; // 服务端 -> 客户端方向密钥流游标
    let mut served = 0usize;

    loop {
        // 1. 读满 2 字节长度前缀
        while in_buf.len() < 2 {
            if !fill(&mut client, &mut in_buf, idle_timeout).await? {
                return Ok(()); // 客户端正常关闭
            }
        }
        let mut len_bytes = [in_buf[0], in_buf[1]];
        if !cipher.is_empty() {
            in_sub = cipher.crypt_in_place(&mut len_bytes, in_sub);
        }
        let dns_len = u16::from_be_bytes(len_bytes) as usize;
        if dns_len == 0 || dns_len > MAX_DNS_MSG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid DNS message length {dns_len}"),
            ));
        }

        // 2. 读满整个查询
        while in_buf.len() < 2 + dns_len {
            if !fill(&mut client, &mut in_buf, idle_timeout).await? {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed mid DNS query",
                ));
            }
        }
        in_buf.advance(2);
        let mut query = in_buf.split_to(dns_len).to_vec();
        if !cipher.is_empty() {
            in_sub = cipher.crypt_in_place(&mut query, in_sub);
        }

        // 3. 上游竞速查询
        let answer = query_upstream_dns(&sockets, &upstreams, &query, idle_timeout).await?;

        // 4. 回写 [2 字节大端长度][应答]，out 方向游标连续推进
        let mut out = Vec::with_capacity(2 + answer.len());
        out.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        out.extend_from_slice(&answer);
        if !cipher.is_empty() {
            out_sub = cipher.crypt_in_place(&mut out, out_sub);
        }
        timeout(idle_timeout, client.write_all(&out))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS response write timeout"))??;

        served += 1;
        if served >= MAX_QUERIES_PER_SESSION {
            debug!("DNS session served {served} queries, closing for fairness");
            return Ok(());
        }
    }
}

/// 从流里再读一段进 buffer。返回 false 表示对端 EOF。
async fn fill<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
    idle_timeout: Duration,
) -> io::Result<bool> {
    let mut tmp = [0u8; 1024];
    match timeout(idle_timeout, reader.read(&mut tmp)).await {
        Ok(Ok(0)) => Ok(false),
        Ok(Ok(n)) => {
            buf.extend_from_slice(&tmp[..n]);
            Ok(true)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "DNS read idle timeout")),
    }
}

/// 把客户端传来的 DNS 目标解析成可用上游地址（过 SSRF 守卫）。
async fn resolve_dns_upstream(dns_server: &str, guard: Guard) -> io::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    if let Ok(addr) = dns_server.parse::<SocketAddr>() {
        if guard.check_ip(addr.ip()).is_ok() {
            out.push(addr);
        } else {
            debug!("rejected restricted DNS upstream {addr}");
        }
    } else {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(dns_server).await?.collect();
        out.extend(addrs.into_iter().filter(|a| guard.check_ip(a.ip()).is_ok()));
    }
    Ok(out)
}

/// 展开服务端**自己配置**的备用上游。
///
/// 这里刻意不过 SSRF 守卫：运维把上游写成 `127.0.0.1:53`（本机 unbound/pdnsd）
/// 或私网递归 DNS 是完全合法的部署方式。守卫只用于「客户端可任意伪造」的
/// `dns_server`，不用于运维显式配置的清单。
async fn resolve_dns_upstream_list(list: &[String]) -> io::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for item in list {
        if let Ok(addr) = item.parse::<SocketAddr>() {
            out.push(addr);
            continue;
        }
        match tokio::net::lookup_host(item).await {
            Ok(addrs) => out.extend(addrs),
            Err(e) => debug!("skip unusable DNS upstream {item}: {e}"),
        }
        if out.len() >= 4 {
            break;
        }
    }
    out.truncate(4);
    Ok(out)
}

/// 多上游竞速：返回第一个合法应答。所有任务都有硬超时，落败方立刻 abort。
async fn query_upstream_dns(
    sockets: &UpstreamSockets,
    upstreams: &[SocketAddr],
    query: &[u8],
    overall_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let hard_cap = overall_timeout.min(Duration::from_secs(5));
    let deadline = Instant::now() + hard_cap;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut handles = Vec::new();

    for (idx, up) in upstreams.iter().take(4).enumerate() {
        let up = *up;
        let q: Arc<Vec<u8>> = Arc::new(query.to_vec());
        let tx = tx.clone();
        let sockets = sockets.clone();
        handles.push(tokio::spawn(async move {
            // 非首选上游稍作让后，优先信任客户端/配置指定的近端上游
            if idx > 0 {
                tokio::time::sleep(Duration::from_millis(RACE_BACKOFF_MS * idx as u64)).await;
            }
            let sock = match sockets.take(up).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                sockets.put(up, sock);
                return;
            }
            // 必须用 await 版本：tokio 对刚建立的 UDP socket 首次 try_send 会返回 WouldBlock
            let send_ok = match timeout(remaining, sock.send(q.as_slice())).await {
                Ok(Ok(_n)) => true,
                Ok(Err(e)) => {
                    debug!("dns send to {up} failed: {e}");
                    false
                }
                Err(_) => {
                    debug!("dns send to {up} timed out");
                    false
                }
            };
            if !send_ok {
                drop(sock);
                return;
            }

            let mut buf = vec![0u8; MAX_DNS_MSG];
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(sock);
                return;
            }
            match timeout(remaining, sock.recv(&mut buf)).await {
                Ok(Ok(n)) if n >= 12 && buf[0..2] == q[0..2] => {
                    buf.truncate(n);
                    sockets.put(up, sock);
                    let _ = tx.send(buf);
                }
                _ => {
                    // 出错/超时的 socket 状态未知，不再归还池
                    drop(sock);
                }
            }
        }));
    }
    drop(tx);

    let res = timeout(hard_cap, rx.recv()).await;
    for h in handles {
        h.abort();
    }

    res.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "all DNS upstreams timed out"))?
        .ok_or_else(|| io::Error::other("no DNS upstream answered"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::resolver::ResolverOptions;
    use tokio::io::duplex;

    /// 构造一个最小 DNS 查询报文
    fn dns_query(fqdn: &[u8], v6: bool) -> Vec<u8> {
        let mut pkt = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in fqdn.split(|&b| b == b'.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label);
        }
        pkt.push(0);
        pkt.extend_from_slice(if v6 { &[0x00, 0x1c] } else { &[0x00, 0x01] });
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt
    }

    /// 假 DNS 上游：应答一条 A 记录 1.2.3.4，TTL 60
    async fn fake_dns() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x81;
                resp[3] = 0x80;
                resp[6] = 0;
                resp[7] = 1;
                resp.extend_from_slice(&[0xc0, 12]);
                resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
                resp.extend_from_slice(&[0x00, 0x04]);
                resp.extend_from_slice(&[1, 2, 3, 4]);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    /// 沉默上游（收到包也不回），用于验证竞速不会等它
    async fn silent_dns() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let _ = sock.recv_from(&mut buf).await;
            }
        });
        addr
    }

    /// 端到端：同一 TCP 会话内连续两个查询，双向游标必须各自连续且不串。
    #[tokio::test]
    async fn multi_query_session_keeps_both_keystreams() {
        let peer = fake_dns().await.to_string();
        let cipher = CuteBiCipher::new(b"tstkey");

        let (mut app, server_side) = duplex(16 * 1024);
        let c = cipher.clone();
        let fallback: Vec<String> = Vec::new();
        let handle = tokio::spawn(async move {
            handle_dns_tcp_over_udp(
                server_side,
                &peer,
                c,
                Duration::from_secs(5),
                Vec::new(),
                Guard::new(true),
                &fallback,
            )
            .await
        });

        let q1 = dns_query(b"example.com", false);
        let q2 = dns_query(b"example.net", true);

        // 客户端方向的连续密钥流
        let mut in_sub = 0usize;
        let mut wire = Vec::new();
        for q in [&q1, &q2] {
            let mut pkt = Vec::new();
            pkt.extend_from_slice(&(q.len() as u16).to_be_bytes());
            pkt.extend_from_slice(q);
            in_sub = cipher.crypt_in_place(&mut pkt, in_sub);
            wire.extend_from_slice(&pkt);
        }
        // 一次性写出，模拟粘包（两个查询挤在同一个 TCP 段）
        app.write_all(&wire).await.unwrap();

        // 服务端方向应为 [len][ans1][len][ans2]，且 out 方向密钥流从 0 连续推进
        let mut raw = vec![0u8; 8192];
        let mut total = 0usize;
        // 读够「两个完整帧」：至少 2 + l1 + 2 字节，且第二条长度可解析
        let want = {
            // 先读到能确定第一条长度
            while total < 2 {
                let n = timeout(Duration::from_secs(3), app.read(&mut raw[total..]))
                    .await
                    .expect("read timed out")
                    .expect("read");
                assert!(n > 0, "unexpected EOF before first length");
                total += n;
            }
            let mut probe = raw[..total].to_vec();
            cipher.crypt_in_place(&mut probe, 0);
            let l1 = u16::from_be_bytes([probe[0], probe[1]]) as usize;
            2 + l1 + 2
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while total < want && Instant::now() < deadline {
            let n = timeout(Duration::from_secs(3), app.read(&mut raw[total..]))
                .await
                .expect("read timed out")
                .expect("read");
            assert!(n > 0, "unexpected EOF waiting for second answer");
            total += n;
        }
        let mut decrypted = raw[..total].to_vec();
        cipher.crypt_in_place(&mut decrypted, 0);

        // 解析第一个应答
        let l1 = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
        assert!((12..=MAX_DNS_MSG).contains(&l1), "bad first length {l1}");
        let ans1 = &decrypted[2..2 + l1];
        assert_eq!(&ans1[0..2], &q1[0..2], "txid of answer 1");
        assert_eq!(&ans1[ans1.len() - 4..], &[1, 2, 3, 4], "A record");

        // 解析第二个应答 —— 旧实现在这里必然解不开
        let off = 2 + l1;
        assert!(decrypted.len() >= off + 2, "missing second length header");
        let l2 = u16::from_be_bytes([decrypted[off], decrypted[off + 1]]) as usize;
        assert!((12..=MAX_DNS_MSG).contains(&l2), "bad second length {l2}");
        let ans2 = &decrypted[off + 2..off + 2 + l2];
        assert_eq!(&ans2[0..2], &q2[0..2], "txid of answer 2");

        drop(app);
        let _ = timeout(Duration::from_secs(5), handle).await;
    }

    #[tokio::test]
    async fn initial_sticky_data_is_consumed() {
        // 握手残余里已经带着完整的第一个查询
        let peer = fake_dns().await.to_string();
        let cipher = CuteBiCipher::new(b"key123");
        let q = dns_query(b"mi.com", false);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&(q.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&q);
        cipher.crypt_in_place(&mut pkt, 0);

        let (mut app, server_side) = duplex(4096);
        let c = cipher.clone();
        let fb: Vec<String> = Vec::new();
        let handle = tokio::spawn(async move {
            handle_dns_tcp_over_udp(
                server_side,
                &peer,
                c,
                Duration::from_secs(4),
                pkt,
                Guard::new(true),
                &fb,
            )
            .await
        });

        let mut raw = vec![0u8; 2048];
        let n = timeout(Duration::from_secs(4), app.read(&mut raw))
            .await
            .expect("no answer")
            .expect("read");
        let mut dec = raw[..n].to_vec();
        cipher.crypt_in_place(&mut dec, 0);
        let l = u16::from_be_bytes([dec[0], dec[1]]) as usize;
        assert!(l >= 12);
        assert_eq!(&dec[2..4], &q[0..2]);

        drop(app);
        let _ = timeout(Duration::from_secs(4), handle).await;
    }

    #[tokio::test]
    async fn rejects_invalid_dns_length_without_hanging() {
        let peer = fake_dns().await.to_string();
        let fb: Vec<String> = Vec::new();
        for bad in [vec![0u8, 0], vec![0xFF, 0xFF, 1, 2, 3]] {
            let (_app, server_side) = duplex(256);
            let res = handle_dns_tcp_over_udp(
                server_side,
                &peer,
                CuteBiCipher::empty(),
                Duration::from_secs(2),
                bad,
                Guard::new(true),
                &fb,
            )
            .await;
            assert!(res.is_err(), "length 0 / oversized must be refused");
        }
    }

    #[tokio::test]
    async fn guard_blocks_restricted_upstream_and_falls_back() {
        // 客户端把 DNS 目标指向环回（旧实现会直接照用）
        let (_app, server_side) = duplex(256);
        let res = handle_dns_tcp_over_udp(
            server_side,
            "127.0.0.53:53",
            CuteBiCipher::empty(),
            Duration::from_secs(1),
            vec![0, 12, 0, 0, 0, 0],
            Guard::new(false),
            &[],
        )
        .await;
        assert!(res.is_err(), "restricted upstream with no fallback must fail");
    }

    #[tokio::test]
    async fn fallback_upstream_used_when_client_upstream_restricted() {
        let live = fake_dns().await.to_string();
        let cipher = CuteBiCipher::empty();
        let q = dns_query(b"ok.example", false);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&(q.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&q);

        let (mut app, server_side) = duplex(4096);
        let handle = tokio::spawn(async move {
            // 客户端指定的上游是环回（被守卫拒绝），备用列表里放真实假上游
            handle_dns_tcp_over_udp(
                server_side,
                "127.0.0.1:53",
                cipher,
                Duration::from_secs(4),
                pkt,
                Guard::new(false),
                &[live],
            )
            .await
        });

        let mut len_buf = [0u8; 2];
        timeout(Duration::from_secs(4), app.read_exact(&mut len_buf))
            .await
            .expect("fallback upstream must answer with a length prefix")
            .expect("read len");
        let l = u16::from_be_bytes(len_buf) as usize;
        assert!((12..=MAX_DNS_MSG).contains(&l), "bad fallback answer length {l}");
        let mut body = vec![0u8; l];
        timeout(Duration::from_secs(4), app.read_exact(&mut body))
            .await
            .expect("read body")
            .expect("read");
        assert_eq!(&body[body.len() - 4..], &[1, 2, 3, 4]);
        drop(app);
        let _ = timeout(Duration::from_secs(4), handle).await;
    }

    #[tokio::test]
    async fn race_ignores_silent_upstream_and_reclaims_tasks() {
        let silent = silent_dns().await;
        let live = fake_dns().await;
        let sockets = UpstreamSockets::default();
        let q = dns_query(b"race.test", false);

        let started = Instant::now();
        let ans = query_upstream_dns(&sockets, &[silent, live], &q, Duration::from_secs(3))
            .await
            .expect("live upstream should win the race");
        assert!(ans.len() >= 12);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must not block on the silent upstream"
        );
        // socket 已归还池，不会无限增长
        assert!(sockets.cached() <= 4, "socket pool leaked: {}", sockets.cached());
    }

    #[tokio::test]
    async fn race_times_out_when_all_upstreams_silent() {
        let s1 = silent_dns().await;
        let s2 = silent_dns().await;
        let sockets = UpstreamSockets::default();
        let res = query_upstream_dns(
            &sockets,
            &[s1, s2],
            &dns_query(b"nobody.test", false),
            Duration::from_millis(400),
        )
        .await;
        assert!(res.is_err(), "all-silent upstreams must time out, not hang");
    }

    #[tokio::test]
    async fn http_dns_answers_via_resolver() {
        let resolver = Resolver::new(&["127.0.0.1:1".to_string()], ResolverOptions::default());
        let (mut app, server_side) = duplex(4096);
        tokio::spawn(async move {
            let _ = handle_http_dns(server_side, "1.1.1.1", false, &resolver).await;
        });
        let mut buf = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(2), app.read(&mut buf))
            .await
            .expect("read")
            .expect("reply");
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(text.starts_with("HTTP/1.0 200 OK"), "{text}");
        assert!(text.ends_with("1.1.1.1,60"), "{text}");
        let len_line = text.lines().find(|l| l.starts_with("Content-Length:")).unwrap();
        let declared: usize = len_line.split(':').nth(1).unwrap().trim().parse().unwrap();
        assert_eq!(declared, "1.1.1.1,60".len());
    }

    #[tokio::test]
    async fn http_dns_returns_404_on_failure() {
        let resolver = Resolver::new(
            &["127.0.0.1:1".to_string()],
            ResolverOptions { query_timeout: Duration::from_millis(120), ..Default::default() },
        );
        let (mut app, server_side) = duplex(4096);
        tokio::spawn(async move {
            let _ = handle_http_dns(server_side, "definitely.invalid", false, &resolver).await;
        });
        let mut buf = vec![0u8; 2048];
        let n = timeout(Duration::from_secs(2), app.read(&mut buf))
            .await
            .expect("read")
            .expect("reply");
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.0 404"));
    }

    #[tokio::test]
    async fn session_closes_on_clean_eof() {
        let peer = fake_dns().await.to_string();
        let fb: Vec<String> = Vec::new();
        let (app, server_side) = duplex(1024);
        let handle = tokio::spawn(async move {
            handle_dns_tcp_over_udp(
                server_side,
                &peer,
                CuteBiCipher::empty(),
                Duration::from_secs(10),
                Vec::new(),
                Guard::new(true),
                &fb,
            )
            .await
        });
        drop(app); // 立即 EOF
        let res = timeout(Duration::from_secs(3), handle).await.expect("no hang");
        assert!(res.unwrap().is_ok(), "EOF is not an error");
    }

    #[tokio::test]
    async fn upstream_list_truncates_and_allows_operator_loopback() {
        let list: Vec<String> = (0..10).map(|i| format!("127.0.0.{i}:53")).collect();
        let out = resolve_dns_upstream_list(&list).await.unwrap();
        assert_eq!(out.len(), 4, "must cap concurrent upstreams");
        // 运维配置的 127.0.0.1 不被守卫拦截（本机递归 resolver 是合法部署）
        assert!(out[0].ip().is_loopback());
    }

    #[tokio::test]
    async fn client_supplied_upstream_is_still_guarded() {
        // 客户端伪造 dns_server=192.168.1.1:53 → 必须被拒
        let out = resolve_dns_upstream("192.168.1.1:53", Guard::new(false)).await.unwrap();
        assert!(out.is_empty(), "private upstream from client must be dropped");
        // 同样的地址若由运维配置则放行
        let fb = resolve_dns_upstream_list(&["192.168.1.1:53".to_string()]).await.unwrap();
        assert_eq!(fb.len(), 1);
    }
}
