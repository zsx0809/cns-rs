//! 隧道复用引擎（tcpDNS 与 httpUDP 共用一套驱动）。
//!
//! 为什么必须有：免流的本质是「每个会话都要带 HTTP 伪装头」，握手 = 一次完整
//! TCP 连接 + 一次 HTTP 往返。旧实现**每个 DNS 查询都新建一条到 VPS 的 TCP 连接**，
//! App 冷启动几十个域名就是几十个并发外连，握手开销远超查询本身，也是断流与
//! 发热的主因。
//!
//! 设计：一条长连接承载同一目标的多个并发请求。驱动任务**独占**读写两端，
//! 因此两个方向的密钥流游标天然串行、不会错位；响应按 key 分发
//! （tcpDNS 用 DNS 事务 ID，httpUDP 用帧内对端地址，由 `HttpUdpCodec` 解出）。

use crate::config::ClientConfig;
use bytes::{Buf, Bytes, BytesMut};
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{canonicalize_addr, HttpUdpCodec, UdpPacket};
use cns_core::transport::{connect_any_mss, read_response_head, response_is_ok};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

/// 复用通道的协议形态
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MuxKind {
    /// tcpDNS：请求/响应均为 `[2 字节大端长度][DNS 报文]`，按事务 ID 分发
    Dns,
    /// httpUDP：帧由 `HttpUdpCodec` 编解码，解出的数据报直接交给上层
    Udp,
}

/// txid -> 等待该 txid 应答的 FIFO 队列（含入队时刻，供过期回收）
type Waiters = HashMap<u16, VecDeque<(oneshot::Sender<Vec<u8>>, Instant)>>;

/// 提前到达、尚无等待者的应答（有界）
type Orphans = VecDeque<(u16, Vec<u8>)>;

struct OutFrame {
    /// tcpDNS 分发键（httpUDP 忽略）
    txid: u16,
    /// 明文 wire 字节，加密由驱动统一完成
    wire: Vec<u8>,
    reply: Option<oneshot::Sender<Vec<u8>>>,
    queued_at: Instant,
}

/// 一条可复用的隧道。克隆廉价（内部全 Arc）。
#[derive(Clone, Debug)]
pub struct MuxTunnel {
    req_tx: mpsc::UnboundedSender<OutFrame>,
    alive: Arc<AtomicBool>,
    failures: Arc<AtomicU64>,
    kind: MuxKind,
    label: Arc<str>,
    generation: u64,
}

impl MuxTunnel {
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    pub fn kind(&self) -> MuxKind {
        self.kind
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    fn submit(&self, frame: OutFrame) -> bool {
        self.alive.load(Ordering::Acquire) && self.req_tx.send(frame).is_ok()
    }

    /// tcpDNS 线格式：`[2 字节大端长度][DNS 报文]`（明文，加密由驱动做）
    pub fn dns_wire(query: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(2 + query.len());
        pkt.extend_from_slice(&(query.len() as u16).to_be_bytes());
        pkt.extend_from_slice(query);
        pkt
    }

    /// 发一个 DNS 查询并等待应答
    pub async fn dns_query(&self, msg: &[u8], wait: Duration) -> io::Result<Vec<u8>> {
        if msg.len() < 12 || msg.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid DNS query length {}", msg.len()),
            ));
        }
        let txid = txid_of(msg);
        let (tx, rx) = oneshot::channel();
        if !self.submit(OutFrame {
            txid,
            wire: Self::dns_wire(msg),
            reply: Some(tx),
            queued_at: Instant::now(),
        }) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{} tunnel unavailable", self.label),
            ));
        }
        match timeout(wait, rx).await {
            Ok(Ok(ans)) => Ok(ans),
            Ok(Err(_)) => {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "tunnel closed before answer"))
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{} answer timed out", self.label),
            )),
        }
    }

    /// 发一个 httpUDP 数据报帧（不等响应；响应由驱动投递到入向通道）
    pub fn udp_send(&self, peer: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > cns_core::protocol::MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("httpUDP payload length {} out of range", payload.len()),
            ));
        }
        let mut codec = HttpUdpCodec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                UdpPacket {
                    // 双栈 socket 会把 v4 对端报成 ::ffff:a.b.c.d，写帧前必须还原地址族
                    peer: canonicalize_addr(peer),
                    payload: Bytes::copy_from_slice(payload),
                },
                &mut buf,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("frame: {e}")))?;

        if !self.submit(OutFrame {
            txid: 0,
            wire: buf.to_vec(),
            reply: None,
            queued_at: Instant::now(),
        }) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "udp tunnel gone"));
        }
        Ok(())
    }

    /// 主动作废本隧道（驱动任务会随 sender 侧不再使用而收尾）
    pub fn close(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

/// 建立一条已完成握手的隧道并挂上驱动任务。
///
/// `target_for_header`：tcpDNS 的上游地址（写进伪装头）；httpUDP 传空串。
/// `udp_out`：httpUDP 模式下驱动把解出的入向数据报发到这里。
impl MuxTunnel {
    /// 建立一条已完成握手的隧道并挂上驱动任务。
    ///
    /// `target_for_header`：tcpDNS 的上游地址（写进伪装头）；httpUDP 传空串。
    /// `udp_out`：httpUDP 模式下驱动把解出的入向数据报发到这里。
    pub async fn open(
        config: &Arc<ClientConfig>,
        cipher: &Arc<CuteBiCipher>,
        kind: MuxKind,
        target_for_header: &str,
        udp_out: Option<mpsc::UnboundedSender<UdpPacket>>,
    ) -> io::Result<MuxTunnel> {
        let header = match kind {
            MuxKind::Dns => {
                let target = if cipher.is_empty() {
                    target_for_header.to_string()
                } else {
                    cipher.encrypt_host(target_for_header)
                };
                config.render_fake_header(&target)
            }
            MuxKind::Udp => config.render_udp_header(),
        };

        let mut stream = connect_any_mss(&config.cns_server, config.enable_tfo, config.tun_mtu)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("dial {} : {e}", config.cns_server)))?;
        // 同 tunnel.rs：TFO_CONNECT 下建连推迟到首写，首写必须有超时。
        timeout(config.timeout(), stream.write_all(&header))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake write timed out"))??;

        let (head, sticky) =
            read_response_head(&mut stream, config.timeout(), config.max_handshake_response())
                .await?;
        if !response_is_ok(&head) {
            let text = String::from_utf8_lossy(&head).to_string();
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("CNS handshake rejected by {}: {}", config.cns_server, text.trim()),
            ));
        }

        let label: Arc<str> = match kind {
            MuxKind::Dns => format!("tcpDNS->{target_for_header}").into(),
            MuxKind::Udp => "httpUDP".into(),
        };

        let (req_tx, req_rx) = mpsc::unbounded_channel::<OutFrame>();
        let alive = Arc::new(AtomicBool::new(true));
        let failures = Arc::new(AtomicU64::new(0));
        let generation = NEXT_GEN.fetch_add(1, Ordering::Relaxed);

        static NEXT_GEN: AtomicU64 = AtomicU64::new(1);

        spawn_driver(
            stream,
            sticky.to_vec(),
            Arc::clone(cipher),
            kind,
            Arc::clone(&label),
            req_rx,
            Arc::clone(&alive),
            Arc::clone(&failures),
            config.timeout(),
            udp_out,
        );

        Ok(MuxTunnel { req_tx, alive, failures, kind, label, generation })
    }
}

fn txid_of(msg: &[u8]) -> u16 {
    if msg.len() >= 2 {
        u16::from_be_bytes([msg[0], msg[1]])
    } else {
        0
    }
}

#[derive(Debug)]
enum Frame {
    Ready(Vec<u8>),
    NeedMore,
    Corrupt,
}

/// 切出一个 `[2 字节大端长度][DNS 报文]`
fn take_dns_frame(buf: &mut BytesMut) -> Frame {
    if buf.len() < 2 {
        return Frame::NeedMore;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 || len > 4096 {
        return Frame::Corrupt;
    }
    if buf.len() < 2 + len {
        return Frame::NeedMore;
    }
    buf.advance(2);
    Frame::Ready(buf.split_to(len).to_vec())
}

#[allow(clippy::too_many_arguments)]
fn spawn_driver(
    stream: tokio::net::TcpStream,
    prefill: Vec<u8>,
    cipher: Arc<CuteBiCipher>,
    kind: MuxKind,
    label: Arc<str>,
    mut req_rx: mpsc::UnboundedReceiver<OutFrame>,
    alive: Arc<AtomicBool>,
    failures: Arc<AtomicU64>,
    idle: Duration,
    udp_out: Option<mpsc::UnboundedSender<UdpPacket>>,
) {
    tokio::spawn(async move {
        let (mut reader, mut writer) = stream.into_split();
        let mut out_sub = 0usize;
        let mut in_sub = 0usize;
        // 同一 txid 可能并发多个相同查询，FIFO 保证每个等待者都拿到一个答案
        let mut routes: Waiters = HashMap::new();
        // 应答可能比注册更早到达（服务端把 200 与首个应答粘在同一段），
        // 没有这里就会被丢弃 —— 正是旧实现「随机 DNS 超时」的根因之一
        let mut orphans: Orphans = VecDeque::new();
        let mut buf = BytesMut::with_capacity(8192);
        let mut tmp = vec![0u8; 8192];

        // 关键修复：握手响应之后粘在同一段里的残余数据绝不能丢，
        // 旧实现把它整包扔掉，导致后续 read_exact 死等（表现为图片时好时坏）。
        if !prefill.is_empty() {
            let mut chunk = prefill;
            if !cipher.is_empty() {
                in_sub = cipher.crypt_in_place(&mut chunk, in_sub);
            }
            buf.extend_from_slice(&chunk);
        }

        let mut broken: Option<std::io::Error> = None;

        loop {
            // 1. 先把缓冲里已完整的响应切干净
            loop {
                match kind {
                    MuxKind::Dns => match take_dns_frame(&mut buf) {
                        Frame::Ready(msg) => {
                            let txid = txid_of(&msg);
                            if !deliver_one(&mut routes, txid, &msg) {
                                push_orphan(&mut orphans, txid, msg, &label);
                            }
                        }
                        Frame::NeedMore => break,
                        Frame::Corrupt => {
                            debug!("[{label}] corrupt dns frame, ending tunnel");
                            broken = Some(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "corrupt dns frame",
                            ));
                            break;
                        }
                    },
                    MuxKind::Udp => {
                        let mut codec = HttpUdpCodec::new();
                        match codec.decode(&mut buf) {
                            Ok(Some(pkt)) => match &udp_out {
                                Some(tx) => {
                                    if tx.send(pkt).is_err() {
                                        debug!("[{label}] udp consumer gone");
                                        broken = Some(io::Error::new(
                                            io::ErrorKind::BrokenPipe,
                                            "consumer gone",
                                        ));
                                        break;
                                    }
                                }
                                None => {
                                    debug!("[{label}] unexpected inbound frame, dropped");
                                }
                            },
                            Ok(None) => break,
                            Err(e) => {
                                // 修复：坏帧不能原地不动，否则缓冲区永远卡在同一前缀 → 活锁
                                debug!("[{label}] httpUDP frame corrupt ({e}), ending tunnel");
                                broken = Some(e);
                                break;
                            }
                        }
                    }
                }
            }
            if broken.is_some() {
                break;
            }

            // 2. 清理已彻底过期的等待者，避免 routes 无界增长
            prune(&mut routes, idle);

            // 3. 读写并行推进
            tokio::select! {
                // 不要 `biased;`：请求队列持续非空时，固定顺序会让读分支永远排不上，
                // 入向应答被无限期推迟（DNS 表现为「查得到但不回」）。
                maybe = req_rx.recv() => {
                    let Some(frame) = maybe else {
                        debug!("[{label}] all senders dropped, ending tunnel");
                        break;
                    };
                    let OutFrame { txid, mut wire, reply, queued_at } = frame;
                    if let Some(tx) = reply {
                        // 先看有没有提前到达的应答
                        if let Some(idx) = orphans.iter().position(|(t, _)| *t == txid) {
                            let (_, msg) = orphans.remove(idx).expect("just located");
                            let _ = tx.send(msg);
                        } else {
                            routes.entry(txid).or_default().push_back((tx, queued_at));
                        }
                    }
                    if !cipher.is_empty() {
                        out_sub = cipher.crypt_in_place(&mut wire, out_sub);
                    }
                    if let Err(e) = write_all_checked(&mut writer, &wire, idle).await {
                        debug!("[{label}] write failed: {e}");
                        broken = Some(e);
                        break;
                    }
                }

                res = timeout(idle, reader.read(&mut tmp)) => {
                    match res {
                        Ok(Ok(0)) => { debug!("[{label}] server closed"); break; }
                        Ok(Ok(n)) => {
                            let mut chunk = tmp[..n].to_vec();
                            if !cipher.is_empty() {
                                in_sub = cipher.crypt_in_place(&mut chunk, in_sub);
                            }
                            buf.extend_from_slice(&chunk);
                        }
                        Ok(Err(e)) => { debug!("[{label}] read error: {e}"); broken = Some(e); break; }
                        Err(_) => { debug!("[{label}] idle > {idle:?}, recycling"); break; }
                    }
                }
            }
        }

        // 退出：让所有在途等待者立刻失败，而不是干等到超时
        routes.clear();
        orphans.clear();
        alive.store(false, Ordering::Release);
        failures.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = broken {
            debug!("[{label}] driver exited: {e}");
        }
    });
}

/// 把应答投递给对应 txid 的第一个存活等待者。返回 false 表示无人等待。
fn deliver_one(routes: &mut Waiters, txid: u16, msg: &[u8]) -> bool {
    if let Some(q) = routes.get_mut(&txid) {
        while let Some((tx, _)) = q.pop_front() {
            if !tx.is_closed() {
                let _ = tx.send(msg.to_vec());
                if q.is_empty() {
                    routes.remove(&txid);
                }
                return true;
            }
            // 等待者已超时/放弃，继续找下一个
        }
        routes.remove(&txid);
    }
    false
}

/// 暂存提前到达的应答（有界，避免被异常服务端灌满内存）
fn push_orphan(orphans: &mut Orphans, txid: u16, msg: Vec<u8>, label: &str) {
    const ORPHAN_CAP: usize = 32;
    if orphans.len() >= ORPHAN_CAP {
        if let Some((t, _)) = orphans.pop_front() {
            debug!("[{label}] orphan queue full, discarded oldest txid {t}");
        }
    }
    debug!("[{label}] answer for txid {txid} arrived before waiter, parked");
    orphans.push_back((txid, msg));
}

fn prune(routes: &mut Waiters, idle: Duration) {
    let cutoff = Instant::now() - idle * 3;
    for q in routes.values_mut() {
        while matches!(q.front(), Some((_, t)) if *t < cutoff) {
            q.pop_front();
        }
    }
    routes.retain(|_, q| !q.is_empty());
}

async fn write_all_checked<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    bytes: &[u8],
    idle: Duration,
) -> io::Result<()> {
    timeout(idle, async {
        w.write_all(bytes).await?;
        w.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write timed out"))?
}

/// tcpDNS 高层句柄：带「死了就重建」语义，对上层完全透明
pub struct DnsChannel {
    config: Arc<ClientConfig>,
    cipher: Arc<CuteBiCipher>,
    upstream: SocketAddr,
    current: Mutex<Option<MuxTunnel>>,
    builds: AtomicU64,
    /// 单飞锁：并发 miss 时只允许一个任务真正建隧道，其余等它建完后复用。
    /// 没有它就会退化成「每查询一条连接」，正是本次要消灭的行为。
    building: Arc<tokio::sync::Mutex<()>>,
}

impl DnsChannel {
    pub fn new(config: Arc<ClientConfig>, cipher: Arc<CuteBiCipher>, upstream: SocketAddr) -> Self {
        Self {
            config,
            cipher,
            upstream,
            current: Mutex::new(None),
            builds: AtomicU64::new(0),
            building: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    pub fn tunnel_builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }

    fn peek_current(&self) -> Option<MuxTunnel> {
        self.current.lock().ok().and_then(|g| g.clone())
    }

    fn drop_current(&self, t: &MuxTunnel) {
        if let Ok(mut g) = self.current.lock() {
            // 只在仍是同一条隧道时才清空，避免误删别人刚建好的
            if let Some(cur) = g.as_ref() {
                if cur.generation() == t.generation() {
                    *g = None;
                }
            }
        }
    }

    async fn ensure(&self) -> io::Result<MuxTunnel> {
        // 快路径：已有存活隧道直接复用
        if let Some(t) = self.peek_current() {
            if t.is_alive() {
                return Ok(t);
            }
        }

        // 慢路径：单飞。拿到锁后必须再检查一次，因为等锁期间别人可能已经建好了
        let _guard = self.building.lock().await;
        if let Some(t) = self.peek_current() {
            if t.is_alive() {
                return Ok(t);
            }
        }

        let t = MuxTunnel::open(
            &self.config,
            &self.cipher,
            MuxKind::Dns,
            &self.upstream.to_string(),
            None,
        )
        .await?;
        self.builds.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.current.lock() {
            *g = Some(t.clone());
        }
        Ok(t)
    }

    /// 查询一次；隧道失效时重建一次再试（旧的「一次查询一条连接」变体保留为兜底）
    pub async fn query(&self, msg: &[u8]) -> io::Result<Vec<u8>> {
        let wait = self.config.timeout();
        let mut last_err = io::Error::other("no attempt made");

        for attempt in 0..2u8 {
            match self.ensure().await {
                Ok(t) => match t.dns_query(msg, wait).await {
                    Ok(ans) => return Ok(ans),
                    Err(e) => {
                        debug!("dns query attempt {attempt} failed on {}: {e}", t.label());
                        // 只有「隧道真的坏了」才拆它。单个查询超时不能杀掉承载着
                        // 另外几十个并发查询的共享隧道——否则一次慢查询会级联重建，
                        // 把整条 DNS 瀑布拖垮（默认 60 s 下这是最常见的抖动源）。
                        let fatal = !matches!(
                            e.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        );
                        last_err = e;
                        if fatal {
                            t.close();
                            self.drop_current(&t);
                        }
                    }
                },
                Err(e) => {
                    warn!("dns tunnel open failed: {e}");
                    last_err = e;
                    tokio::time::sleep(Duration::from_millis(80)).await;
                }
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_config(server: SocketAddr) -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
            socks5_listen: String::new(),
            dns_listen: String::new(),
            tproxy_listen: None,
            gid: None,
            cns_server: server.to_string(),
            cns_password: "mux-test-key".to_string(),
            proxy_key: "Meng".to_string(),
            udp_flag: "httpUDP".to_string(),
            header_host: "mclient.alipay.com".to_string(),
            custom_header: None,
            enable_tfo: false,
            timeout_seconds: 2,
            ..Default::default()
        })
    }

    fn dns_msg(txid: u16) -> Vec<u8> {
        let mut m = vec![(txid >> 8) as u8, (txid & 0xff) as u8, 0x01, 0x00];
        m.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&[3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 0, 0, 1, 0, 1]);
        m
    }

    /// mock tcpDNS 服务端：按 `[len][msg]` 切帧并原样回显。
    /// 原样回显刻意保持事务 ID 不变 —— 真实 DNS 应答必须复用查询的 txid，
    /// 客户端正是按 txid 路由的。断言 `answer == query` 是最强的分发正确性校验。
    ///
    /// 协议事实（与真实客户端一致）：HTTP 伪装头是**明文**发送的，
    /// 头之后的隧道载荷才从密钥流游标 0 开始异或。所以头部绝不能再解一次。
    async fn serve_dns_mock(stream: TcpStream, cipher: Arc<CuteBiCipher>) {
        let (mut reader, mut writer) = stream.into_split();
        let mut acc: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 1024];
        let mut sub_in = 0usize;
        let mut sub_out = 0usize;

        loop {
            let n = reader.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            acc.extend_from_slice(&tmp[..n]);
            if let Some(idx) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                // 头部之后可能已经粘着第一个加密查询，必须保留
                let rest = acc.split_off(idx + 4);
                writer
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await
                    .unwrap();
                let mut buf = BytesMut::from(&rest[..]);
                mock_loop(&mut reader, &mut writer, &cipher, &mut buf, &mut sub_in, &mut sub_out)
                    .await;
                return;
            }
            if acc.len() > 8192 {
                return;
            }
        }
    }

    async fn mock_loop<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
        reader: &mut R,
        writer: &mut W,
        cipher: &Arc<CuteBiCipher>,
        buf: &mut BytesMut,
        sub_in: &mut usize,
        sub_out: &mut usize,
    ) {
        let mut r = [0u8; 2048];
        loop {
            while buf.len() >= 2 {
                let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if len == 0 || len > 4096 || buf.len() < 2 + len {
                    break;
                }
                buf.advance(2);
                let ans = buf.split_to(len).to_vec();
                let mut out = Vec::new();
                out.extend_from_slice(&(ans.len() as u16).to_be_bytes());
                out.extend_from_slice(&ans);
                if !cipher.is_empty() {
                    *sub_out = cipher.crypt_in_place(&mut out, *sub_out);
                }
                if writer.write_all(&out).await.is_err() {
                    return;
                }
            }
            match timeout(Duration::from_secs(4), reader.read(&mut r)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                Ok(Ok(n)) => {
                    let mut chunk = r[..n].to_vec();
                    if !cipher.is_empty() {
                        *sub_in = cipher.crypt_in_place(&mut chunk, *sub_in);
                    }
                    buf.extend_from_slice(&chunk);
                }
            }
        }
    }

    /// 核心回归：8 个并发查询必须只建**一条** TCP 连接，且答案互不串扰。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_concurrent_queries_share_a_single_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cipher = Arc::new(CuteBiCipher::new(b"mux-test-key"));
        let conns = Arc::new(AtomicU64::new(0));

        {
            let c = Arc::clone(&cipher);
            let cn = Arc::clone(&conns);
            tokio::spawn(async move {
                while let Ok((s, _)) = listener.accept().await {
                    cn.fetch_add(1, Ordering::Relaxed);
                    let cc = Arc::clone(&c);
                    tokio::spawn(async move { serve_dns_mock(s, cc).await });
                }
            });
        }

        let config = test_config(addr);
        let channel = Arc::new(DnsChannel::new(Arc::clone(&config), Arc::clone(&cipher), addr));

        let mut tasks = Vec::new();
        for i in 0..8u16 {
            // 关键：8 个任务共用同一个 DnsChannel，才能验证「一条隧道跑多个请求」
            let ch = Arc::clone(&channel);
            let msg = dns_msg(0x1000 + i);
            tasks.push(tokio::spawn(async move {
                let ans = ch.query(&msg).await.expect("answer must arrive");
                (msg, ans, ch.tunnel_builds())
            }));
        }

        for t in tasks {
            let (msg, ans, builds) = t.await.unwrap();
            assert!(ans.len() >= 12, "answer too short: {}", ans.len());
            assert_eq!(txid_of(&ans), txid_of(&msg), "wrong txid delivered");
            // 原样回显语义下，答案必须逐字节等于它自己的查询 —— 分发不能串
            assert_eq!(ans, msg, "answer content mismatch (cross-talk?)");
            assert!(builds >= 1);
        }
        // 复用生效：连接数应远小于查询数（允许极偶尔的 idle 回收）
        let used = conns.load(Ordering::Relaxed);
        assert!(used <= 3, "mux regressed: {used} TCP connections for 8 queries (old code = 8)");
    }

    #[test]
    fn dns_wire_framing() {
        let q = dns_msg(0xABCD);
        let wire = MuxTunnel::dns_wire(&q);
        assert_eq!(&wire[0..2], &(q.len() as u16).to_be_bytes());
        assert_eq!(&wire[2..], &q[..]);
        assert_eq!(txid_of(&q), 0xABCD);
        assert_eq!(txid_of(&[0x00]), 0);
    }

    #[test]
    fn take_dns_frame_state_machine() {
        let mut buf = BytesMut::from(&[0x00, 0x02, 0xAA][..]);
        assert!(matches!(take_dns_frame(&mut buf), Frame::NeedMore));
        buf.extend_from_slice(&[0xBB]);
        match take_dns_frame(&mut buf) {
            Frame::Ready(v) => assert_eq!(v, vec![0xAA, 0xBB]),
            other => panic!("expected ready, got {other:?}"),
        }
        assert!(buf.is_empty());

        for (bytes, want) in
            [(&[0x00u8, 0x00][..], true), (&[0xFF, 0xFF, 1][..], true), (&[0x00][..], false)]
        {
            let mut b = BytesMut::from(bytes);
            let corrupt = matches!(take_dns_frame(&mut b), Frame::Corrupt);
            assert_eq!(corrupt, want, "{bytes:?}");
        }
    }

    /// 同一 txid 的并发查询必须按 FIFO 各自拿到一个答案（不能都收到同一个）
    #[test]
    fn deliver_one_is_fifo_per_txid() {
        let mut routes: Waiters = HashMap::new();
        let (a_tx, a_rx) = oneshot::channel();
        let (b_tx, b_rx) = oneshot::channel();
        let q = routes.entry(7).or_default();
        q.push_back((a_tx, Instant::now()));
        q.push_back((b_tx, Instant::now()));

        assert!(deliver_one(&mut routes, 7, &[1, 2]));
        assert!(deliver_one(&mut routes, 7, &[3, 4]));
        assert_eq!(a_rx.blocking_recv().unwrap(), vec![1, 2]);
        assert_eq!(b_rx.blocking_recv().unwrap(), vec![3, 4]);
        assert!(routes.is_empty());

        // 无人等待时返回 false，不 panic
        assert!(!deliver_one(&mut routes, 99, &[0]));
    }

    #[test]
    fn prune_drops_closed_waiters() {
        let mut routes: Waiters = HashMap::new();
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        drop(rx);
        routes.entry(1).or_default().push_back((tx, Instant::now() - Duration::from_secs(100)));
        prune(&mut routes, Duration::from_millis(10));
        assert!(routes.is_empty(), "expired waiter must be reaped");

        // 未过期的一律保留
        let (tx2, _rx2) = oneshot::channel::<Vec<u8>>();
        routes.entry(2).or_default().push_back((tx2, Instant::now()));
        prune(&mut routes, Duration::from_secs(30));
        assert_eq!(routes.values().next().map(|q| q.len()), Some(1));
    }

    #[test]
    fn deliver_one_skips_closed_waiters() {
        let mut routes: Waiters = HashMap::new();
        // 第一个等待者已经不要了（客户端超时后 drop 了 receiver）
        let (dead_tx, dead_rx) = oneshot::channel::<Vec<u8>>();
        drop(dead_rx);
        let (live_tx, live_rx) = oneshot::channel::<Vec<u8>>();
        let q = routes.entry(5).or_default();
        q.push_back((dead_tx, Instant::now()));
        q.push_back((live_tx, Instant::now()));

        assert!(deliver_one(&mut routes, 5, b"payload"));
        assert_eq!(live_rx.blocking_recv().unwrap(), b"payload");
        assert!(routes.is_empty(), "emptied bucket must be removed");
        // 无等待者时返回 false
        assert!(!deliver_one(&mut routes, 9, b"x"));
    }

    #[test]
    fn orphan_queue_is_bounded_and_matched() {
        let mut orphans: Orphans = VecDeque::new();
        let label: Arc<str> = "t".into();
        for i in 0..40u16 {
            push_orphan(&mut orphans, i, vec![i as u8], &label);
        }
        assert_eq!(orphans.len(), 32, "orphan queue must stay bounded");
        // 命中即取走
        let idx = orphans.iter().position(|(t, _)| *t == 39).expect("newest kept");
        let (_, msg) = orphans.remove(idx).unwrap();
        assert_eq!(msg, vec![39u8]);
    }

    #[tokio::test]
    async fn open_fails_fast_on_unreachable_server() {
        let cipher = Arc::new(CuteBiCipher::new(b"k"));
        // 端口 1 基本不会有监听者
        let config = test_config(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
        let err = MuxTunnel::open(&config, &cipher, MuxKind::Udp, "", None).await.unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::Other
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn handshake_rejection_surfaces_as_error() {
        // 服务端回 403：客户端必须报错而不是当成成功隧道
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut b = [0u8; 64];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.0 403 Forbidden\r\n\r\n").await;
            }
        });
        let config = test_config(addr);
        let cipher = Arc::new(CuteBiCipher::new(b"k"));
        let err =
            MuxTunnel::open(&config, &cipher, MuxKind::Dns, "8.8.8.8:53", None).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err:?}");
    }

    #[tokio::test]
    async fn sticky_bytes_after_response_head_are_not_lost() {
        // 服务端把「200 响应」与「第一个答案」粘在同一段发出
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cipher = Arc::new(CuteBiCipher::new(b"mux-test-key"));
        let c = Arc::clone(&cipher);
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let mut acc: Vec<u8> = Vec::new();
            let mut b = [0u8; 512];
            loop {
                let n = s.read(&mut b).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                acc.extend_from_slice(&b[..n]); // 伪装头是明文
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let msg = dns_msg(0x2222);
            let mut out = Vec::new();
            out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            out.extend_from_slice(&msg);
            c.crypt_in_place(&mut out, 0);
            // 粘成一包发出
            let mut sticky: Vec<u8> =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            sticky.extend_from_slice(&out);
            let _ = s.write_all(&sticky).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let config = test_config(addr);
        let t = MuxTunnel::open(&config, &cipher, MuxKind::Dns, "1.1.1.1:53", None)
            .await
            .expect("open");
        // 残余已在缓冲里，dns_query 不该再等下一次 read
        let ans = t
            .dns_query(&dns_msg(0x2222), Duration::from_secs(2))
            .await
            .expect("sticky answer must be recovered");
        assert_eq!(txid_of(&ans), 0x2222);
        assert!(ans.len() >= 12);
    }

    #[tokio::test]
    async fn udp_send_encodes_canonical_family() {
        let (tx, mut rx) = mpsc::unbounded_channel::<UdpPacket>();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cipher = Arc::new(CuteBiCipher::new(b"mux-test-key"));
        tokio::spawn(async move {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let mut b = [0u8; 512];
            let _ = s.read(&mut b).await;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").await;
            // 读一帧再原样送回
            let mut acc = BytesMut::new();
            let c = cipher_for_task();
            let mut sub = 0usize;
            loop {
                let mut r = [0u8; 2048];
                let n = match s.read(&mut r).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let mut chunk = r[..n].to_vec();
                if !c.is_empty() {
                    sub = c.crypt_in_place(&mut chunk, sub);
                }
                acc.extend_from_slice(&chunk);
                let mut codec = HttpUdpCodec::new();
                if let Ok(Some(pkt)) = codec.decode(&mut acc) {
                    let mut out = BytesMut::new();
                    let _ = codec.encode(pkt, &mut out);
                    let mut wire = out.to_vec();
                    if !c.is_empty() {
                        c.crypt_in_place(&mut wire, 0);
                    }
                    let _ = s.write_all(&wire).await;
                    return;
                }
            }
        });

        let config = test_config(addr);
        let t = MuxTunnel::open(&config, &cipher, MuxKind::Udp, "", Some(tx)).await.unwrap();
        let mapped: SocketAddr = "[::ffff:203.0.113.33]:7777".parse().unwrap();
        t.udp_send(mapped, b"dlv").unwrap();

        let pkt = timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("no datagram back")
            .expect("channel");
        assert!(pkt.peer.is_ipv4(), "peer must be canonicalized: {}", pkt.peer);
        assert_eq!(pkt.peer.port(), 7777);
        assert_eq!(&pkt.payload[..], b"dlv");
    }

    fn cipher_for_task() -> Arc<CuteBiCipher> {
        Arc::new(CuteBiCipher::new(b"mux-test-key"))
    }

    #[tokio::test]
    async fn dns_query_rejects_bad_lengths() {
        let (tx, _rx) = mpsc::unbounded_channel::<OutFrame>();
        let t = MuxTunnel {
            req_tx: tx,
            alive: Arc::new(AtomicBool::new(true)),
            failures: Arc::new(AtomicU64::new(0)),
            kind: MuxKind::Dns,
            label: "t".into(),
            generation: 1,
        };
        assert!(t.dns_query(b"short", Duration::from_millis(10)).await.is_err());
        let big = vec![0u8; 5000];
        assert!(t.dns_query(&big, Duration::from_millis(10)).await.is_err());
        assert!(t.udp_send("1.2.3.4:53".parse().unwrap(), b"").is_err());
    }
}
