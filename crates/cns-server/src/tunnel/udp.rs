use bytes::{Bytes, BytesMut};
use cns_core::crypto::CuteBiCipher;
use cns_core::protocol::{canonicalize_addr, HttpUdpCodec, UdpPacket, MAX_PAYLOAD_LEN};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

/// UDP -> TCP 队列深度
const UDP_QUEUE_SIZE: usize = 2048;
/// 微聚合上限：单次 write 最多攒这么多字节
const MAX_BATCH_BYTES: usize = 32 * 1024;
/// 单个 httpUDP 报文上限（协议 2 字节长度前缀决定）
const MAX_UDP_DATAGRAM: usize = MAX_PAYLOAD_LEN;

/// 会话级观测计数（不写日志，只累计，供 /status 或 debug 输出）
#[derive(Default)]
pub struct UdpTunnelStats {
    pub packets_to_client: AtomicU64,
    pub packets_to_target: AtomicU64,
    pub dropped_queue_full: AtomicU64,
    pub bad_frames: AtomicU64,
}

pub struct UdpTunnel {
    client: TcpStream,
    udp_socket: Arc<UdpSocket>,
    cipher: CuteBiCipher,
    idle_timeout: Duration,
}

impl UdpTunnel {
    pub fn new(
        client: TcpStream,
        udp_socket: UdpSocket,
        cipher: CuteBiCipher,
        idle_timeout: Duration,
    ) -> Self {
        Self { client, udp_socket: Arc::new(udp_socket), cipher, idle_timeout }
    }

    /// 启动 UDP 隧道生命周期。
    ///
    /// 修复要点：
    /// * 旧实现 `while let Ok(Some(..)) = codec.decode(..)` 在解码报错时**不消费字节**，
    ///   缓冲区永远卡在同一坏帧上 → 会话活锁（不断流也不报错）。现在坏帧直接终止会话。
    /// * 接收超时按「空闲」语义续期，而不是整体硬超时；
    /// * 队列满时丢最新包并计数（保持实时性），不再静默丢弃。
    pub async fn run(self, initial_data: Vec<u8>) -> io::Result<()> {
        let stats = Arc::new(UdpTunnelStats::default());
        self.run_with_stats(initial_data, stats).await
    }

    pub async fn run_with_stats(
        self,
        initial_data: Vec<u8>,
        stats: Arc<UdpTunnelStats>,
    ) -> io::Result<()> {
        let (mut c_read, mut c_write) = self.client.into_split();
        let (tx, mut rx) = mpsc::channel::<UdpPacket>(UDP_QUEUE_SIZE);

        let socket_recv = Arc::clone(&self.udp_socket);
        let socket_send = Arc::clone(&self.udp_socket);

        let cipher_c2s = self.cipher.clone();
        let cipher_s2c = self.cipher.clone();
        let idle_timeout = self.idle_timeout;

        let stats_rx = Arc::clone(&stats);
        let stats_tx = Arc::clone(&stats);
        let stats_send = Arc::clone(&stats);

        // 任一子任务结束即整体收敛
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

        // 1. 目标网络 -> 队列
        let rx_shutdown = shutdown_tx.clone();
        let mut udp_recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_DATAGRAM];
            loop {
                let recv = timeout(idle_timeout, socket_recv.recv_from(&mut buf)).await;
                let (len, peer) = match recv {
                    Ok(Ok(res)) => res,
                    Ok(Err(e)) => {
                        debug!("UDP recv_from error: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("UDP idle for {idle_timeout:?}, closing tunnel");
                        break;
                    }
                };

                let packet = UdpPacket {
                    // 双栈 socket 会把 v4 对端报成 ::ffff:a.b.c.d，必须还原地址族
                    peer: canonicalize_addr(peer),
                    payload: Bytes::copy_from_slice(&buf[..len]),
                };

                match tx.try_send(packet) {
                    Ok(()) => {
                        stats_rx.packets_to_client.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // 背压：实时业务丢新包比排队旧包更有意义
                        stats_rx.dropped_queue_full.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            let _ = rx_shutdown.send(());
        });

        // 2. 队列 -> 客户端 TCP（微聚合 + 原位混淆）
        let tx_shutdown = shutdown_tx.clone();
        let mut tcp_send_task = tokio::spawn(async move {
            let mut codec = HttpUdpCodec::new();
            let mut batch_buf = BytesMut::with_capacity(MAX_BATCH_BYTES);
            let mut pass_sub = 0usize;

            while let Some(packet) = rx.recv().await {
                batch_buf.clear();
                if codec.encode(packet, &mut batch_buf).is_err() {
                    // 超长帧：跳过该包而不是写出坏帧污染字节流
                    stats_tx.bad_frames.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // 微聚合：队列里已就绪的报文一并打包，但不超阈值
                while batch_buf.len() < MAX_BATCH_BYTES {
                    match rx.try_recv() {
                        Ok(more) => {
                            let before = batch_buf.len();
                            if codec.encode(more, &mut batch_buf).is_err() {
                                batch_buf.truncate(before);
                                stats_tx.bad_frames.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => break,
                    }
                }

                if !cipher_s2c.is_empty() {
                    pass_sub = cipher_s2c.crypt_in_place(&mut batch_buf, pass_sub);
                }

                if timeout(idle_timeout, c_write.write_all(&batch_buf))
                    .await
                    .map_err(|e| debug!("UDP->TCP write timeout: {e:?}"))
                    .and_then(|r| r.map_err(|e| debug!("UDP->TCP write error: {e}")))
                    .is_err()
                {
                    break;
                }
            }
            let _ = c_write.shutdown().await;
            let _ = tx_shutdown.send(());
        });

        // 3. 客户端 TCP -> 目标网络
        let c_shutdown = shutdown_tx.clone();
        let mut tcp_recv_task = tokio::spawn(async move {
            let mut codec = HttpUdpCodec::new();
            let mut in_buffer = BytesMut::with_capacity(64 * 1024);
            let mut read_buf = vec![0u8; 32 * 1024];
            let mut pass_sub = 0usize;

            // 握手阶段粘在 HTTP 头之后的首帧数据
            if !initial_data.is_empty() {
                let mut data = initial_data;
                if !cipher_c2s.is_empty() {
                    pass_sub = cipher_c2s.crypt_in_place(&mut data, pass_sub);
                }
                in_buffer.extend_from_slice(&data);
                if drain_frames(&mut codec, &mut in_buffer, &socket_send, &stats_send)
                    .await
                    .is_err()
                {
                    let _ = c_shutdown.send(());
                    return;
                }
            }

            loop {
                let n = match timeout(idle_timeout, c_read.read(&mut read_buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        debug!("TCP read from client error: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("client idle for {idle_timeout:?}, closing tunnel");
                        break;
                    }
                };

                let chunk = &mut read_buf[..n];
                if !cipher_c2s.is_empty() {
                    pass_sub = cipher_c2s.crypt_in_place(chunk, pass_sub);
                }
                in_buffer.extend_from_slice(chunk);

                if drain_frames(&mut codec, &mut in_buffer, &socket_send, &stats_send)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = c_shutdown.send(());
        });

        // 任一方向退出即回收其它任务
        tokio::select! {
            _ = &mut udp_recv_task => {}
            _ = &mut tcp_send_task => {}
            _ = &mut tcp_recv_task => {}
            _ = shutdown_rx.recv() => {}
        }

        // 兜底取消：select 分支退出后其余任务仍在跑（例如阻塞在 socket 上）
        udp_recv_task.abort();
        tcp_send_task.abort();
        tcp_recv_task.abort();

        if stats.bad_frames.load(Ordering::Relaxed) > 0 {
            debug!(
                "httpUDP session ended with {} malformed frames",
                stats.bad_frames.load(Ordering::Relaxed)
            );
        }
        Ok(())
    }
}

/// 解出缓冲区里所有完整帧并打向目标。返回 Err 表示协议损坏，调用方必须终止会话。
async fn drain_frames(
    codec: &mut HttpUdpCodec,
    in_buffer: &mut BytesMut,
    socket: &UdpSocket,
    stats: &UdpTunnelStats,
) -> io::Result<()> {
    loop {
        match codec.decode(in_buffer) {
            Ok(Some(pkt)) => {
                stats.packets_to_target.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = socket.send_to(&pkt.payload, pkt.peer).await {
                    debug!("send_to {} failed: {e}", pkt.peer);
                }
            }
            Ok(None) => return Ok(()), // 需要更多字节
            Err(e) => {
                // 关键修复：坏帧不能原地不动，否则缓冲区永远卡在同一前缀 → 活锁
                stats.bad_frames.fetch_add(1, Ordering::Relaxed);
                warn!("httpUDP frame decode failed, closing session: {e}");
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;

    /// tokio 没有 TcpStream::pair，用 loopback listener 造一对
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let a = TcpStream::connect(addr).await.unwrap();
        let (b, _) = listener.accept().await.unwrap();
        (a, b)
    }

    /// 起一个会回显 UDP 的目标端
    async fn echo_peer() -> (SocketAddr, Arc<UdpSocket>) {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let s = Arc::clone(&sock);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = s.recv_from(&mut buf).await {
                let _ = s.send_to(&buf[..n], peer).await;
            }
        });
        (addr, sock)
    }

    #[tokio::test]
    async fn tunnel_forwards_udp_both_ways() {
        let (peer_addr, _) = echo_peer().await;
        let cipher = CuteBiCipher::new(b"tstkey");

        // 模拟客户端 TCP 半边
        let (app_side, mut app_peer) = tcp_pair().await;
        let out_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        out_socket.connect(peer_addr).await.unwrap();

        let tunnel = UdpTunnel::new(
            app_side,
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            cipher.clone(),
            Duration::from_secs(2),
        );
        let handle = tokio::spawn(tunnel.run(Vec::new()));

        // 构造 httpUDP 帧：目标为 echo peer
        let mut codec = HttpUdpCodec::new();
        let mut frame = BytesMut::new();
        codec
            .encode(
                UdpPacket { peer: peer_addr, payload: Bytes::from_static(b"ping-udp") },
                &mut frame,
            )
            .unwrap();
        let mut wire = frame.to_vec();
        cipher.crypt_in_place(&mut wire, 0);
        app_peer.write_all(&wire).await.unwrap();
        app_peer.flush().await.unwrap();

        // 读回一帧
        let mut raw = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(3), app_peer.read(&mut raw))
            .await
            .expect("must reply")
            .expect("read");
        let mut got = raw[..n].to_vec();
        cipher.crypt_in_place(&mut got, 0);

        let mut buf = BytesMut::from(&got[..]);
        let pkt = codec.decode(&mut buf).unwrap().expect("a frame");
        assert_eq!(pkt.peer, peer_addr);
        assert_eq!(&pkt.payload[..], b"ping-udp");

        drop(app_peer);
        let _ = timeout(Duration::from_secs(3), handle).await;
        let _ = out_socket;
    }

    #[tokio::test]
    async fn malformed_frame_terminates_instead_of_livelock() {
        // 旧实现在这里会活锁：坏帧不消费 → 反复报错但缓冲区不变
        let cipher = CuteBiCipher::empty();
        let (app_side, mut app_peer) = tcp_pair().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let tunnel = UdpTunnel::new(app_side, sock, cipher, Duration::from_secs(30));
        let handle = tokio::spawn(tunnel.run(Vec::new()));

        // pkg_len=12 且 addr_type=9（未定义），后面堆大量字节：旧实现会卡在同一个坏前缀上
        let mut bad = vec![12, 0, 0, 0, 0, 9, 1, 2, 3, 4, 0, 53, 0xAA, 0xBB];
        bad.extend_from_slice(&[0x7Fu8; 8192]);
        app_peer.write_all(&bad).await.unwrap();

        let res = timeout(Duration::from_secs(5), handle).await;
        assert!(res.is_ok(), "session must terminate, not livelock");
    }

    #[tokio::test]
    async fn idle_timeout_closes_tunnel() {
        let cipher = CuteBiCipher::empty();
        let (app_side, _app_peer) = tcp_pair().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tunnel = UdpTunnel::new(app_side, sock, cipher, Duration::from_millis(300));
        let res = timeout(Duration::from_secs(3), tunnel.run(Vec::new())).await;
        assert!(res.is_ok(), "idle timeout must end the session");
    }

    #[tokio::test]
    async fn drain_frames_reports_bad_frame() {
        let mut codec = HttpUdpCodec::new();
        let mut buf = BytesMut::from(&[12, 0, 0, 0, 0, 9, 1, 1, 1, 1, 0, 53, 1, 2][..]);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stats = UdpTunnelStats::default();
        assert!(drain_frames(&mut codec, &mut buf, &sock, &stats).await.is_err());
        assert_eq!(stats.bad_frames.load(Ordering::Relaxed), 1);
    }
}
