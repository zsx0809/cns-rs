//! 双向流式原位异或数据泵（服务端与客户端共用同一份实现）。
//!
//! 旧代码里 server 的 `tunnel/tcp.rs` 与 client 的 `outbound/tunnel.rs` 各写了
//! 一份几乎相同的 pump。两份都有的问题这里一次修掉：
//!
//! * **半关闭**：`tokio::try_join!` 在任一侧返回 Err 时会 drop 另一侧 future，
//!   直接掐断仍在传输的反方向。改成 `join!` + 结果合并。
//! * **EOF 后必须 shutdown 对向写端**，否则对端要等到 idle 超时才感知断开
//!   （表现为「关掉 App 后 VPS 侧连接挂 300 秒」）。
//! * **缓冲复用**：旧实现每连接每方向 `vec![0u8; 32768]`，4096 并发即常驻 ~256MB，
//!   与「1.5MB 微内核」的宣传完全相反。现在走共享 `BufferPool`。

use crate::crypto::CuteBiCipher;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// 单方向搬运缓冲大小
pub const PUMP_BUFFER_SIZE: usize = 32 * 1024;

/// 缓冲池：克隆廉价；高并发下避免反复 alloc/free 大块内存。
#[derive(Clone, Default)]
pub struct BufferPool {
    pool: Arc<Mutex<Vec<Vec<u8>>>>,
    cap: usize,
}

impl BufferPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// 限制池内缓存数量（占用 ≈ cap × 32KB）
    pub fn with_cap(cap: usize) -> Self {
        Self { pool: Arc::new(Mutex::new(Vec::new())), cap: cap.max(1) }
    }

    pub fn get(&self) -> Vec<u8> {
        let mut buf = self.pool.lock().ok().and_then(|mut p| p.pop()).unwrap_or_default();
        buf.resize(PUMP_BUFFER_SIZE, 0);
        buf
    }

    /// 归还缓冲；容量不足的一律丢弃，防止污染池
    pub fn put(&self, buf: Vec<u8>) {
        if buf.capacity() < PUMP_BUFFER_SIZE {
            return;
        }
        if let Ok(mut p) = self.pool.lock() {
            if p.len() < self.cap {
                p.push(buf);
            }
        }
    }

    pub fn cached(&self) -> usize {
        self.pool.lock().map(|p| p.len()).unwrap_or(0)
    }
}

/// 单向搬运：`read -> 原位异或 -> write`，全程保留密钥流游标（TCP 分包必需）。
///
/// 结束（EOF 或错误）时 shutdown 自己的写端，让对端尽快感知半关闭。
/// `prefill` 是握手阶段已经收到、但尚未转发的字节（HTTP 头之后的粘包载荷）。
/// 它属于本方向的密钥流起点，必须在 pump 内部按游标解密，绝不能在外面另起游标。
async fn pump_one<R, W>(
    reader: &mut R,
    writer: &mut W,
    cipher: &CuteBiCipher,
    idle: Duration,
    buf: &mut [u8],
    prefill: &[u8],
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut pass_sub = 0usize;
    let mut result = Ok(());

    if !prefill.is_empty() {
        let mut chunk = prefill.to_vec();
        if !cipher.is_empty() {
            pass_sub = cipher.crypt_in_place(&mut chunk, pass_sub);
        }
        let r = match timeout(idle, writer.write_all(&chunk)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "prefill write timeout")),
        };
        if let Err(e) = r {
            let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
            return Err(e);
        }
    }

    loop {
        let n = match timeout(idle, reader.read(buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                result = Err(e);
                break;
            }
            Err(_) => {
                result = Err(io::Error::new(io::ErrorKind::TimedOut, "read idle timeout"));
                break;
            }
        };

        if !cipher.is_empty() {
            pass_sub = cipher.crypt_in_place(&mut buf[..n], pass_sub);
        }

        match timeout(idle, writer.write_all(&buf[..n])).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                result = Err(e);
                break;
            }
            Err(_) => {
                result = Err(io::Error::new(io::ErrorKind::TimedOut, "write timeout"));
                break;
            }
        }
    }

    // 半关闭：正常 EOF 与出错都要通知对向
    let _ = timeout(Duration::from_secs(1), writer.shutdown()).await;
    result
}

/// 双向泵：A <-> B，两个方向各自维护密钥流游标。
///
/// 语义与原版 Go 的 `tcpForward` 对齐：不主动把握手残余塞给目标，
/// 全部数据走同一条连续密钥流。
pub async fn pump_bidirectional<A, B>(
    side_a: A,
    side_b: B,
    cipher: CuteBiCipher,
    idle: Duration,
    pool: &BufferPool,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    pump_bidirectional_with_prefill(side_a, side_b, cipher, idle, pool, Vec::new(), Vec::new())
        .await
}

/// 带握手粘包注入的双向泵。
///
/// * `prefill_to_b`：客户端 HTTP 头之后粘来的载荷，需要转发给目标端 B；
/// * `prefill_to_a`：服务端响应头之后粘来的载荷，需要转发给本地应用 A。
///
/// 旧实现把这两段残余直接丢掉 —— 表现为「目标先推的数据随机丢失」。
/// 注意每个方向的游标都从 0 起算，因此 prefill 必须在 pump 内部解密。
pub async fn pump_bidirectional_with_prefill<A, B>(
    side_a: A,
    side_b: B,
    cipher: CuteBiCipher,
    idle: Duration,
    pool: &BufferPool,
    prefill_to_b: Vec<u8>,
    prefill_to_a: Vec<u8>,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let (mut a_read, mut a_write) = tokio::io::split(side_a);
    let (mut b_read, mut b_write) = tokio::io::split(side_b);

    let mut buf_ab = pool.get();
    let mut buf_ba = pool.get();

    let ab = pump_one(&mut a_read, &mut b_write, &cipher, idle, &mut buf_ab, &prefill_to_b);
    let ba = pump_one(&mut b_read, &mut a_write, &cipher, idle, &mut buf_ba, &prefill_to_a);

    // join! 而非 try_join!：一侧结束绝不能掐断另一侧
    let (r_ab, r_ba) = tokio::join!(ab, ba);

    pool.put(buf_ab);
    pool.put(buf_ba);

    match (r_ab, r_ba) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(e1), Err(_)) => Err(e1),
    }
}

/// 便捷版：自带一个临时缓冲池
pub async fn pump_streams<A, B>(
    side_a: A,
    side_b: B,
    cipher: CuteBiCipher,
    idle: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let pool = BufferPool::new();
    pump_bidirectional(side_a, side_b, cipher, idle, &pool).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    fn cipher() -> CuteBiCipher {
        CuteBiCipher::new(b"pump-key-tstkey")
    }

    /// 真实 TCP 回显端，验证跨内核缓冲的搬运
    #[tokio::test]
    async fn roundtrip_over_real_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 256];
            if let Ok(n) = s.read(&mut b).await {
                let _ = s.write_all(&b[..n]).await;
                let _ = s.shutdown().await;
            }
        });

        let (mut app_peer, app_side) = tokio::io::duplex(4096);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let c = cipher();
        tokio::spawn(async move {
            let _ = pump_streams(app_side, tcp, c, Duration::from_secs(3)).await;
        });

        let payload = b"pump bidirectional over real tcp";
        let mut enc = payload.to_vec();
        cipher().crypt_in_place(&mut enc, 0);
        app_peer.write_all(&enc).await.unwrap();

        let mut got = vec![0u8; payload.len()];
        timeout(Duration::from_secs(3), app_peer.read_exact(&mut got))
            .await
            .expect("no echo")
            .expect("read");
        cipher().crypt_in_place(&mut got, 0);
        assert_eq!(got, payload);
    }

    /// 反方向先推数据（SSH banner 语义）也必须被搬运
    #[tokio::test]
    async fn server_first_banner_flows() {
        let (mut a_peer, a_side) = tokio::io::duplex(4096);
        let (mut b_peer, b_side) = tokio::io::duplex(4096);
        // 本测试只考察搬运方向性与半关闭，故用空混淆器
        let h = tokio::spawn(pump_streams(
            a_side,
            b_side,
            CuteBiCipher::empty(),
            Duration::from_secs(2),
        ));

        b_peer.write_all(b"SSH-2.0-OpenSSH").await.unwrap();
        let mut got = [0u8; 15];
        timeout(Duration::from_secs(2), a_peer.read_exact(&mut got))
            .await
            .expect("banner lost")
            .expect("read");
        assert_eq!(&got, b"SSH-2.0-OpenSSH");

        a_peer.write_all(b"hi").await.unwrap();
        let mut back = [0u8; 2];
        timeout(Duration::from_secs(2), b_peer.read_exact(&mut back))
            .await
            .expect("reverse lost")
            .expect("read");
        assert_eq!(&back, b"hi");

        drop(a_peer);
        drop(b_peer);
        let _ = timeout(Duration::from_secs(4), h).await;
    }

    /// 旧实现用 try_join!：一侧 EOF 立刻 drop 另一侧，反方向剩余数据被吞
    #[tokio::test]
    async fn one_way_eof_does_not_cut_the_other_way() {
        let (mut a_peer, a_side) = tokio::io::duplex(8192);
        let (mut b_peer, b_side) = tokio::io::duplex(8192);

        let h = tokio::spawn(pump_streams(
            a_side,
            b_side,
            CuteBiCipher::empty(),
            Duration::from_secs(5),
        ));

        a_peer.write_all(b"from-a").await.unwrap();
        a_peer.shutdown().await.unwrap();

        // B 侧稍后才回数据：此时 pump 的另一方向必须仍然活着
        tokio::time::sleep(Duration::from_millis(120)).await;
        b_peer.write_all(b"late-from-b").await.unwrap();

        let mut got = vec![0u8; 6];
        timeout(Duration::from_secs(2), b_peer.read_exact(&mut got))
            .await
            .expect("A->B data lost")
            .expect("read");
        assert_eq!(&got, b"from-a");

        let mut late = vec![0u8; 11];
        timeout(Duration::from_secs(2), a_peer.read_exact(&mut late))
            .await
            .expect("B->A late data was cut by try_join semantics")
            .expect("read");
        assert_eq!(&late, b"late-from-b");

        drop(b_peer);
        let _ = timeout(Duration::from_secs(6), h).await;
    }

    #[tokio::test]
    async fn large_transfer_keeps_keystream_aligned() {
        let blob: Vec<u8> = (0..300 * 1024).map(|i| (i * 29 + 3) as u8).collect();
        let (mut a_peer, a_side) = tokio::io::duplex(1 << 16);
        let (mut b_peer, b_side) = tokio::io::duplex(1 << 16);

        let expect = blob.len();
        let c = cipher();
        let mut enc = blob.clone();
        c.crypt_in_place(&mut enc, 0);

        tokio::spawn(async move {
            let mut acc: Vec<u8> = Vec::with_capacity(expect);
            let mut t = [0u8; 16384];
            while acc.len() < expect {
                match b_peer.read(&mut t).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => acc.extend_from_slice(&t[..n]),
                }
            }
            let _ = b_peer.write_all(&acc).await;
        });

        let h = tokio::spawn(pump_streams(a_side, b_side, cipher(), Duration::from_secs(10)));
        a_peer.write_all(&enc).await.unwrap();

        let mut got: Vec<u8> = Vec::with_capacity(expect);
        let mut t = [0u8; 16384];
        while got.len() < expect {
            match a_peer.read(&mut t).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&t[..n]),
            }
        }
        cipher().crypt_in_place(&mut got, 0);
        assert_eq!(got.len(), blob.len());
        assert_eq!(got, blob, "keystream drifted across chunks");

        drop(a_peer);
        let _ = timeout(Duration::from_secs(5), h).await;
    }

    /// 握手粘包：HTTP 头之后的载荷必须被转发而不是丢弃
    /// 握手粘包：HTTP 头之后的残余载荷必须被转发，且游标接续正确
    #[tokio::test]
    async fn prefill_is_forwarded_with_correct_keystream() {
        let c = cipher();
        let (mut a_peer, a) = tokio::io::duplex(4096);
        let (mut b_peer, b) = tokio::io::duplex(4096);
        let pool = BufferPool::new();

        // 客户端把「HTTP 头 + 第一段载荷」写进了同一段：残余密文作为 prefill_to_b 交给 pump
        let payload = b"sticky-first-payload";
        let mut encrypted = payload.to_vec();
        let next_sub = c.crypt_in_place(&mut encrypted, 0);
        // 游标是展开表内的下标 = 已消耗字节数 mod 表长
        assert_eq!(next_sub, payload.len() % c.key_len());

        let pool_in_task = pool.clone();
        let h = tokio::spawn(async move {
            pump_bidirectional_with_prefill(
                a,
                b,
                cipher(),
                Duration::from_secs(2),
                &pool_in_task,
                encrypted,
                Vec::new(),
            )
            .await
        });

        let mut got = vec![0u8; payload.len()];
        timeout(Duration::from_secs(2), b_peer.read_exact(&mut got))
            .await
            .expect("prefill payload lost")
            .expect("read");
        assert_eq!(got, payload, "prefill must be decrypted at this direction's cursor");

        // 后续数据继续沿同一条游标（旧实现丢了 prefill，这里必然错位）
        let more = b"second-chunk";
        let mut cont = more.to_vec();
        c.crypt_in_place(&mut cont, next_sub);
        a_peer.write_all(&cont).await.unwrap();

        let mut got2 = vec![0u8; more.len()];
        timeout(Duration::from_secs(2), b_peer.read_exact(&mut got2))
            .await
            .expect("follow-up lost")
            .expect("read");
        assert_eq!(got2, more, "keystream must continue after prefill");

        drop(a_peer);
        drop(b_peer);
        // 本测试只验 prefill 语义；缓冲回收由 shared_pool_recycles_buffers_across_sessions 专门覆盖
        let _ = timeout(Duration::from_secs(6), h).await;
        let _ = pool;
    }

    #[tokio::test]
    async fn idle_timeout_surfaces_error() {
        let (_ka, a) = tokio::io::duplex(64);
        let (_kb, b) = tokio::io::duplex(64);
        let res = timeout(
            Duration::from_millis(1500),
            pump_streams(a, b, CuteBiCipher::empty(), Duration::from_millis(150)),
        )
        .await
        .expect("must return on idle timeout");
        assert!(res.is_err());
    }

    #[test]
    fn buffer_pool_reuses_and_validates_capacity() {
        let pool = BufferPool::with_cap(2);
        let b1 = pool.get();
        assert_eq!(b1.len(), PUMP_BUFFER_SIZE);
        pool.put(b1);
        assert_eq!(pool.cached(), 1);
        let b2 = pool.get();
        assert_eq!(pool.cached(), 0);
        pool.put(b2);
        pool.put(pool.get());
        assert!(pool.cached() <= 2, "cap must be honored");

        // 容量不足的缓冲必须被丢弃
        let before = pool.cached();
        pool.put(vec![0u8; 8]);
        pool.put(Vec::new());
        assert_eq!(pool.cached(), before);
    }

    /// 共享池的价值所在：会话结束后缓冲必须被归还，且池不会无限增长
    #[tokio::test]
    async fn shared_pool_recycles_buffers_across_sessions() {
        let pool = BufferPool::with_cap(4);
        // 先手动掏空，确保起点为 0
        while pool.cached() > 0 {
            let b = pool.get();
            drop(b);
        }
        assert_eq!(pool.cached(), 0);

        // 跑两个会话（顺序执行，避免调度影响断言）
        for _ in 0..2 {
            let (a_peer, a) = tokio::io::duplex(1024);
            let (b_peer, b) = tokio::io::duplex(1024);
            let p = pool.clone();
            let h = tokio::spawn(async move {
                pump_bidirectional(a, b, CuteBiCipher::empty(), Duration::from_millis(200), &p)
                    .await
            });
            drop(a_peer);
            drop(b_peer);
            let r = timeout(Duration::from_secs(3), h).await;
            assert!(r.is_ok(), "session must finish on its own");
        }

        // 每个会话归还 2 个缓冲（两个方向各一），第二个会话复用后仍归还 2 个
        assert!(
            pool.cached() >= 2,
            "buffers must be recycled into the shared pool, got {}",
            pool.cached()
        );
        assert!(pool.cached() <= 4, "pool cap must be honored");
    }

    #[tokio::test]
    async fn plaintext_cipher_passthrough_works() {
        let (mut a_peer, a) = tokio::io::duplex(1024);
        let (mut b_peer, b) = tokio::io::duplex(1024);
        let h = tokio::spawn(pump_streams(a, b, CuteBiCipher::empty(), Duration::from_secs(2)));
        a_peer.write_all(b"plain").await.unwrap();
        let mut got = [0u8; 5];
        b_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"plain");
        b_peer.write_all(b"back").await.unwrap();
        let mut back = [0u8; 4];
        a_peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
        drop(a_peer);
        drop(b_peer);
        let _ = timeout(Duration::from_secs(3), h).await;
    }
}
