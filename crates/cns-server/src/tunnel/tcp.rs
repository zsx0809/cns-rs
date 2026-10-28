//! TCP 隧道数据泵。
//!
//! 实现已下沉到 `cns_core::transport::pump`，服务端与客户端共用同一份代码
//! （旧版两边各写一份，同一个 bug 要修两遍，还修不一致）。这里只保留服务端
//! 需要的薄封装与兼容导出。

pub use cns_core::transport::{pump_bidirectional, pump_streams, BufferPool, PUMP_BUFFER_SIZE};

use cns_core::crypto::CuteBiCipher;
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;

/// 服务端会话：客户端 <-> 目标，带共享缓冲池
pub async fn pump_tcp_stream(
    client: TcpStream,
    target: TcpStream,
    cipher: CuteBiCipher,
    tcp_timeout: Duration,
) -> io::Result<()> {
    let pool = BufferPool::new();
    pump_bidirectional(client, target, cipher, tcp_timeout, &pool).await
}

/// 复用同一个池的会话（高并发下省掉每会话 2×32KB 分配）
pub async fn pump_tcp_stream_with_pool(
    client: TcpStream,
    target: TcpStream,
    cipher: CuteBiCipher,
    tcp_timeout: Duration,
    pool: &BufferPool,
) -> io::Result<()> {
    pump_bidirectional(client, target, cipher, tcp_timeout, pool).await
}
