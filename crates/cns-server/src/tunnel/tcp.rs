use cns_core::crypto::CuteBiCipher;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const BUFFER_SIZE: usize = 32 * 1024; // 32KB 零拷贝缓冲

/// TCP 双向流式原位异或数据泵 (零垃圾产生、高性能非阻塞传输，完全对齐原版 Go 的 tcpForward 行为)
pub async fn pump_tcp_stream(
    mut client: TcpStream,
    mut server: TcpStream,
    cipher: CuteBiCipher,
    tcp_timeout: Duration,
) -> io::Result<()> {
    let (mut c_read, mut c_write) = client.split();
    let (mut s_read, mut s_write) = server.split();

    let client_cipher = cipher.clone();
    let server_cipher = cipher;

    // 客户端 -> 目标服务器（解密方向）
    // 严格对齐原版 Go：绝不主动向目标 SSH/TCP 服务器注入握手残余数据，保持目标服务纯净握手环境
    let c2s = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut pass_sub = 0;
        loop {
            let n = match timeout(tcp_timeout, c_read.read(&mut buf)).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "c2s read timed out")),
            };

            if !client_cipher.is_empty() {
                pass_sub = client_cipher.crypt_in_place(&mut buf[..n], pass_sub);
            }

            timeout(tcp_timeout, s_write.write_all(&buf[..n]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "c2s write timed out"))??;
        }
        let _ = s_write.shutdown().await;
        Ok::<(), io::Error>(())
    };

    // 目标服务器 -> 客户端（加密方向）
    // 目标 SSH 服务器率先推送的 SSH-2.0-OpenSSH Banner 将被顺畅读取并流式加密送回客户端
    let s2c = async move {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut pass_sub = 0;
        loop {
            let n = match timeout(tcp_timeout, s_read.read(&mut buf)).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "s2c read timed out")),
            };

            if !server_cipher.is_empty() {
                pass_sub = server_cipher.crypt_in_place(&mut buf[..n], pass_sub);
            }

            timeout(tcp_timeout, c_write.write_all(&buf[..n]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "s2c write timed out"))??;
        }
        let _ = c_write.shutdown().await;
        Ok::<(), io::Error>(())
    };

    tokio::try_join!(c2s, s2c)?;
    Ok(())
}
