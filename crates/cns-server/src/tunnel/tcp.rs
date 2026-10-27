use cns_core::crypto::CuteBiCipher;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info};

const BUFFER_SIZE: usize = 32 * 1024; // 32KB 零拷贝缓冲

/// TCP 双向流式原位异或数据泵
pub async fn pump_tcp_stream(
    mut client: TcpStream,
    mut server: TcpStream,
    cipher: CuteBiCipher,
    tcp_timeout: Duration,
    initial_data: Vec<u8>,
) -> io::Result<()> {
    let (mut c_read, mut c_write) = client.split();
    let (mut s_read, mut s_write) = server.split();

    let client_cipher = cipher.clone();
    let server_cipher = cipher;

    // 客户端 -> 目标服务器（解密方向）
    let c2s = async move {
        let mut pass_sub = 0;

        // 如果握手报文包含粘包的初始载荷，优先解密并转发
        if !initial_data.is_empty() {
            let mut init_buf = initial_data;
            if !client_cipher.is_empty() {
                pass_sub = client_cipher.crypt_in_place(&mut init_buf, pass_sub);
            }
            info!(
                "Initial client payload forwarded ({} bytes): {:?}",
                init_buf.len(),
                String::from_utf8_lossy(&init_buf[..init_buf.len().min(64)])
            );
            timeout(tcp_timeout, s_write.write_all(&init_buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "initial write timed out"))??;
        }

        let mut buf = vec![0u8; BUFFER_SIZE];
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

            info!(
                "Client decrypted {} bytes to upstream: {:?}",
                n,
                String::from_utf8_lossy(&buf[..n.min(64)])
            );

            timeout(tcp_timeout, s_write.write_all(&buf[..n]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "c2s write timed out"))??;
        }
        let _ = s_write.shutdown().await;
        Ok::<(), io::Error>(())
    };

    // 目标服务器 -> 客户端（加密方向）
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

            info!(
                "Upstream returned {} raw bytes: {:?}",
                n,
                String::from_utf8_lossy(&buf[..n.min(64)])
            );

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
                pass_sub = server_cipher.crypt_in_place(&mut buf[..n], pass_sub);
            }

            timeout(tcp_timeout, c_write.write_all(&buf[..n]))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "s2c write timed out"))??;
        }
        let _ = c_write.shutdown().await;
        Ok::<(), io::Error>(())
    };

    // 任意一侧结束即完成双向协同清理
    tokio::select! {
        res = c2s => {
            if let Err(e) = res {
                debug!("TCP c2s stream closed: {}", e);
            }
        }
        res = s2c => {
            if let Err(e) = res {
                debug!("TCP s2c stream closed: {}", e);
            }
        }
    }

    Ok(())
}
