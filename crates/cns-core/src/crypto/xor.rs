use base64::prelude::*;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    Base64DecodeError,
    InvalidTerminator,
    Utf8Error,
}

impl std::error::Error for CryptoError {}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Base64DecodeError => write!(f, "Invalid base64 payload"),
            CryptoError::InvalidTerminator => write!(f, "Decrypted host missing null terminator"),
            CryptoError::Utf8Error => write!(f, "Decrypted host is not valid UTF-8"),
        }
    }
}

/// 密钥流的最小重复单元：`base[j] = password[j] | j`（j 为口令内下标）。
///
/// 这是与原版 Go/C 逐字节对齐的定义 —— 密钥流在全局位置 p 取
/// `base[p % pass_len]`，其中的 `| j` 用的是**周期内**下标，不是全局下标。
fn build_base_mask(password: &[u8]) -> Vec<u8> {
    password.iter().enumerate().map(|(i, &b)| b | (i as u8)).collect()
}

/// 把基础表重复展开到「≥64 且为 8 的倍数」的长度，使热循环可 8 路批处理且无需
/// 每次判断回绕。展开后的表与基础表在模 `pass_len` 意义下完全等价。
fn build_expanded_mask(password: &[u8]) -> Vec<u8> {
    let base = build_base_mask(password);
    let raw_len = base.len();
    if raw_len == 0 {
        return base;
    }

    // 需要 repeat 次使得 raw_len * repeat ≡ 0 (mod 8)
    let gcd = |mut a: usize, mut b: usize| {
        while b != 0 {
            (a, b) = (b, a % b);
        }
        a
    };
    let mut repeat = 8 / gcd(raw_len, 8);
    while raw_len * repeat < MIN_VECTOR_LEN {
        repeat += 8 / gcd(raw_len, 8);
    }

    let mut table = Vec::with_capacity(raw_len * repeat);
    for _ in 0..repeat {
        table.extend_from_slice(&base);
    }
    table
}

const MIN_VECTOR_LEN: usize = 64;

/// CuteBi 流式异或混淆器（与原版 Go/C 协议兼容）。
///
/// 注意：这是**混淆**而非密码学加密。密钥流仅由口令决定且每个会话都从 0 开始，
/// 已知明文（固定 `GET / HTTP/1.1` 起始）可直接恢复密钥流前缀。它用于躲过 DPI
/// 特征匹配，不提供机密性。若需要真正的加密请另行协商 AEAD 会话密钥。
#[derive(Clone, Debug)]
pub struct CuteBiCipher {
    mask_table: Vec<u8>,
}

impl CuteBiCipher {
    /// 根据原始密码生成预计算掩码表
    pub fn new(password: &[u8]) -> Self {
        Self { mask_table: build_expanded_mask(password) }
    }

    /// 空混淆器（明文直通）
    pub fn empty() -> Self {
        Self { mask_table: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.mask_table.is_empty()
    }

    /// 密钥流周期（展开后表长，为基础表长的整数倍）
    pub fn key_len(&self) -> usize {
        self.mask_table.len()
    }

    /// 原位批量异或。返回更新后的游标，供下一 TCP 分片续用（保证分包语义一致）。
    pub fn crypt_in_place(&self, data: &mut [u8], password_sub: usize) -> usize {
        let table = &self.mask_table;
        let pass_len = table.len();
        if pass_len == 0 || data.is_empty() {
            return password_sub;
        }

        // 展开表长是 8 的倍数，故归一化到 [0, pass_len) 后仍可安全按 8 步进
        let mut idx = password_sub % pass_len;

        // 先处理到 8 对齐（pass_len 为 8 的倍数，对齐后按 8 步进永不越界错位）
        let head = ((8 - (idx % 8)) % 8).min(data.len());
        for d in &mut data[..head] {
            *d ^= table[idx];
            idx += 1;
            if idx == pass_len {
                idx = 0;
            }
        }

        let mut pos = head;
        // 此时 idx 必为 8 的倍数，pass_len 也是 8 的倍数 ⇒ idx + 8 <= pass_len 恒成立
        while pos + 8 <= data.len() {
            debug_assert!(idx % 8 == 0 && idx + 8 <= pass_len);
            for (d, m) in data[pos..pos + 8].iter_mut().zip(&table[idx..idx + 8]) {
                *d ^= *m;
            }
            idx += 8;
            if idx == pass_len {
                idx = 0;
            }
            pos += 8;
        }

        while pos < data.len() {
            data[pos] ^= table[idx];
            idx += 1;
            if idx == pass_len {
                idx = 0;
            }
            pos += 1;
        }

        idx
    }

    /// 解密 HTTP 伪装头中的目标地址 (Base64 + XOR)。规范：末字节必须为 `\0`。
    pub fn decrypt_host(&self, host_b64: &[u8]) -> Result<String, CryptoError> {
        let mut decoded =
            BASE64_STANDARD.decode(host_b64).map_err(|_| CryptoError::Base64DecodeError)?;

        if decoded.is_empty() {
            return Err(CryptoError::InvalidTerminator);
        }

        self.crypt_in_place(&mut decoded, 0);

        if *decoded.last().unwrap() != 0 {
            return Err(CryptoError::InvalidTerminator);
        }

        let host_bytes = &decoded[..decoded.len() - 1];
        String::from_utf8(host_bytes.to_vec()).map_err(|_| CryptoError::Utf8Error)
    }

    /// 将明文目标 host 混淆为 base64 字符串（客户端与集成测试使用）
    pub fn encrypt_host(&self, host: &str) -> String {
        let mut data = host.as_bytes().to_vec();
        data.push(0);
        self.crypt_in_place(&mut data, 0);
        BASE64_STANDARD.encode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 参考实现：严格逐字节按原版语义 `out[p] = in[p] ^ (pwd[p%L] | (p%L))`
    fn reference(password: &[u8], data: &[u8], start: usize) -> (Vec<u8>, usize) {
        if password.is_empty() {
            return (data.to_vec(), start);
        }
        let l = password.len();
        let mut out = data.to_vec();
        let mut sub = start;
        for b in out.iter_mut() {
            let j = sub % l;
            *b ^= password[j] | (j as u8);
            sub += 1;
        }
        (out, sub)
    }

    #[test]
    fn test_mask_table_definition() {
        let password = b"666";
        let cipher = CuteBiCipher::new(password);
        assert!(cipher.mask_table.len() % 8 == 0);
        assert!(cipher.mask_table.len() >= 64);
        for (i, &m) in cipher.mask_table.iter().enumerate() {
            let j = i % 3;
            assert_eq!(m, password[j] | (j as u8));
        }
    }

    #[test]
    fn test_matches_reference_across_all_lengths() {
        let passwords: Vec<Vec<u8>> = vec![
            b"1".to_vec(),
            b"666".to_vec(),
            b"tstkey".to_vec(),
            b"secret123456".to_vec(),
            b"Z".repeat(7),
            b"Z".repeat(13),
            b"Z".repeat(64),
            b"Z".repeat(100),
            b"Z".repeat(129),
        ];
        for pwd in passwords {
            let cipher = CuteBiCipher::new(&pwd);
            for len in [1usize, 2, 7, 8, 9, 15, 16, 63, 64, 65, 129, 300, 1024, 4096] {
                let plain: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
                let mut got = plain.clone();
                let end = cipher.crypt_in_place(&mut got, 0);
                let (want, want_end) = reference(&pwd, &plain, 0);
                assert_eq!(got, want, "pwd_len={} len={}", pwd.len(), len);
                assert_eq!(end % pwd.len(), want_end % pwd.len());
            }
        }
    }

    #[test]
    fn test_chunked_streaming_equals_whole() {
        let passwords: Vec<Vec<u8>> =
            vec![b"tstkey".to_vec(), b"a".to_vec(), b"abcdefghijklmnop".to_vec(), b"Z".repeat(13)];
        for pwd in passwords {
            let cipher = CuteBiCipher::new(&pwd);
            let full: Vec<u8> = (0..999).map(|i| (i * 7) as u8).collect();
            let mut whole = full.clone();
            cipher.crypt_in_place(&mut whole, 0);

            for split in [1usize, 7, 8, 9, 64, 100, 511, 998] {
                let mut a = full[..split].to_vec();
                let mut b = full[split..].to_vec();
                let next = cipher.crypt_in_place(&mut a, 0);
                cipher.crypt_in_place(&mut b, next);
                let mut joined = a;
                joined.extend_from_slice(&b);
                assert_eq!(joined, whole, "pwd_len={} split={}", pwd.len(), split);
            }
        }
    }

    #[test]
    fn test_xor_is_involution() {
        let cipher = CuteBiCipher::new(b"secret123456");
        let original = b"Hello, CuteBi Network Suite in pure Rust! Super fast stream.";
        let mut buffer = original.to_vec();
        let sub = cipher.crypt_in_place(&mut buffer, 0);
        assert_ne!(&buffer[..], &original[..]);
        let sub2 = cipher.crypt_in_place(&mut buffer, 0);
        assert_eq!(&buffer[..], &original[..]);
        assert_eq!(sub, sub2);
    }

    #[test]
    fn test_host_encrypt_decrypt_roundtrip() {
        for pwd in ["666", "tstkey", "a-very-long-passphrase-for-xor"] {
            let cipher = CuteBiCipher::new(pwd.as_bytes());
            for host in [
                "example.com:443",
                "1.1.1.1:443",
                "[2001:db8::1]:22",
                "mclient.alipay.com:80",
                &format!("{}:8080", "a".repeat(200)),
            ] {
                let enc = cipher.encrypt_host(host);
                assert_eq!(cipher.decrypt_host(enc.as_bytes()).unwrap(), host);
            }
        }
    }

    #[test]
    fn test_python_compatibility() {
        let cipher = CuteBiCipher::new(b"tstkey");
        let data = b"GET /generate_204 HTTP/1.1\r\nHost: connect.rom.miui.com\r\nConnection: close\r\n\r\n";
        let mut buf = data.to_vec();
        cipher.crypt_in_place(&mut buf, 0);

        let mask = [116u8, 115, 118, 107, 101, 125];
        let expected: Vec<u8> =
            data.iter().enumerate().map(|(i, &b)| b ^ mask[i % mask.len()]).collect();
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_empty_cipher_is_passthrough() {
        let cipher = CuteBiCipher::empty();
        assert!(cipher.is_empty());
        let data = b"plain bytes".to_vec();
        let mut buf = data.clone();
        let next = cipher.crypt_in_place(&mut buf, 0);
        assert_eq!(buf, data);
        assert_eq!(next, 0);
    }

    #[test]
    fn test_decrypt_host_rejects_bad_input() {
        let cipher = CuteBiCipher::new(b"tstkey");
        assert_eq!(
            cipher.decrypt_host(b"!!!not base64!!!").unwrap_err(),
            CryptoError::Base64DecodeError
        );
        assert_eq!(cipher.decrypt_host(b"").unwrap_err(), CryptoError::InvalidTerminator);
    }
}
