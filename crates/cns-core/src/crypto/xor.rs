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

/// CuteBi 流式异或加密器
#[derive(Clone, Debug)]
pub struct CuteBiCipher {
    mask_table: Vec<u8>,
}

impl CuteBiCipher {
    /// 构造函数：根据原始密码生成预计算掩码表 mask[i] = password[i] | i
    pub fn new(password: &[u8]) -> Self {
        let mask_table = if password.is_empty() {
            Vec::new()
        } else {
            password
                .iter()
                .enumerate()
                .map(|(i, &b)| b | (i as u8))
                .collect()
        };
        Self { mask_table }
    }

    /// 检查密码是否为空
    pub fn is_empty(&self) -> bool {
        self.mask_table.is_empty()
    }

    /// 原位（in-place）批量异或变换，输入输出同一段内存，零拷贝。
    /// 自动采用 64 位并行批量异或，剩余尾部单字节处理。
    /// 返回更新后的 password_sub 偏移游标。
    pub fn crypt_in_place(&self, data: &mut [u8], mut password_sub: usize) -> usize {
        let pass_len = self.mask_table.len();
        if pass_len == 0 || data.is_empty() {
            return password_sub;
        }

        let n = data.len();
        let mut data_sub = 0;

        // 8 字节（64 位）并行向量化异或
        while data_sub + 8 <= n {
            let mut m_bytes = [0u8; 8];
            for k in 0..8 {
                m_bytes[k] = self.mask_table[password_sub];
                password_sub += 1;
                if password_sub == pass_len {
                    password_sub = 0;
                }
            }
            let m = u64::from_ne_bytes(m_bytes);
            let chunk_ptr = data[data_sub..data_sub + 8].as_mut_ptr() as *mut u64;
            unsafe {
                *chunk_ptr ^= m;
            }
            data_sub += 8;
        }

        // 剩余尾部单字节处理
        while data_sub < n {
            data[data_sub] ^= self.mask_table[password_sub];
            data_sub += 1;
            password_sub += 1;
            if password_sub == pass_len {
                password_sub = 0;
            }
        }

        password_sub
    }

    /// 解密 HTTP 伪装头中的 Host (Base64 + XOR)
    /// 规范：解密后末尾字节必须为 0 (\0)，返回去除 \0 后的字符串
    pub fn decrypt_host(&self, host_b64: &[u8]) -> Result<String, CryptoError> {
        let mut decoded = BASE64_STANDARD
            .decode(host_b64)
            .map_err(|_| CryptoError::Base64DecodeError)?;

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

    /// 辅助方法：将明文目标 host 加密为 base64 字符串（用于客户端模拟与集成测试）
    pub fn encrypt_host(&self, host: &str) -> String {
        let mut data = host.as_bytes().to_vec();
        data.push(0); // 追加 \0
        self.crypt_in_place(&mut data, 0);
        BASE64_STANDARD.encode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_table_generation() {
        let password = b"666";
        let cipher = CuteBiCipher::new(password);
        // '6' is 54 (0x36)
        // i=0: 54 | 0 = 54
        // i=1: 54 | 1 = 55
        // i=2: 54 | 2 = 54
        assert_eq!(cipher.mask_table, vec![54 | 0, 54 | 1, 54 | 2]);
    }

    #[test]
    fn test_xor_symmetry() {
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
    fn test_stream_chunks() {
        let cipher = CuteBiCipher::new(b"cutebi_pwd");
        let full_data = b"This is a relatively long payload designed to test chunk streaming across multiple buffers.";
        let mut whole = full_data.to_vec();
        cipher.crypt_in_place(&mut whole, 0);

        // 分两段加密
        let mut chunk1 = full_data[..20].to_vec();
        let mut chunk2 = full_data[20..].to_vec();

        let next_sub = cipher.crypt_in_place(&mut chunk1, 0);
        cipher.crypt_in_place(&mut chunk2, next_sub);

        let mut combined = chunk1;
        combined.extend_from_slice(&chunk2);

        assert_eq!(whole, combined);
    }

    #[test]
    fn test_host_encrypt_decrypt() {
        let cipher = CuteBiCipher::new(b"666");
        let original_host = "example.com:443";
        let encrypted_b64 = cipher.encrypt_host(original_host);

        let decrypted = cipher.decrypt_host(encrypted_b64.as_bytes()).unwrap();
        assert_eq!(decrypted, original_host);
    }

    #[test]
    fn test_python_compatibility() {
        let cipher = CuteBiCipher::new(b"tstkey");
        let data = b"GET /generate_204 HTTP/1.1\r\nHost: connect.rom.miui.com\r\nConnection: close\r\n\r\n";
        let mut buf = data.to_vec();
        cipher.crypt_in_place(&mut buf, 0);
        
        let mask = [116u8, 115, 118, 107, 101, 125];
        let expected: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ mask[i % mask.len()]).collect();
        assert_eq!(buf, expected);
    }
}
