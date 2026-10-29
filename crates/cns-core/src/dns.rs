//! DNS 报文的读写工具（客户端 fakeip 应答 + 上游应答解析共用）。
//!
//! 为什么下沉到 core：客户端要**构造**应答（fakeip 秒回），服务端要**解析**应答
//! （回源地址族择优），httpUDP 隧道两端还要校验 txid。三处各写一份压缩指针
//! 处理逻辑，历史上已经因此出过「客户端能解、服务端解错」的偏差。
//!
//! 压缩指针规则只需要两条：
//! * 读：`11xxxxxx xxxxxxxx` = 指针，偏移是低 14 位；纯跳过时指针按 2 字节结束。
//! * 写：应答里的 RR name 一律用 `0xC0 0x0C` 指向偏移 12（= Question 的 QNAME 起点），
//!   前提是问题段被原样复制在偏移 12 —— 本模块的构造器保证了这一点。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;
/// 报文头长度
pub const HEADER_LEN: usize = 12;

/// 单条应答记录
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
}

impl Record {
    pub fn rtype(&self) -> u16 {
        match self {
            Record::A(_) => TYPE_A,
            Record::AAAA(_) => TYPE_AAAA,
        }
    }

    pub fn rdata_len(&self) -> usize {
        match self {
            Record::A(_) => 4,
            Record::AAAA(_) => 16,
        }
    }

    fn write_rdata(&self, out: &mut Vec<u8>) {
        match self {
            Record::A(v4) => out.extend_from_slice(&v4.octets()),
            Record::AAAA(v6) => out.extend_from_slice(&v6.octets()),
        }
    }
}

/// 从 `IpAddr` 造记录（fakeip 分配器与解析结果回写都用得上）。
pub fn record_of(ip: IpAddr) -> Record {
    match ip {
        IpAddr::V4(v4) => Record::A(v4),
        IpAddr::V6(v6) => Record::AAAA(v6),
    }
}

/// 解析出的查询问题段
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// 小写、无末尾点的域名（根域为 ""）
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// 问题段结束后的下标（QCLASS 之后）
    pub end: usize,
}

/// 跳过（只推进游标，不读内容）一个 DNS 名称，返回结束后的下标。
///
/// 压缩指针按「2 字节结束」处理：名称在指针处即终止，后续字节属于 RR 头。
/// 需要读全名请用 [`read_name`]。
pub fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            msg.get(pos + 1)?;
            return Some(pos + 2);
        }
        pos += 1 + len;
    }
}

/// 读出完整域名（跟随压缩指针），返回 `(小写名称, 物理结束下标)`。
///
/// 指针只允许指向**更靠前**的偏移：向后跳会拼出无限环，这里直接判非法，
/// 顺带把「畸形报文把中继线程挂死」这一类故障堵在解析层。
pub fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut physical_end = start;
    let mut jumps = 0usize;
    const MAX_JUMPS: usize = 128;

    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            physical_end = physical_end.max(pos + 1);
            break;
        }
        if len & 0xc0 == 0xc0 {
            let lo = *msg.get(pos + 1)? as usize;
            let off = ((len & 0x3f) << 8) | lo;
            if off >= start || off >= msg.len() {
                return None;
            }
            physical_end = physical_end.max(pos + 2);
            pos = off;
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            continue;
        }
        let s = pos + 1;
        let e = s + len;
        if e > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[s..e]).to_ascii_lowercase());
        physical_end = physical_end.max(e);
        pos = e;
    }

    Some((labels.join("."), physical_end))
}

/// 解析查询报文的问题段（只接受 QDCOUNT==1，与中继/隧道语义一致：
/// 多问题报文的事务 ID 回填与压缩指针都会错乱）。
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let (name, after_name) = read_name(msg, HEADER_LEN)?;
    if after_name + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
    let qclass = u16::from_be_bytes([msg[after_name + 2], msg[after_name + 3]]);
    Some(Question { name, qtype, qclass, end: after_name + 4 })
}

/// 把域名编码成 wire 格式 label 序列（不含压缩指针）。
pub fn write_name(out: &mut Vec<u8>, name: &str) -> bool {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return true;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    true
}

/// 构造标准查询报文（单问题、RD=1、不带 EDNS）。
pub fn build_query(name: &str, qtype: u16) -> Option<Vec<u8>> {
    let mut msg = Vec::with_capacity(HEADER_LEN + name.len() + 4);
    msg.extend_from_slice(&rand_txid().to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00]); // flags: RD
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    if !write_name(&mut msg, name) {
        return None; // label 超长 / 空 label
    }
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(msg)
}

/// 从应答里提取地址记录与最小 TTL。
///
/// `want_v6 = Some(false)` 只取 A，`Some(true)` 只取 AAAA，`None` 两种都取
/// （fakeip 的后台解析需要同时知道域名有没有 v6，才能决定回不回 AAAA）。
pub fn extract_addresses(msg: &[u8], want_v6: Option<bool>) -> (Vec<IpAddr>, u32) {
    let mut addrs = Vec::new();
    let mut min_ttl = u32::MAX;
    if msg.len() < HEADER_LEN {
        return (addrs, 0);
    }
    if msg[3] & 0x0f != 0 {
        return (addrs, 0); // RCODE != NOERROR
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        let after = match skip_name(msg, pos) {
            Some(p) => p + 4,
            None => return (Vec::new(), 0),
        };
        if after > msg.len() {
            return (Vec::new(), 0);
        }
        pos = after;
    }
    for _ in 0..an {
        let after = match skip_name(msg, pos) {
            Some(p) => p,
            None => break,
        };
        if after + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[after], msg[after + 1]]);
        let class = u16::from_be_bytes([msg[after + 2], msg[after + 3]]);
        let ttl =
            u32::from_be_bytes([msg[after + 4], msg[after + 5], msg[after + 6], msg[after + 7]]);
        let rdlen = u16::from_be_bytes([msg[after + 8], msg[after + 9]]) as usize;
        let data = after + 10;
        let data_end = match data.checked_add(rdlen) {
            Some(e) if e <= msg.len() => e,
            _ => break,
        };
        if class == CLASS_IN {
            let take_v4 = rtype == TYPE_A && rdlen == 4 && !matches!(want_v6, Some(true));
            let take_v6 = rtype == TYPE_AAAA && rdlen == 16 && !matches!(want_v6, Some(false));
            if take_v4 {
                min_ttl = min_ttl.min(ttl);
                addrs.push(IpAddr::V4(Ipv4Addr::new(
                    msg[data],
                    msg[data + 1],
                    msg[data + 2],
                    msg[data + 3],
                )));
            } else if take_v6 {
                let mut o = [0u8; 16];
                o.copy_from_slice(&msg[data..data_end]);
                min_ttl = min_ttl.min(ttl);
                addrs.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
        }
        pos = data_end;
    }
    (addrs, if min_ttl == u32::MAX { 0 } else { min_ttl })
}

/// 应答头部：QR=1、**从查询复制 RD**、RA=1、RCODE 由参数给，四个计数占位。
///
/// 位布局容易写错，这里按 16 位 flags 逐个定位：
/// byte2 = QR(15) OPCODE(14-10) AA(9) TC(8) RD(7→ 实为 bit0 of byte2)
/// 即 RD 落在 byte2 的最低位；RA 落在 byte3 的最高位。把 RD 写成 0x80|… 到 byte3
/// 是经典错误（应答的 RD 会被 resolver 判成「不支持递归」，部分 App 直接放弃）。
fn build_header(txid: u16, rd: bool, rcode: u8) -> [u8; HEADER_LEN] {
    [
        (txid >> 8) as u8,
        (txid & 0xff) as u8,
        0x80 | if rd { 0x01 } else { 0x00 }, // QR=1, OPCODE=0, AA=0, TC=0, RD=复制
        0x80 | (rcode & 0x0f),               // RA=1, RCODE
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT（调用方覆盖）
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT：一律裁掉 EDNS OPT —— 回包越小越不可能撞上 MTU 黑洞
    ]
}

/// 用给定记录构造应答：原样复制问题段，RR name 用压缩指针 `0xC0 0x0C`。
///
/// `records` 的 rtype 必须与问题的 qtype 一致，否则视为构造错误返回 Err
/// （把 A 记录塞进 AAAA 应答是能把整个 App 解析搞坏的静默故障）。
pub fn build_response(query: &[u8], records: &[Record], ttl: u32) -> Result<Vec<u8>, String> {
    let q = parse_question(query).ok_or("无法解析 DNS 问题段")?;
    for r in records {
        if r.rtype() != q.qtype {
            return Err(format!("记录类型 {:?} 与查询类型 {} 不匹配", r, q.qtype));
        }
    }
    let txid = u16::from_be_bytes([query[0], query[1]]);
    let rd = query[2] & 0x01 != 0; // RD = flags 的 bit7（byte2 最低位）
    let mut out = Vec::with_capacity(q.end + records.len() * 26);
    let mut hdr = build_header(txid, rd, 0);
    hdr[6] = (records.len() >> 8) as u8;
    hdr[7] = (records.len() & 0xff) as u8;
    out.extend_from_slice(&hdr);
    // 问题段原样复制（起点即偏移 12，因此 0xC00C 指针必然有效）
    out.extend_from_slice(&query[HEADER_LEN..q.end]);
    for r in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&r.rtype().to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(r.rdata_len() as u16).to_be_bytes());
        r.write_rdata(&mut out);
    }
    Ok(out)
}

/// NODATA：RCODE=0、ANCOUNT=0（域名存在但该类型无记录）。
pub fn build_nodata(query: &[u8]) -> Result<Vec<u8>, String> {
    build_minimal(query, 0, 0)
}

/// NXDOMAIN：域名不存在。不带 SOA —— 最小化包长，避开 MTU 黑洞。
pub fn build_nxdomain(query: &[u8]) -> Result<Vec<u8>, String> {
    build_minimal(query, 3, 0)
}

/// SERVFAIL：让 App 的 resolver 知道「该重试或换服务器」。
///
/// 不能图省事回 NODATA：形状正确但内容为空的应答会被部分 App 判定为
/// 「域名不存在」并长期缓存负面结果，表现成「某些网站永远打不开」。
pub fn build_servfail(query: &[u8]) -> Result<Vec<u8>, String> {
    build_minimal(query, 2, 0)
}

fn build_minimal(query: &[u8], rcode: u8, ancount: u16) -> Result<Vec<u8>, String> {
    let q = parse_question(query).ok_or("无法解析 DNS 问题段")?;
    let txid = u16::from_be_bytes([query[0], query[1]]);
    let rd = query[2] & 0x01 != 0; // RD = flags 的 bit7（byte2 最低位）
    let mut out = Vec::with_capacity(q.end);
    let mut hdr = build_header(txid, rd, rcode);
    hdr[6] = (ancount >> 8) as u8;
    hdr[7] = (ancount & 0xff) as u8;
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&query[HEADER_LEN..q.end]);
    Ok(out)
}

/// 事务 ID：无 rand 依赖，用时钟 + 进程 id + 原子计数混出。
pub fn rand_txid() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0);
    c ^ nanos ^ (std::process::id() as u16)
}

/// 是否值得本地处理的查询类型（A / AAAA）。其余类型（PTR/SRV/SOA…）
/// 必须原样透传，本地瞎答会把「同网段发现」「VoIP SRV 定位」这类功能打掉。
pub fn is_address_query(qtype: u16) -> bool {
    matches!(qtype, TYPE_A | TYPE_AAAA)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(name: &str, qtype: u16, arcount: u16) -> Vec<u8> {
        let mut m = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        m.extend_from_slice(&arcount.to_be_bytes());
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m
    }

    #[test]
    fn parses_plain_question() {
        let q = parse_question(&query_bytes("Example.COM", TYPE_A, 0)).unwrap();
        assert_eq!(q.name, "example.com", "必须小写归一，缓存键与 fakeip 映射才稳定");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        // 12 头 + "\x07Example\x03COM\0"(13) + qtype(2) + qclass(2)
        assert_eq!(q.end, 12 + 13 + 4);
    }

    #[test]
    fn root_and_single_label_names() {
        // 根域查询：12 字节头 + [0](name) + qtype + qclass
        let root = vec![0u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        let q = parse_question(&root).unwrap();
        assert_eq!(q.name, "");

        let one = parse_question(&query_bytes("localhost", TYPE_AAAA, 0)).unwrap();
        assert_eq!(one.name, "localhost");
        assert_eq!(one.qtype, TYPE_AAAA);
    }

    #[test]
    fn refuses_multi_question_and_truncated() {
        let mut multi = query_bytes("a.test", TYPE_A, 0);
        multi[5] = 2;
        assert!(parse_question(&multi).is_none());
        assert!(parse_question(&[0, 1, 0]).is_none());
        let mut cut = query_bytes("a.test", TYPE_A, 0);
        cut.truncate(cut.len() - 2);
        assert!(parse_question(&cut).is_none());
    }

    #[test]
    fn read_name_follows_back_pointer() {
        // 偏移 12 处是真实 label "abc\0"（12..17）；偏移 17 处是指针 C0 0C 回指 12。
        // DNS 压缩指针只允许向后指（向前指必然构成环）。
        let mut msg: Vec<u8> = vec![0; 12];
        msg.extend_from_slice(&[3, b'a', b'b', b'c', 0]);
        assert_eq!(msg.len(), 17);
        msg.extend_from_slice(&[0xc0, 0x0c]);
        let (name, _) = read_name(&msg, 17).unwrap();
        assert_eq!(name, "abc");
    }

    #[test]
    fn forward_or_out_of_range_pointer_is_refused() {
        let mut msg: Vec<u8> = vec![0; 12];
        // 指针指向自己（12）—— 经典压缩环，必须失败而不是挂死
        msg.extend_from_slice(&[0xc0, 0x0c]);
        assert!(read_name(&msg, 12).is_none());

        let mut beyond: Vec<u8> = vec![0; 12];
        beyond.extend_from_slice(&[0xc0, 0xff]); // 超出报文长度
        assert!(read_name(&beyond, 12).is_none());
    }

    #[test]
    fn skip_name_handles_pointer_and_labels() {
        let mut msg: Vec<u8> = vec![0; 12];
        msg.extend_from_slice(&[3, b'f', b'o', b'o', 0, 0xc0, 0x04]);
        assert_eq!(skip_name(&msg, 12), Some(17));
        assert_eq!(skip_name(&msg, 17), Some(19));
        assert_eq!(skip_name(&msg, 100), None);
    }

    #[test]
    fn response_echoes_question_and_uses_pointer() {
        let q = query_bytes("img.example.com", TYPE_A, 1);
        let rec = vec![Record::A(Ipv4Addr::new(198, 18, 0, 7))];
        let resp = build_response(&q, &rec, 60).unwrap();
        assert_eq!(&resp[0..2], &q[0..2], "txid 必须回显");
        assert_eq!(resp[2] & 0x80, 0x80, "QR 必须置位");
        assert_eq!(&resp[4..6], &[0, 1]);
        assert_eq!(&resp[6..8], &[0, 1], "ANCOUNT");
        assert_eq!(&resp[10..12], &[0, 0], "ARCOUNT 裁成 0（EDNS 一律不带）");

        let qp = parse_question(&q).unwrap();
        assert_eq!(&resp[12..qp.end], &q[12..qp.end], "问题段必须逐字节复制");
        // RR 布局：NAME(2 指针) TYPE(2) CLASS(2) TTL(4) RDLEN(2) RDATA(4)
        let rr = qp.end;
        assert_eq!(&resp[rr..rr + 2], &[0xc0, 0x0c], "RR name 用指针");
        assert_eq!(&resp[rr + 2..rr + 4], &[0, 1], "TYPE=A");
        assert_eq!(&resp[rr + 4..rr + 6], &[0, 1], "CLASS=IN");
        assert_eq!(&resp[rr + 6..rr + 10], &[0, 0, 0, 60], "TTL");
        assert_eq!(&resp[rr + 10..rr + 12], &[0, 4], "RDLENGTH");
        assert_eq!(&resp[rr + 12..rr + 16], &[198, 18, 0, 7], "RDATA");
        assert_eq!(resp.len(), rr + 16, "应答长度必须刚好等于各字段之和");

        // 构造出的应答必须能被自己的解析器读回
        let (addrs, ttl) = extract_addresses(&resp, Some(false));
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7))]);
        assert_eq!(ttl, 60);
        // 名称仍应能从应答里解出（回写缓存时要用）
        assert_eq!(parse_question(&resp).unwrap().name, "img.example.com");
    }

    #[test]
    fn multiple_records_roundtrip() {
        let q = query_bytes("a.b.c", TYPE_AAAA, 0);
        let rec = vec![
            Record::AAAA(Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 7)),
            Record::AAAA(Ipv6Addr::new(0xfd53, 0, 0, 0, 0, 0, 0, 8)),
        ];
        let resp = build_response(&q, &rec, 300).unwrap();
        assert_eq!(&resp[6..8], &[0, 2]);
        let (addrs, ttl) = extract_addresses(&resp, Some(true));
        assert_eq!(addrs.len(), 2);
        assert_eq!(ttl, 300);
    }

    #[test]
    fn mismatched_record_type_is_an_error() {
        let q = query_bytes("a.test", TYPE_A, 0);
        let err = build_response(&q, &[Record::AAAA(Ipv6Addr::LOCALHOST)], 60).unwrap_err();
        assert!(err.contains("不匹配"), "{err}");
    }

    #[test]
    fn nodata_nxdomain_servfail_shapes() {
        let q = query_bytes("a.test", TYPE_AAAA, 0);
        let nd = build_nodata(&q).unwrap();
        assert_eq!(&nd[2..4], &[0x81, 0x80]);
        assert_eq!(&nd[6..8], &[0, 0]);
        assert_eq!(&nd[10..12], &[0, 0]);
        assert_eq!(nd.len(), q.len(), "NODATA 长度等于查询长度");

        assert_eq!(build_nxdomain(&q).unwrap()[3] & 0x0f, 3);
        assert_eq!(build_servfail(&q).unwrap()[3] & 0x0f, 2, "SERVFAIL=2");

        // RD 必须从查询复制（RD 是 flags 的 bit7 → byte2 的最低位）
        let mut q2 = query_bytes("a.test", TYPE_A, 0);
        q2[2] &= 0xfe; // 清掉 RD
        let r = build_nodata(&q2).unwrap();
        assert_eq!(r[2] & 0x80, 0x80, "QR 置位");
        assert_eq!(r[2] & 0x01, 0, "RD 被正确复制为 0");
        assert_eq!(r[3] & 0x80, 0x80, "RA 恒为 1");
        assert_eq!(build_nodata(&q).unwrap()[2] & 0x01, 1, "RD=1 的查询必须回 RD=1");
    }

    #[test]
    fn extract_addresses_type_filter_and_rcode() {
        let q = query_bytes("mix.test", TYPE_A, 0);
        let mixed = build_response(&q, &[Record::A(Ipv4Addr::new(1, 1, 1, 1))], 60).unwrap();
        assert_eq!(extract_addresses(&mixed, Some(true)).0.len(), 0, "只要 AAAA 就不该给 A");
        assert_eq!(extract_addresses(&mixed, Some(false)).0.len(), 1);
        assert_eq!(extract_addresses(&mixed, None).0.len(), 1);

        let mut bad = mixed.clone();
        bad[3] |= 3;
        assert!(extract_addresses(&bad, None).0.is_empty(), "非 NOERROR 必须无记录");
    }

    /// 真实上游应答里 A 与 AAAA 混在同一 ANCOUNT 是常见形态（带 CNAME 链也一样），
    /// 服务端族择优依赖这里能分别取对。
    #[test]
    fn extract_from_mixed_upstream_answer() {
        // qname 在 12，问题 A/mix.test；答案：CNAME(指针) + A + AAAA
        let mut msg: Vec<u8> = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, 0, 0, 0, 0];
        msg.extend_from_slice(&[3, b'm', b'i', b'x', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
        let qend = msg.len();
        // CNAME -> 0x0c
        msg.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 10, 0, 0]);
        // A
        msg.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 1, 0x88, 0x00, 0x04]);
        msg.extend_from_slice(&[93, 184, 216, 34]);
        // AAAA
        msg.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0, 0, 1, 0x2c, 0x00, 0x10]);
        for i in 0..16 {
            msg.push(i as u8);
        }
        assert!(qend < msg.len());
        let (v4, t4) = extract_addresses(&msg, Some(false));
        let (v6, t6) = extract_addresses(&msg, Some(true));
        assert_eq!(v4, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(t4, 392);
        assert_eq!(v6.len(), 1, "AAAA 也要取到");
        assert!(v6[0].is_ipv6());
        assert_eq!(t6, 300);
        assert_eq!(extract_addresses(&msg, None).0.len(), 2, "None = 两种都要");
    }

    #[test]
    fn extract_addresses_survives_garbage_without_panicking() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 11],
            vec![0u8; 12],
            vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 1, 0, 1,
                 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 255], // rdlen 越界
            vec![0, 1, 0x81, 0x80, 0, 1, 0xff, 0xff, 0, 0, 0, 0],
            vec![0, 1, 0x81, 0x80, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ];
        for bytes in cases {
            let _ = extract_addresses(&bytes, None);
            let _ = parse_question(&bytes);
            let _ = build_nodata(&bytes);
        }
    }

    #[test]
    fn build_query_shape_and_roundtrip() {
        let q = build_query("WWW.Example.COM", TYPE_A).unwrap();
        let parsed = parse_question(&q).unwrap();
        assert_eq!(parsed.name, "www.example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 0, "不带 EDNS");
        assert!(build_query(&"a".repeat(64), TYPE_A).is_none(), "label 超 63 必须拒绝");
    }

    #[test]
    fn txids_are_not_constant() {
        assert_ne!(rand_txid(), rand_txid());
    }

    #[test]
    fn response_stays_small_enough_for_udp() {
        // fakeip 应答即使 20 条记录也远小于 512：不会被 DNS/UDP 长度限制截断，
        // 也就不会在 MTU 黑洞链路上靠分片活着。
        let q = query_bytes("many.example.com", TYPE_A, 0);
        let rec: Vec<Record> = (0..20)
            .map(|i| Record::A(Ipv4Addr::new(198, 18, (i / 250) as u8, (i % 250) as u8)))
            .collect();
        let resp = build_response(&q, &rec, 60).unwrap();
        assert!(resp.len() < 400, "20 条记录应答 {}/20 = {} 字节，过大", rec.len(), resp.len());
    }

    #[test]
    fn is_address_query_only_for_a_and_aaaa() {
        assert!(is_address_query(TYPE_A));
        assert!(is_address_query(TYPE_AAAA));
        for other in [2u16, 5, 6, 12, 15, 16, 33, 255] {
            assert!(!is_address_query(other), "{other} 不该本地代答");
        }
    }

    #[test]
    fn record_of_preserves_family() {
        assert_eq!(record_of(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), Record::A(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(record_of(IpAddr::V6(Ipv6Addr::LOCALHOST)), Record::AAAA(Ipv6Addr::LOCALHOST));
    }
}
