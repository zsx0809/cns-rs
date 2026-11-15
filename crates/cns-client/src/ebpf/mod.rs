use std::fs::File;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use tracing::{error, info};

pub static CNS_BPF_ELF: &[u8] = include_bytes!("../../bpf/cns_sockops.o");

const SYS_BPF: libc::c_long = 280;

// BPF syscall commands
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_int = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_MAP_DELETE_ELEM: libc::c_int = 3;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_PROG_ATTACH: libc::c_int = 8;
const BPF_PROG_DETACH: libc::c_int = 9;

// BPF types
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;

const BPF_PROG_TYPE_SOCK_OPS: u32 = 13;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;

const BPF_CGROUP_INET4_CONNECT: u32 = 8;
const BPF_CGROUP_INET6_CONNECT: u32 = 11;
const BPF_CGROUP_SOCK_OPS: u32 = 3;

#[repr(C)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
struct BpfAttrMapOp {
    map_fd: u32,
    pad0: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

#[repr(C)]
struct BpfAttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct BpfAttrAttach {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct OrigDstVal {
    family: u16,
    port: u16, // network order
    ip_raw: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct ClientTupleKey {
    family: u16,
    port: u16, // network order
    ip_raw: [u8; 16],
}

/// eBPF 透明代理生命周期管理器
pub struct EbpfManager {
    cgroup_fd: RawFd,
    prog_c4: RawFd,
    prog_c6: RawFd,
    prog_so: RawFd,
    cfg_map_fd: RawFd,
    cookie_dst_map_fd: RawFd,
    tuple_dst_map_fd: RawFd,
}

impl EbpfManager {
    /// 加载 eBPF 模块并 attach 到指定 cgroup
    pub fn load_and_attach(
        cgroup_path: &Path,
        proxy_port: u16,
        proxy_gid: u32,
    ) -> io::Result<Self> {
        let elf = CNS_BPF_ELF;
        let cgroup_file = File::open(cgroup_path)?;
        let cgroup_fd = cgroup_file.as_raw_fd();

        // 1. 创建 BPF Maps
        let cfg_map_fd = Self::create_map(BPF_MAP_TYPE_ARRAY, 4, 4, 4, "cns_cfg")?;
        let cookie_dst_map_fd =
            Self::create_map(BPF_MAP_TYPE_LRU_HASH, 8, 20, 65536, "cookie_dst")?;
        let tuple_dst_map_fd =
            Self::create_map(BPF_MAP_TYPE_LRU_HASH, 20, 20, 65536, "tuple_dst")?;

        // 写入初始配置
        let k_port: u32 = 0;
        let v_port: u32 = proxy_port as u32;
        Self::map_update(cfg_map_fd, &k_port, &v_port)?;

        let k_gid: u32 = 1;
        let v_gid: u32 = proxy_gid;
        Self::map_update(cfg_map_fd, &k_gid, &v_gid)?;

        // 2. 解析 ELF、重定位并加载各程序
        let mut map_table = std::collections::HashMap::new();
        map_table.insert("cns_config_map".to_string(), cfg_map_fd);
        map_table.insert("cookie_dst_map".to_string(), cookie_dst_map_fd);
        map_table.insert("tuple_dst_map".to_string(), tuple_dst_map_fd);

        let prog_c4 = match Self::load_elf_prog(
            elf,
            "cgroup/connect4",
            ".relcgroup/connect4",
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            BPF_CGROUP_INET4_CONNECT,
            &map_table,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                Self::cleanup_fds(&[cfg_map_fd, cookie_dst_map_fd, tuple_dst_map_fd]);
                return Err(e);
            }
        };

        let prog_c6 = match Self::load_elf_prog(
            elf,
            "cgroup/connect6",
            ".relcgroup/connect6",
            BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
            BPF_CGROUP_INET6_CONNECT,
            &map_table,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                Self::cleanup_fds(&[cfg_map_fd, cookie_dst_map_fd, tuple_dst_map_fd, prog_c4]);
                return Err(e);
            }
        };

        let prog_so = match Self::load_elf_prog(
            elf,
            "sockops",
            ".relsockops",
            BPF_PROG_TYPE_SOCK_OPS,
            BPF_CGROUP_SOCK_OPS,
            &map_table,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                Self::cleanup_fds(&[
                    cfg_map_fd,
                    cookie_dst_map_fd,
                    tuple_dst_map_fd,
                    prog_c4,
                    prog_c6,
                ]);
                return Err(e);
            }
        };

        // 3. Attach 到 cgroup
        if let Err(e) = Self::attach_prog(cgroup_fd, prog_c4, BPF_CGROUP_INET4_CONNECT) {
            Self::cleanup_fds(&[
                cfg_map_fd,
                cookie_dst_map_fd,
                tuple_dst_map_fd,
                prog_c4,
                prog_c6,
                prog_so,
            ]);
            return Err(e);
        }

        if let Err(e) = Self::attach_prog(cgroup_fd, prog_c6, BPF_CGROUP_INET6_CONNECT) {
            let _ = Self::detach_prog(cgroup_fd, prog_c4, BPF_CGROUP_INET4_CONNECT);
            Self::cleanup_fds(&[
                cfg_map_fd,
                cookie_dst_map_fd,
                tuple_dst_map_fd,
                prog_c4,
                prog_c6,
                prog_so,
            ]);
            return Err(e);
        }

        if let Err(e) = Self::attach_prog(cgroup_fd, prog_so, BPF_CGROUP_SOCK_OPS) {
            let _ = Self::detach_prog(cgroup_fd, prog_c4, BPF_CGROUP_INET4_CONNECT);
            let _ = Self::detach_prog(cgroup_fd, prog_c6, BPF_CGROUP_INET6_CONNECT);
            Self::cleanup_fds(&[
                cfg_map_fd,
                cookie_dst_map_fd,
                tuple_dst_map_fd,
                prog_c4,
                prog_c6,
                prog_so,
            ]);
            return Err(e);
        }

        // 保持 cgroup_file 打开
        std::mem::forget(cgroup_file);

        info!(
            "eBPF transparent proxy attached to {:?} (proxy_port={proxy_port}, gid={proxy_gid})",
            cgroup_path
        );

        Ok(Self {
            cgroup_fd,
            prog_c4,
            prog_c6,
            prog_so,
            cfg_map_fd,
            cookie_dst_map_fd,
            tuple_dst_map_fd,
        })
    }

    /// 根据客户端 peer_addr 查出原始目的地址
    pub fn lookup_orig_dst(&self, peer_addr: SocketAddr) -> io::Result<SocketAddr> {
        let mut key = ClientTupleKey::default();
        key.port = peer_addr.port().to_be();
        match peer_addr {
            SocketAddr::V4(v4) => {
                key.family = 2; // AF_INET
                let oct = v4.ip().octets();
                key.ip_raw[0..4].copy_from_slice(&oct);
            }
            SocketAddr::V6(v6) => {
                key.family = 10; // AF_INET6
                let oct = v6.ip().octets();
                key.ip_raw.copy_from_slice(&oct);
            }
        }

        let mut val = OrigDstVal::default();
        let attr = BpfAttrMapOp {
            map_fd: self.tuple_dst_map_fd as u32,
            pad0: 0,
            key: &key as *const _ as u64,
            value_or_next_key: &mut val as *mut _ as u64,
            flags: 0,
        };

        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_LOOKUP_ELEM,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapOp>(),
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // 查到之后可主动删除避免 LRU 堆积
        let _ = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_DELETE_ELEM,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapOp>(),
            )
        };

        let port = u16::from_be(val.port);
        match val.family {
            2 => {
                let mut oct = [0u8; 4];
                oct.copy_from_slice(&val.ip_raw[0..4]);
                Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(oct), port)))
            }
            10 => {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&val.ip_raw[0..16]);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(oct),
                    port,
                    0,
                    0,
                )))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid addr family from ebpf: {other}"),
            )),
        }
    }

    fn create_map(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        name: &str,
    ) -> io::Result<RawFd> {
        let mut attr: BpfAttrMapCreate = unsafe { std::mem::zeroed() };
        attr.map_type = map_type;
        attr.key_size = key_size;
        attr.value_size = value_size;
        attr.max_entries = max_entries;
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(15);
        attr.map_name[..copy_len].copy_from_slice(&bytes[..copy_len]);

        let fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_CREATE,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapCreate>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }

    fn map_update<K, V>(map_fd: RawFd, key: &K, val: &V) -> io::Result<()> {
        let attr = BpfAttrMapOp {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key as *const _ as u64,
            value_or_next_key: val as *const _ as u64,
            flags: 0,
        };
        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_MAP_UPDATE_ELEM,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrMapOp>(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn load_elf_prog(
        elf: &[u8],
        sec_name: &str,
        rel_name: &str,
        prog_type: u32,
        attach_type: u32,
        map_table: &std::collections::HashMap<String, RawFd>,
    ) -> io::Result<RawFd> {
        // 解析 64-bit ELF Header
        if elf.len() < 64 || &elf[0..4] != b"\x7fELF" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ELF"));
        }
        let e_shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap()) as usize;
        let e_shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap()) as usize;
        let e_shstrndx = u16::from_le_bytes(elf[62..64].try_into().unwrap()) as usize;

        struct Shdr {
            name_off: usize,
            offset: usize,
            size: usize,
            link: usize,
            name: String,
        }

        let mut shdrs = Vec::with_capacity(e_shnum);
        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            let name_off = u32::from_le_bytes(elf[off..off + 4].try_into().unwrap()) as usize;
            let offset = u64::from_le_bytes(elf[off + 24..off + 32].try_into().unwrap()) as usize;
            let size = u64::from_le_bytes(elf[off + 32..off + 40].try_into().unwrap()) as usize;
            let link = u32::from_le_bytes(elf[off + 40..off + 44].try_into().unwrap()) as usize;
            shdrs.push(Shdr {
                name_off,
                offset,
                size,
                link,
                name: String::new(),
            });
        }

        let strtab_off = shdrs[e_shstrndx].offset;
        for s in &mut shdrs {
            let start = strtab_off + s.name_off;
            let mut end = start;
            while end < elf.len() && elf[end] != 0 {
                end += 1;
            }
            s.name = String::from_utf8_lossy(&elf[start..end]).to_string();
        }

        let sec_idx = shdrs
            .iter()
            .position(|s| s.name == sec_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("section {sec_name} not found"),
                )
            })?;
        let rel_idx = shdrs
            .iter()
            .position(|s| s.name == rel_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("section {rel_name} not found"),
                )
            })?;
        let symtab_idx = shdrs
            .iter()
            .position(|s| s.name == ".symtab")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, ".symtab not found"))?;

        let symtab_sh = &shdrs[symtab_idx];
        let sym_strtab_off = shdrs[symtab_sh.link].offset;
        let mut symbols = Vec::new();
        let mut off = symtab_sh.offset;
        let symtab_end = symtab_sh.offset + symtab_sh.size;
        while off + 24 <= symtab_end {
            let st_name = u32::from_le_bytes(elf[off..off + 4].try_into().unwrap()) as usize;
            let start = sym_strtab_off + st_name;
            let mut end = start;
            while end < elf.len() && elf[end] != 0 {
                end += 1;
            }
            symbols.push(String::from_utf8_lossy(&elf[start..end]).to_string());
            off += 24;
        }

        // 提取指令并做重定位
        let sec_sh = &shdrs[sec_idx];
        let mut code = elf[sec_sh.offset..sec_sh.offset + sec_sh.size].to_vec();

        let rel_sh = &shdrs[rel_idx];
        let mut r_off = rel_sh.offset;
        let rel_end = rel_sh.offset + rel_sh.size;
        while r_off + 16 <= rel_end {
            let r_offset = u64::from_le_bytes(elf[r_off..r_off + 8].try_into().unwrap()) as usize;
            let r_info = u64::from_le_bytes(elf[r_off + 8..r_off + 16].try_into().unwrap());
            let r_sym = (r_info >> 32) as usize;
            let sym_name = &symbols[r_sym];

            let map_fd = map_table.get(sym_name).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("map symbol {sym_name} not found in map_table"),
                )
            })?;

            let dst_reg = code[r_offset + 1] & 0x0F;
            code[r_offset + 1] = dst_reg | (1 << 4); // BPF_PSEUDO_MAP_FD
            let fd_bytes = (*map_fd as i32).to_le_bytes();
            code[r_offset + 4..r_offset + 8].copy_from_slice(&fd_bytes);

            r_off += 16;
        }

        let mut log_buf = vec![0u8; 65536];
        let license = b"GPL\0";

        let mut attr: BpfAttrProgLoad = unsafe { std::mem::zeroed() };
        attr.prog_type = prog_type;
        attr.insn_cnt = (code.len() / 8) as u32;
        attr.insns = code.as_ptr() as u64;
        attr.license = license.as_ptr() as u64;
        attr.log_level = 1;
        attr.log_size = log_buf.len() as u32;
        attr.log_buf = log_buf.as_mut_ptr() as u64;
        attr.expected_attach_type = attach_type;

        let name_bytes = sec_name.replace('/', "_").into_bytes();
        let copy_len = name_bytes.len().min(15);
        attr.prog_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let fd = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_PROG_LOAD,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrProgLoad>(),
            )
        };

        if fd < 0 {
            let log = String::from_utf8_lossy(&log_buf);
            error!("BPF load {sec_name} failed verifier log:\n{log}");
            return Err(io::Error::last_os_error());
        }

        Ok(fd as RawFd)
    }

    fn attach_prog(target_fd: RawFd, prog_fd: RawFd, attach_type: u32) -> io::Result<()> {
        let attr = BpfAttrAttach {
            target_fd: target_fd as u32,
            attach_bpf_fd: prog_fd as u32,
            attach_type,
            attach_flags: 0,
        };
        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_PROG_ATTACH,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrAttach>(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn detach_prog(target_fd: RawFd, prog_fd: RawFd, attach_type: u32) -> io::Result<()> {
        let attr = BpfAttrAttach {
            target_fd: target_fd as u32,
            attach_bpf_fd: prog_fd as u32,
            attach_type,
            attach_flags: 0,
        };
        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_PROG_DETACH,
                &attr as *const _ as *const libc::c_void,
                std::mem::size_of::<BpfAttrAttach>(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn cleanup_fds(fds: &[RawFd]) {
        for &fd in fds {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        info!("detaching eBPF programs from cgroup...");
        let _ = Self::detach_prog(self.cgroup_fd, self.prog_c4, BPF_CGROUP_INET4_CONNECT);
        let _ = Self::detach_prog(self.cgroup_fd, self.prog_c6, BPF_CGROUP_INET6_CONNECT);
        let _ = Self::detach_prog(self.cgroup_fd, self.prog_so, BPF_CGROUP_SOCK_OPS);

        Self::cleanup_fds(&[
            self.cgroup_fd,
            self.prog_c4,
            self.prog_c6,
            self.prog_so,
            self.cfg_map_fd,
            self.cookie_dst_map_fd,
            self.tuple_dst_map_fd,
        ]);
        info!("eBPF programs detached and fds cleaned up");
    }
}
