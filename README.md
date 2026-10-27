# cns-rs (CuteBi Network Suite - Rust Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20OpenWrt-green.svg)]()

基于现代纯异步 Rust（**Tokio 1.x** + **Socket2** + **Tokio-Util**）对经典免流/内网穿透项目 **CuteBi Network Suite (CNS / CLNC)** 进行的全面现代化重构。

本项目采用标准 **Cargo Workspace** 多组件架构，同时提供**服务端（`cns-server`）**与**客户端（`cns-client`）**，100% 协议级互相兼容，并向前兼容现存所有旧版客户端与服务端。

---

## 📦 架构组件

```text
cns-rs/
├── crates/
│   ├── cns-core/     // 【协议与密码核心库】SIMD 向量化加解密、httpUDP 零拷贝帧编解码、Socket2 内核调优
│   ├── cns-server/   // 【服务端 cns】高性能 TCP/UDP 隧道、DNS 专线、微聚合冲水队列 (1.5MB)
│   └── cns-client/   // 【客户端 clnc】通用 SOCKS5 入站、免流 HTTP 模板渲染、自适应智能保活 (1.4MB)
```

---

## ⚡ 为什么用 Rust 重构？（对比原版）

| 维度 | 原版 Go 服务端 / C 客户端 | cns-rs (Rust Edition) | 优势 |
| :--- | :--- | :--- | :--- |
| **垃圾回收 (GC)** | 服务端 Go STW 垃圾回收抖动，UDP 高频切片容易逃逸卡顿 | **纯异步 Rust，零 GC (Zero-GC)** | 延迟曲线绝对平滑，海外 4K 直播不再频繁卡顿转圈 |
| **客户端稳定性** | 原版 C 客户端硬编码 15 秒超时自杀重连，频繁断流 | **异步可控保活 + 智能静默续连** | 彻底根除因跨国网络微抖动造成的断流转圈 |
| **客户端易用性** | 仅支持 Linux 复杂的 iptables/TProxy，配置语法反人类 | **原生集成标准 SOCKS5 入站** | 手机 Wi-Fi、电脑浏览器、Telegram、Clash 上游即插即用 |
| **内存常驻 (RSS)** | 20MB ~ 40MB | **1.5MB ~ 4MB** | 极小资源占用，适合 128MB 嵌入式设备与小鸡 |
| **二进制体积** | 服务端 6.4MB + 客户端 1.6MB | `cns-server` **1.5MB** + `cns-client` **1.4MB** | LTO + Strip 极限压缩，单文件无运行时依赖 |
| **数据泵效率** | 手工多层 copy / 锁竞争 | **64位无锁原位（In-place）批量异或 + 零拷贝 Buffer** | CPU 消耗降至物理下限，轻松跑满单核千兆 |

---

## 🛠️ 编译与运行

### 1. 构建全套 Workspace
```bash
git clone https://github.com/your-username/cns-rs.git
cd cns-rs
cargo build --release --workspace
```
构建产物直接位于：
- `target/release/cns-server` (服务端)
- `target/release/cns-client` (客户端)

---

## 🚀 快速启动指南

### 🖥️ 一、服务端 (`cns-server`)

编辑 `config.json`（支持与原版 CNS 配置文件完全互通）：
```json
{
  "listen_addr": [":1254"],
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "encrypt_password": "666",
  "tcp_timeout": 300,
  "udp_timeout": 30,
  "enable_dns_tcp_over_udp": true,
  "enable_tfo": true
}
```

启动服务端：
```bash
./target/release/cns-server -c config.json
```

#### Systemd 后台服务配置（Linux）
`/etc/systemd/system/cns-server.service`:
```ini
[Unit]
Description=CuteBi Network Suite Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cns-server -c /etc/cns/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

---

### 📱 二、客户端 (`cns-client`)

编辑 `client.json`：
```json
{
  "socks5_listen": "127.0.0.1:1080",
  "cns_server": "YOUR_SERVER_IP:1254",
  "cns_password": "666",
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "header_host": "mclient.alipay.com",
  "enable_tfo": true,
  "timeout_seconds": 60
}
```

启动客户端：
```bash
./target/release/cns-client -c client.json
```

启动后，客户端会在本地开启一个标准 SOCKS5 代理（`127.0.0.1:1080`）：
- **电脑/手机浏览器：** 安装 SwitchyOmega 或配置 Wi-Fi 代理指向 `127.0.0.1:1080`，所有流量自动被包装成免流伪装头穿透！
- **作为上游代理：** 可以在 Clash / Sing-box / V2Ray 的 `outbounds` 中直接将 `cns-client` 作为 `socks5` 类型的出站节点，轻松配合规则分流去广告。

---

## 🧪 自动化测试验证

全链路单元测试与集成测试（包含客户端到服务端全链路闭环）：
```bash
cargo test --workspace
```

---

## 📄 License

开源遵循 [MIT License](LICENSE)。
