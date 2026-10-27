# cns-rs (CuteBi Network Suite - Rust Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20OpenWrt-green.svg)]()

基于现代纯异步 Rust（**Tokio 1.x** + **Socket2** + **Tokio-Util**）对经典免流/内网穿透项目 **CuteBi Network Suite (CNS / CLNC)** 进行的全面现代化重构。

本项目采用标准 **Cargo Workspace** 多组件架构，同时提供**服务端（`cns-server`）**、**客户端（`cns-client`）**以及 **Android 免流模块套件**，100% 协议级互相兼容，并向前兼容现存所有旧版客户端与服务端。

---

## ⚡ 一键极速安装（小白/新手推荐）

在你的 Linux VPS 云服务器（支持 Debian / Ubuntu / CentOS / Alpine / Rocky 等）上直接复制运行以下一行命令：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zsx0809/cns-rs/main/install.sh)
```

脚本将全自动引导你完成：
* ✅ 智能检测系统架构并安装
* ✅ 交互式设定监听端口、免流密码、伪装 Header 字段
* ✅ 自动配置 systemd 守护进程与开机自启
* ✅ 安装完成后自动生成客户端（Android 模块）可一键复制的配置代码块！

---

## 📦 架构组件

```text
cns-rs/
├── install.sh         // 【一键安装与管理脚本】全自动部署与运维菜单
├── android-module/    // 【Android 免流套件】现代 NAT REDIRECT 透明代理，告别崩溃 TUN
│   ├── 开启.sh
│   ├── 关闭.sh
│   ├── 检测.sh
│   └── Core/cns-client (预编译 ARM64 二进制)
├── crates/
│   ├── cns-core/      // 【核心库】SIMD 向量化加解密、httpUDP 帧零拷贝编解码、Socket2 调优
│   ├── cns-server/    // 【服务端】高性能 TCP/UDP 隧道、DNS 专线、微聚合冲水队列 (1.5MB)
│   └── cns-client/    // 【客户端】通用 SOCKS5 入站、Linux 透明代理、免流 HTTP 模板渲染 (1.4MB)
```

---

## ⚡ 为什么用 Rust 重构？（性能与稳定性对比）

| 维度 | 原版 Go 服务端 / C 客户端 | cns-rs (Rust Edition) | 优势 |
| :--- | :--- | :--- | :--- |
| **垃圾回收 (GC)** | 服务端 Go STW 垃圾回收抖动，高频小包易逃逸卡顿 | **纯异步 Rust，零 GC (Zero-GC)** | 延迟曲线绝对平滑，海外 4K 直播不再卡顿转圈 |
| **客户端稳定性** | 原版 C 客户端硬编码 15 秒超时自杀断连 | **异步可控保活 + 智能静默续连** | 彻底根除因跨国网络微抖动造成的播放器断流重连 |
| **Android 体验** | 脆弱易崩溃的 `tunDev` 虚拟网卡，易造成分片丢包 | **现代 Linux 内核级 NAT REDIRECT 透明代理** | 零用户态上下文拷贝，跑满基带上限，大幅降低发热 |
| **易用性与接入** | 仅支持 Linux 复杂的 iptables，配置晦涩 | **原生集成标准 SOCKS5 + TProxy 透明代理** | 手机 Wi-Fi、电脑浏览器、Telegram、Clash 出站即插即用 |
| **内存常驻 (RSS)** | 20MB ~ 40MB | **1.5MB ~ 4MB** | 极小资源占用，适合 128MB 嵌入式设备与小鸡 |
| **二进制体积** | 服务端 6.4MB + 客户端 1.6MB | `cns-server` **1.5MB** + `cns-client` **1.4MB** | LTO + Strip 极限压缩，单文件无外部动态库依赖 |

---

## 📱 Android 手机端免流模块使用方法

直接将仓库内的 `android-module` 文件夹放进手机（例如 `/data/免流模式`）：

1. **修改节点信息：** 在 `android-module/modes/联通.json` 中填入你的服务器 IP、端口和密码。
2. **选择当前模式：** 在 `android-module/config.ini` 中确认 `modeName='联通'`。
3. **一键启停：**
   * 启动免流：`./开启.sh`
   * 关闭免流：`./关闭.sh`
   * 查看状态：`./检测.sh`

---

## 🛠️ 从源码手动构建

需要标准 Rust 工具链（Rust 1.75+）：

```bash
git clone https://github.com/zsx0809/cns-rs.git
cd cns-rs
cargo build --release --workspace
```
构建产物直接位于：
* `target/release/cns-server` (服务端)
* `target/release/cns-client` (客户端)

---

## 🧪 自动化测试验证

全链路单元测试与客户端-服务端集成测试闭环：
```bash
cargo test --workspace
```

---

## 📄 License

开源遵循 [MIT License](LICENSE)。欢迎 Star 与提交 PR 共同维护！
