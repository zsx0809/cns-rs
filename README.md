# cns-rs (CuteBi Network Suite - Rust Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20OpenWrt-green.svg)]()

基于现代纯异步 Rust（**Tokio 1.x** + **Socket2** + **Tokio-Util**）对经典免流/网络穿透工具 **CuteBi Network Suite (CNS / CLNC)** 进行的工业级现代化重构。

本项目采用标准 **Cargo Workspace** 多组件架构，同时提供**服务端（`cns-server`）**、**客户端（`cns-client`）**以及 **Android 免流透明代理模块套件**，100% 协议级双向兼容，向前兼容所有旧版 CNS/CLNC 客户端与服务端。

---

## ⚡ 核心现代化特性

* **🚀 纯异步事件驱动 Reactor**：基于 Tokio 非阻塞 epoll/kqueue 架构，告别老版 C 语言多进程 `fork()` 的高昂内存开销，极度轻量省电。
* **🛡️ 动态源 IP 镜像智能 DNS (Dynamic Source IP Mirroring)**：
  - 通过 Linux 内核 `IP_RECVORIGDSTADDR` 套接字控制信标，精准捕获 Android 系统发往运营商 DNS（如 `120.80.80.80` / `221.5.88.88`）的原始请求。
  - 自动通过 Raw Socket 构造携带 RFC 768 校验和的动态回包，彻底消灭 Android 协议栈因“源 IP 不匹配”而丢弃 DNS 响应导致的域名超时、图片无法加载等疑难杂症。
* **⚡ QUIC 智能拦截与秒级回退**：自动阻断 UDP 443（QUIC），促使 B 站、Chrome 等现代应用秒级回退至基于 TCP 的 TLS 1.3 / HTTP/2，消除封面图片与短视频首帧的白屏等待。
* **🔒 工业级防爆盘与防 OOM 内存墙**：
  - **零热路径日志**：剔除 TCP/UDP 数据泵热路径上的每包日志输出，生产环境默认静默，彻底解决老版本因每包打印日志写满 VPS 磁盘的问题。
  - **最大并发信号量保护**：内置 `tokio::sync::Semaphore`（服务端 4096，客户端 2048），防止连接风暴引发无界内存扩张。
  - **首包握手防挂死**：对建立连接后的首个 HTTP 握手及外部回源设置 10 秒超时强行截断，免疫 Slowloris 悬挂半开连接攻击。
* **🔄 原生支持应用层长连接复用**：无缝透明透传 HTTP/1.1 Keep-Alive 与 HTTP/2 多路复用，兼顾运营商免流计费风控与高吞吐网络体验。
* **🩺 内置全协议健康自检引擎**：一键自动化测试 UDP 53 DNS 解析、TCP 80 HTTP 明文、TLS 443 HTTPS 握手及 UDP 隧道连通性。

---

## ⚡ 一键极速安装（服务端 VPS）

在你的 Linux VPS 云服务器（支持 Debian / Ubuntu / CentOS / Alpine / Rocky 等）上直接复制运行以下一行命令：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zsx0809/cns-rs/main/install.sh)
```

脚本将全自动引导你完成：
* ✅ 智能检测系统架构并安装
* ✅ 交互式设定监听端口、免流密码、伪装 Header 字段
* ✅ 自动配置 systemd 守护进程、开机自启、日志速率与磁盘限额保护
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
│   └── Core/
│       ├── cns-client (预编译 ARM64 极速二进制)
│       └── cns_rules.sh (现代化 iptables 规则与健康检测脚本)
├── crates/
│   ├── cns-core/      // 【核心库】SIMD 向量化加解密、httpUDP 帧零拷贝编解码、Socket2 调优
│   ├── cns-server/    // 【服务端】高性能 TCP/UDP 隧道、DNS 专线、微聚合冲水队列 (1.5MB)
│   └── cns-client/    // 【客户端】通用 SOCKS5 入站、Linux 透明代理、DNS 动态镜像 (1.4MB)
```

---

## ⚡ 为什么用 Rust 重构？（性能与稳定性对比）

| 维度 | 原版 Go 服务端 / C 客户端 | cns-rs (Rust Edition) | 优势 |
| :--- | :--- | :--- | :--- |
| **垃圾回收 (GC)** | 服务端 Go STW 垃圾回收抖动，高频小包易逃逸卡顿 | **纯异步 Rust，零 GC (Zero-GC)** | 延迟曲线绝对平滑，海外 4K 直播不再卡顿转圈 |
| **DNS 与图片加载** | 传统硬编码回包源 IP，Android 频繁丢包超时 | **内核 IP_RECVORIGDSTADDR 智能动态镜像** | 彻底消灭 B 站图片与现代应用无法加载的问题 |
| **客户端稳定性** | 原版 C 客户端硬编码 15 秒超时自杀断连 | **异步可控保活 + 智能静默续连** | 彻底根除因跨国网络微抖动造成的播放器断流重连 |
| **Android 体验** | 脆弱易崩溃的 `tunDev` 虚拟网卡，易造成分片丢包 | **现代 Linux 内核级 NAT REDIRECT 透明代理** | 零用户态上下文拷贝，跑满基带上限，大幅降低发热 |
| **磁盘与内存安全** | 异常报错疯狂刷屏，长时间运行写爆 VPS 硬盘 | **热路径零日志 + 信号量连接硬隔离 (Semaphore)** | 内存严格锁死在几 MB，VPS 磁盘增量死锁在 0 |
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
   * 连通性自检：`./检测.sh`

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
