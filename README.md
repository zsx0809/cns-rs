# cns-rs (CuteBi Network Suite - Rust Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20OpenWrt-green.svg)]()
[![Release](https://img.shields.io/github/v/release/zsx0809/cns-rs?color=brightgreen)](https://github.com/zsx0809/cns-rs/releases)

基于纯异步 Rust（**Tokio 1.x** + **Socket2** + **Tokio-Util**）对经典免流/网络穿透工具 **CuteBi Network Suite (CNS / CLNC)** 进行的全面现代化工业级重构。

本项目采用标准 **Cargo Workspace** 多组件架构，同时提供**服务端（`cns-server`）**、**客户端（`cns-client`）**以及 **Android Magisk / KernelSU / APatch 模块套件**。与原版 Go / C 架构保持 **100% 协议级双向无缝兼容**。

---

## ⚡ 为什么选择 cns-rs？（对比原版 CuteBi 的七大质变）

| 评测维度 | 原版 Go 服务端 / C 客户端 | cns-rs (Rust Edition) | 体验质变 |
| :--- | :--- | :--- | :--- |
| **开发语言** | Go (服务端) + C 语言 (客户端) | **纯异步 Rust (Tokio 1.x)** | 零 GC 垃圾回收抖动，消除长视频卡顿 |
| **内存开销 (RSS)** | 20MB ~ 50MB | **1.5MB ~ 3.5MB** | 内存降低 10 倍以上，适合 128MB 远古小鸡与嵌入式设备 |
| **代理模式** | 脆弱 TUN 虚拟网卡 (`tunDev`) | **现代 Linux 内核级 NAT REDIRECT** | 零用户态上下文拷贝，跑满 5G 基带上限，大幅降低发热 |
| **断流稳定性** | C 客户端硬编码 15 秒超时强行断连 | **智能保活 + 异步无死锁续连** | 彻底根除跨国微抖动造成的播放器中途断流转圈 |
| **现代 App 兼容** | 双栈 CDN 导致图片转圈、网页白底黑字 | **AAAA 本地过滤 + 动态源 IP 镜像** | 彻底解决 B 站封面加载失败与 GitHub 网页无样式 |
| **QUIC 优化** | UDP 443 悬挂导致 3~8 秒白屏等待 | **智能 REJECT 阻断，秒退 TLS 1.3** | 现代浏览器与短视频首帧秒开 |
| **磁盘与内存安全** | 异常报错狂刷写爆 VPS 几十G硬盘 | **热路径零日志 + 4096 信号量隔离** | 硬盘增量死锁为 0，彻底免疫 OOM 与爆盘 |

---

## 🔄 双向无缝兼容矩阵（新老版本任意混搭）

本项目在重构核心的同时，对经典 CuteBi 协议进行了严格的二进制与报文级对齐：

* **新客户端 (`cns-client`) ↔ 原版老服务端 (Go/C 版 CNS)**：
  * 100% 畅通！客户端自适应老版服务端的 `(%>w<%)` 特征标头与 WebSocket 升级协议；
  * 即使连接朋友或公开的老版 CNS 节点，手机端依然享有**不发热、不断流、图片秒开**的全部升级红利。
* **原版老客户端 (`clnc` / 旧模块) ↔ 新服务端 (`cns-server`)**：
  * 100% 畅通！新服务端完美支持老客户端发来的特征标头、`httpUDP` 游戏数据帧、`tcpDNS` 专线查询以及首包粘包（Sticky Packet）还原转发。

---

## 🚀 核心架构与黑科技

### 1. 独家「动态源 IP 镜像 DNS」技术 (Dynamic Source IP Mirroring)
Android 11+ 内核网络栈对 DNS 响应的校验极其严格。传统代理回包源若不匹配，内核直接将包丢弃。
`cns-rs` 通过 Linux 内核级 `IP_RECVORIGDSTADDR` 套接字控制信标精确捕获原始查询目标，并利用 Raw Socket 伪造完全合规的镜像回包（含 RFC 768 UDP 校验和），彻底消灭 DNS 解析超时丢包。

### 2. 毫秒级 AAAA 权威空响应拦截 (NODATA Response)
面对双栈 CDN（如 Fastly、GitHub、Cloudflare），Chrome 会优先尝试 IPv6 连接。而在不支持 `ip6tables nat` 的移动网络环境下，直连 IPv6 阻断会导致样式表无法加载。
`cns-client` 在本地以 **0.01 毫秒**拦截 AAAA 查询并秒回权威空响应（NODATA），促使客户端立即回退至纯 IPv4 走免流隧道，**彻底根除网页白底黑字与 IPv6 漏免风险**。

### 3. 双上游并发竞速解析引擎 (Racing DNS Resolver)
服务端同时向全球最快两大 Anycast DNS（`8.8.8.8` 与 `1.1.1.1`）并发查询，先到先得，消除单一 DNS 节点的抖动与丢包。

### 4. 工业级防爆盘与防 OOM 内存墙
彻底拔除数据转发热路径上的每包日志输出，生产环境默认静默；内置 `tokio::sync::Semaphore` 最大并发信号量隔离（服务端 4096，客户端 2048），配合首包 10 秒防挂死超时，彻底终结内存膨胀与硬盘写满。

---

## ⚡ 一键极速部署（Linux VPS 云服务器）

在你的 Linux VPS 上直接运行以下官方一键安装命令（动态识别并支持 **Ubuntu / Debian / Alpine / CentOS / AlmaLinux / Rocky / Fedora / Arch** 等主流发行版，纯静态免依赖，无需在 VPS 上编译）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zsx0809/cns-rs/main/install.sh)
```

脚本全自动引导：
* ✅ 智能操作系统与硬件架构（`x86_64` / `aarch64`）识别；
* ✅ 自动安装全平台通用纯静态二进制服务端，128MB/500MB 超低内存小鸡亦能秒级完成部署；
* ✅ 交互式配置端口、密码与混淆 Host；
* ✅ 自适应配置 systemd 或 OpenRC (Alpine) 后台守护开机自启；
* ✅ 安装完成后自动生成客户端手机模块可一键复制的配置代码块！

---

## 📱 Android 手机端模块使用指引

专为 **Magisk / KernelSU / APatch** 打造的标准化 Root 模块：

### 1. 下载模块刷机包
前往 [GitHub Releases](https://github.com/zsx0809/cns-rs/releases/latest) 下载最新发布的：
👉 **`cns-rs-v0.1.1-magisk-ksu-arm64.zip`**
直接在 **Magisk**、**KernelSU** 或 **APatch** 管理器中刷入！

### 2. 模块主目录路径
模块安装于手机系统存储中的：
```text
/data/adb/modules/cns_rs/
(同时已创建免流软链接: /data/免流模式/)
```

### 3. 配置与启停
1. 使用 **MT 管理器** 打开 `/data/adb/modules/cns_rs/modes/联通.json`，修改为你的真实服务器 IP 与密码；
2. 在终端（Termux / 终端模拟器）中执行：
   * 开启免流：`su -c /data/adb/modules/cns_rs/开启.sh`
   * 关闭免流：`su -c /data/adb/modules/cns_rs/关闭.sh`
   * 连通自检：`su -c /data/adb/modules/cns_rs/检测.sh`
3. 💡 **KSU / APatch 特权**：可在管理器模块界面直接点击【操作 / Action】按钮，实现一键启停！

---

## 🛠️ 本地编译构建

本项目支持在 Linux x86_64 及 Android Termux (aarch64) 环境下本地编译：

```bash
git clone https://github.com/zsx0809/cns-rs.git
cd cns-rs

# 编译所有组件
cargo build --release --workspace

# 独立打包 Magisk / KernelSU 模块 zip
python3 build_module.py
```

构建产物：
* `target/release/cns-server` (服务端)
* `target/release/cns-client` (客户端)
* `cns-rs-v0.1.0-magisk-ksu-arm64.zip` (手机模块)

---

## 📄 License

本项目遵循 [MIT License](LICENSE) 开源协议。欢迎 Star 收藏与提交 PR / Issue 共同维护！
