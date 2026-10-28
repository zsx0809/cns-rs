# cns-rs (CuteBi Network Suite - Rust Edition)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/Server-Linux%20(musl%20static)-green)]()
[![Platform](https://img.shields.io/badge/Client-Android%20arm64%20(bionic)-blue)]()
[![Release](https://img.shields.io/github/v/release/zsx0809/cns-rs?color=brightgreen)](https://github.com/zsx0809/cns-rs/releases)

基于纯异步 Rust（**Tokio 1.x** + **Socket2** + **Tokio-Util**）对经典免流/网络穿透工具 **CuteBi Network Suite (CNS / CLNC)** 的重构。

采用标准 **Cargo Workspace** 三组件架构：**服务端 `cns-server`**、**客户端 `cns-client`**、**Android Magisk / KernelSU / APatch 模块**。与原版 Go/C 保持**协议级双向兼容**（伪装头格式、`(%>w<%)` 特征串、`httpUDP` 帧、`tcpDNS` 报文、粘包与密钥流游标语义全部逐字节对齐）。

> **免流原理说明**：CNS 类工具的免流本质是**用合法免流域名的 HTTP 伪装头替换真实目标地址**，隧道里所有 TCP/UDP/DNS 会话都必须携带这个请求头。`cns-rs` 不做任何"绕过计费系统"的事，它只是一个协议实现与性能工程；能否免流取决于你的运营商规则。**请仅在你拥有合法使用权的SIM与自建服务端上使用。**

---

## ⚡ 与原版 Go/C 实现的差异（可验证部分）

| 维度 | 原版 Go 服务端 / C 客户端 | cns-rs | 依据 |
| :--- | :--- | :--- | :--- |
| 运行模型 | Go GC + 每连接 goroutine | Tokio 单线程调度、无 GC 抖动 | 语言层事实 |
| 转发热路径 | 每包一次日志/拷贝 | 原位异或 + 32KB 缓冲池复用（`BufferPool`） | `cns-core::transport::pump` |
| 代理入口 | TUN 虚拟网卡（用户态拷贝） | **内核 NAT REDIRECT / TPROXY**，TUN 已移除 | 见「关于 TUN」 |
| DNS 隧道 | 每个查询新建一条 TCP 连接并完整握手 | **隧道复用 + 本地缓存**，一条连接跑并发查询 | `cns-client::outbound::mux` |
| DNS 上游 | 由客户端随意指定 | 服务端配置为权威 + 客户端可选沿用 App 原始目标 | `dns_mode: orig\|fixed` |
| 半关闭 | `try_join!`：单向 EOF 掐断另一向 | `join!` + 显式 `shutdown`，SSH/HTTPS banner 不丢 | `pump.rs` 有回归测试 |
| 并发保护 | 无（原版靠系统 fd 上限） | 全局信号量 + 单 IP 并发上限 + 排水式优雅停机 | `cns-server::serve` |
| 监听地址 | 只绑一个族 | `[::]:port` 默认**双栈**（v4-mapped 一并接受） | 回归测试 `dualstack_listener_accepts_ipv4_clients` |
| 坏帧处理 | 解码失败原地不动 → 会话活锁 | 解码失败即终止会话并计数 | `tunnel::udp` 回归测试 |
| 目标滥用 | 服务端可对任意内网地址回源（SSRF 跳板） | **默认拒绝私网/环回/链路本地/云元数据**，需显式放行 | `config::is_restricted_ip` |

关于**内存与吞吐**：本仓库不再写"1.5MB 微内核""降低 10 倍"这类无法复核的数字。想验证请用 `bash scripts/bench.sh` —— 它跑单向吞吐、并发建连、DNS 延迟分位、RSS 与 fd 数，方法学细节写在脚本头部注释里。

一次实测输出（aarch64 chroot / 回环 / `BENCH_DURATION=5 CONCURRENCY=200 ROUNDS=40`，用于同机跨版本对比，**不是**对外的性能承诺）：

```
1/4 吞吐    下载经隧道 9679.9 Mbit/s   上传经隧道 9579.7 Mbit/s
2/4 建连    成功 200 / 失败 0   用时 0.18s   1088 会话/s
3/4 DNS     AAAA 本地NODATA  p50 0.11 ms  p90 0.44 ms
            A 首次(带隧道)    p50 0.24 ms  p90 0.39 ms
            A 缓存命中        p50 0.21 ms  p90 0.25 ms
4/4 RSS     cns-server 5120 KB  线程 9  fd 12
            cns-client 5276 KB  线程 9  fd 13
```

> 吞吐数字受限于回环而非本项目，所以这里没有意义化的"提升 N 倍"表述；
> 手机上的真实体验请用 `su -c /data/adb/modules/cns_rs/检测.sh` 在设备上复测。

---

## 🔄 兼容性矩阵

| 组合 | 状态 | 说明 |
| :--- | :--- | :--- |
| 新客户端 ↔ 新服务端 | ✅ | 完整支持 TCP / tcpDNS / httpUDP / httpDNS |
| 新客户端 ↔ 老服务端 (Go/C) | ✅ | 伪装头、`(%>w<%)`、粘包与游标语义逐字节对齐；`httpUDP` 依赖老服务端已具备的帧格式 |
| 老客户端 (`clnc`) ↔ 新服务端 | ✅ | 支持特征头、`httpUDP` 帧、`tcpDNS`、首包粘包还原 |
| 老客户端 ↔ 新客户端（同机） | ⚠️ | 老 `clnc` 需要 TUN；本实现已不提供 TUN（见下） |

---

## 🚀 核心机制

### 1. 伪装头与会话目标
所有会话（TCP、`tcpDNS`、`httpUDP`）都以一个 HTTP 请求头开场：

```http
GET / HTTP/1.1
Host: mclient.alipay.com
Meng: <base64(XOR("1.1.1.1:443\0"))>
```

* `Host` 为运营商免流白名单域名（可配 `header_host`）；
* `Meng`（`proxy_key` 可配）携带被**混淆**后的真实目标；未设口令时该值为明文 `host:port`；
* `custom_header` 支持模板占位符 `[HOST_HEADER]` / `[PROXY_KEY]` / `[ENCRYPTED_TARGET]`，脚本自动补全 CRLF。

⚠️ **关于「加密」**：CNS 的 `mask[i] = password[i] | i` 是**混淆**，不是密码学加密。密钥流仅由口令决定、每个会话都从 0 开始，而明文起始是固定的 `GET / HTTP/1.1` —— 已知明文可直接恢复密钥流前缀。它的作用是躲过 DPI 特征匹配，不提供机密性与完整性。若需要真正的加密，请自行在隧道外再叠一层（或在服务端开启 TLS 转发）。

### 2. 隧道复用（本仓库最大的一处性能修正）
免流的代价是「每个会话都要一次 HTTP 握手」。老客户端**每个 DNS 查询新建一条到 VPS 的 TCP 连接**，App 冷启动几十个域名 = 几十个并发外连，握手开销远超查询本身，也是发热与断流主因。

`cns-client` 现在用 `outbound::mux`：一条长连接承载同一目标的多个并发请求，按 **DNS 事务 ID** 分发应答，读写两个方向各自维护连续密钥流；命中本地缓存的查询完全不发网络包。回归测试 `many_concurrent_queries_share_a_single_connection` 断言「8 个并发查询只建 1 条 TCP 连接」。

### 3. DNS：源地址镜像回包
Android 内核严格校验 DNS 回包源地址，非 `orig_dst` 的回包会被直接丢弃。`cns-client` 通过 `IP_RECVORIGDSTADDR` 捕获原始查询目标，回包时**优先** `IP_TRANSPARENT` + `bind(orig_dst)`（内核自动补 IP/UDP 头与校验和，对 IPv6 同样有效），失败再退到手工构造的 IPv4 raw 包，最后才降级为中继源地址。IPv4 报文 ID 递增而非固定值。

`AAAA` 本地拦截（秒回 NODATA，促使 App 回退 IPv4 走隧道）由 **`block_ipv6`** 控制，**默认 true**。双栈/IPv6-only 网络请设为 `false`，否则解析不到任何地址。

### 4. httpUDP 通道
免流场景下 UDP 只有 53 端口在网关侧可达，且 53 有严格网关限制，因此 UDP 只能与隧道同行。`httpUDP` 帧格式：

```
[2 字节小端 pkg_len][flag0][0][0][addr_type][IP][2 字节大端 port][payload]
```

客户端已接通：`SOCKS5 UDP ASSOCIATE → UdpRelay → httpUDP 隧道`（旧版 `render_udp_header()` 定义了却从未调用，该路径只有老 `clnc` 能触达）。relay 维护**来源 allowlist**，未做过 ASSOCIATE 的地址一律拒绝，避免被当成开放 UDP 反射器。

### 5. 抗断流
* `SO_KEEPALIVE` + `TCP_KEEPIDLE=30/INTVL=10/CNT=6`：基站/光猫 NAT 表项老化才是「假连接」主因；
* `TCP_FASTOPEN_CONNECT`：客户端出站首写携带 SYN 数据（旧版只在服务端开了 TFO，客户端从未使用，所谓 0-RTT 只是宣传）；
* 隧道空闲超时后自动回收并在下一次查询时重建；驱动任务退出时立即让所有在途请求失败，不干等到超时；
* DNS 竞速（`dns_upstream` 多上游）带硬超时并 abort 落败方，不再悬挂 fd。

---

## 📦 产物与部署

**产物只存放在仓库根目录一份**（不再同时镜像到 `bin/`，也不在模块源码目录里保存二进制副本 —— 同一二进制存 3~4 份既显杂乱又容易装到过期版本）：

| 根目录文件 | 目标三元组 | 链接方式 | 用途 |
| :--- | :--- | :--- | :--- |
| `cns-server-x86_64` | `x86_64-unknown-linux-musl` | **静态** | VPS 服务端（主流方案） |
| `cns-server-aarch64` | `aarch64-unknown-linux-musl` | **静态** | ARM 服务器 / 小鸡 / OpenWrt |
| `cns-client-aarch64` | `aarch64-linux-android` | 动态（`/system/bin/linker64`） | 手机客户端，打包时注入模块 zip |
| `sha256sums.txt` | — | — | `install.sh` 下载校验依据 |

```bash
bash scripts/build.sh                 # 构建全部三个产物 + 生成 sha256sums.txt
bash scripts/build.sh --server-only   # 只要服务端
bash scripts/build.sh --client-only   # 只要手机客户端
bash scripts/build.sh --clean         # 构建后清理 target/ 释放空间
python3 build_module.py               # 打包模块 zip（自动取根目录的 cns-client-aarch64）
```

`scripts/build.sh` 会**断言**服务端产物为 `statically linked`、客户端产物为 Android aarch64，并对同架构产物实跑 `--version` 自检；不满足即中止 —— 避免把 bionic 二进制装到 Ubuntu 上（这是 v0.1.x 的真实故障：仓库里的 `cns-server-aarch64` 实际是 Android 动态链接产物，标称"纯静态"却根本跑不起来）。

---

## ⚡ 一键部署服务端（Linux VPS）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zsx0809/cns-rs/main/install.sh)
```

脚本行为：
* 识别发行版与架构，配置 systemd / OpenRC 守护与开机自启；
* **只从 GitHub Releases 拉取**预编译静态二进制，并按 `sha256sums.txt` 校验（第三方加速镜像仅作回退，且失败即中止，绝不安装未校验的二进制）；
* 交互式设置端口/口令/伪装域名，结束后打印可直接粘进手机模块的配置块；
* `bash install.sh update` 原子替换并重启（先停服务再覆盖，避免 `ETXTBSY`）。

服务端 `config.json`（全部字段可省略，省略即取默认）：

```json
{
  "listen_addr": [":1254"],
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "encrypt_password": "换成你的口令",
  "tcp_timeout": 300,
  "udp_timeout": 30,
  "handshake_timeout": 10,
  "dial_timeout": 10,
  "max_connections": 4096,
  "max_connections_per_ip": 128,
  "enable_dns_tcp_over_udp": true,
  "enable_tfo": true,
  "ipv6_only": false,
  "transparent": false,
  "enable_httpdns": false,
  "dns_upstream": ["223.5.5.5:53", "8.8.8.8:53"],
  "allow_private_targets": false,
  "allow_target_cidrs": []
}
```

**安全默认值**（与 v0.1.x 不同，这些都会导致行为变化）：

1. **配置解析失败即拒绝启动**。旧版会 `warn` 后静默使用默认配置，而默认 `encrypt_password` 为空 = 明文开放代理；一个逗号写错就把节点变成公开转发器。调试请用 `--allow-defaults` 显式声明。
2. **默认拒绝回源到私网/环回/链路本地/云元数据**。协议允许客户端在头里指定任意目标，无守卫即是打内网和偷 `169.254.169.254` 凭据的跳板。需要内网回源时设 `allow_private_targets: true` 或用 `allow_target_cidrs` 精确放行。
3. **`enable_httpdns` 默认 false**：公开递归解析器有滥用面。
4. **默认双栈监听**：`[::]:port` 同时接受 IPv4。v0.1.x 无条件 `set_only_v6(true)`，导致 IPv4-only 移动网络完全连不上。

---

## 📱 Android 模块

```bash
python3 build_module.py          # 自动使用根目录 cns-client-aarch64
# 产物：cns-rs-v0.2.0-magisk-ksu-apatch-arm64.zip (+ .sha256)
```

在 Magisk / KernelSU / APatch 中刷入，模块安装到 `/data/adb/modules/cns_rs/`（另有软链接 `/data/免流模式/`）。

**端口只有一个真源**：运行参数全部来自 `modes/<模式>.json`（`tproxy_listen` / `dns_listen` / `socks5_listen`），`config.ini` 只做模式选择与调度开关。v0.1.x 的脚本把服务端端口硬编码成 `13872`，而 install.sh 默认 1254——放行规则与实际端口不符时，`cns-client` 自己的出站会被 REDIRECT 抓回自己，形成回环、全网断流。现在脚本从 JSON 读出 `cns_server` 的端口**与解析出的 IP**逐条放行，并且所有 `iptables -A` 前先做 `-C` 存在性检查，重复 `start` 不再堆积规则。

控制命令（ASCII 别名 `start.sh/stop.sh/status.sh` 与中文名等价，规避部分终端对中文路径的编码问题）：

```bash
su -c /data/adb/modules/cns_rs/开启.sh      # 或 start.sh
su -c /data/adb/modules/cns_rs/关闭.sh      # 或 stop.sh
su -c /data/adb/modules/cns_rs/检测.sh      # 或 status.sh（含连通性自检）
```

KSU / APatch 可在模块列表点【操作 / Action】一键开关。

客户端 `modes/联通.json`：

```json
{
  "cns_server": "你的服务端IP:1254",
  "cns_password": "与服务端一致的口令",
  "proxy_key": "Meng",
  "header_host": "mclient.alipay.com",
  "tproxy_listen": "[::]:7750",
  "dns_listen": "0.0.0.0:7753",
  "socks5_listen": "127.0.0.1:1080",
  "tproxy_mode": "redirect",
  "gid": 3004,
  "enable_tfo": true,
  "enable_udp_tunnel": true,
  "dns_mode": "orig",
  "dns_upstream": ["223.5.5.5:53", "8.8.8.8:53"],
  "block_ipv6": true,
  "dns_cache_size": 2048,
  "buffer_pool_cap": 64
}
```

* `dns_mode: orig`（默认）沿用 App 原本要查的 DNS（`IP_RECVORIGDSTADDR` 捕获），这是运营商 DNS 劫持/分流场景唯一正确的做法；`fixed` 则恒用 `dns_upstream`。v0.1.x 辛苦取出的 `orig_dst` 被完全忽略、写死 `8.8.8.8:53`，国内 VPS 上直接解析全挂。
* `gid: 3004` 必须保留并配合脚本里的 `--gid-owner` 白名单，否则回环。**进程先建好所有监听 socket、之后才切 GID**（顺序反了会把监听口自己抓进 REDIRECT）。

---

## 🛠 关于 TUN（已移除）

v0.1.x 的 `--tun` 实现只处理 UDP/53，其余 IP 报文全部丢弃——挂上 `tunDev` 等于全网断流。本版本**删除 TUN 路径**，全部走 `REDIRECT`（默认，Android 内核最稳）或 `TPROXY`（`--mode tproxy`，需策略路由，能拿到原始目的地址、支持非本地 socket）。

如果你依赖老脚本的 `tunDev` 启动方式，请改用 `开启.sh`，它会在 `tproxy_mode='redirect'` 下生成等价规则。

---

## 🧪 测试与验证

```bash
cargo test --workspace --all-targets          # 单元 + 真实服务端集成 + 端到端
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash crates/cns-server/tests/smoke_real_binary.sh cns-server-aarch64 cns-client-aarch64
```

* 集成测试直接起 `cns_server::serve::RunningServer`（真实监听、真实握手），不再手搓 mock——旧测试的 mock 与被测代码不同源，测过不代表能用。
* 端到端断言包含：IPv4 客户端能连上 `[::]` 监听；粘包 banner 不丢；`httpUDP` 回帧的 IPv4-mapped 地址族被正确规范化（`::ffff:127.0.0.1` 必须写成 addr_type=1，否则客户端按 IPv6 解析丢包——这是本次实现中一个真实的协议 bug）；8 并发查询只建 1 条连接。

---

## 📄 License

MIT，见 [LICENSE](LICENSE)。
