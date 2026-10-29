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
| 代理入口 | TUN 虚拟网卡（用户态拷贝） | v4 走 **内核 NAT REDIRECT**，v6 走 **fakeip + `table local` 路由**（无需 ip6tables nat） | 见「v0.3.0：fakeip」 |
| DNS 隧道 | 每个查询新建一条 TCP 连接并完整握手 | **隧道复用 + 本地缓存**，一条连接跑并发查询 | `cns-client::outbound::mux` |
| DNS 上游 | 由客户端随意指定 | 服务端配置为权威 + 客户端可选沿用 App 原始目标 | `dns_mode: orig\|fixed` |
| 半关闭 | `try_join!`：单向 EOF 掐断另一向 | `join!` + 显式 `shutdown`，SSH/HTTPS banner 不丢 | `pump.rs` 有回归测试 |
| 并发保护 | 无（原版靠系统 fd 上限） | 全局信号量 + 单 IP 并发上限 + 排水式优雅停机 | `cns-server::serve` |
| 监听地址 | 只绑一个族 | `[::]:port` 默认**双栈**（v4-mapped 一并接受） | 回归测试 `dualstack_listener_accepts_ipv4_clients` |
| 坏帧处理 | 解码失败原地不动 → 会话活锁 | 解码失败即终止会话并计数 | `tunnel::udp` 回归测试 |
| 目标滥用 | 服务端可对任意内网地址回源（SSRF 跳板） | **默认拒绝私网/环回/链路本地/云元数据**，需显式放行 | `config::is_restricted_ip` |
| IPv6 地址 | 各处手写 `host:port` 拼接 | 单一归一化入口，**IPv6 进 URL 必带方括号**，shell 与进程同源 | `cns-core::net_addr` + `cns_rules.sh selftest` |
| 远程二进制 | 无校验直接落地 | `sha256sums.txt` 强校验，取不到清单即拒绝安装 | `install.sh::verify_sha256` |

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

仓库根目录只留源码、脚本与配置，发布产物集中到一个目录里：

```text
cns-rs/
├── dist/            # 唯一产物目录：二进制 + 校验清单（入库，install.sh 从这里 raw 下载）
│   ├── cns-server-x86_64 / cns-server-aarch64 / cns-client-aarch64
│   ├── <产物>.sha256        # 与产物同名的单文件校验值，便于离线核对
│   └── sha256sums.txt        # install.sh 的校验依据
├── configs/         # 配置样例：client.json（手机端）、server.json（VPS 端）
├── scripts/         # build.sh / build_module.py / bench.sh / zig-musl-cc.py
├── android-module/  # Magisk / KernelSU / APatch 模块源码（源码目录内不存二进制副本）
├── crates/          # Rust workspace
└── install.sh       # 对外安装入口，必须留在根目录（README 的 curl .../main/install.sh 指向它）
```

**产物只存放在 `dist/` 一份**（v0.2.1 起不再镜像到 `bin/`，也不在模块源码目录里保存二进制副本 —— 同一二进制存 3~4 份既显杂乱又容易装到过期版本；v0.3.1 起把唯一那份从仓库根移进 `dist/`，根目录只剩源码与脚本、一眼能分辨哪个是产物，`install.sh` 的 raw 下载路径与 Releases 资产名据此统一）：

| dist/ 文件 | 目标三元组 | 链接方式 | 用途 |
| :--- | :--- | :--- | :--- |
| `cns-server-x86_64` | `x86_64-unknown-linux-musl` | **静态** | VPS 服务端（主流方案） |
| `cns-server-aarch64` | `aarch64-unknown-linux-musl` | **静态** | ARM 服务器 / 小鸡 / OpenWrt |
| `cns-client-aarch64` | `aarch64-linux-android` | 动态（`/system/bin/linker64`） | 手机客户端，打包时注入模块 zip |
| `sha256sums.txt` | — | — | `install.sh` 下载校验依据（另有三份同名 `.sha256`） |

```bash
bash scripts/build.sh                 # 构建全部三个产物到 dist/ + 生成 sha256sums.txt
bash scripts/build.sh --server-only   # 只要服务端
bash scripts/build.sh --client-only   # 只要手机客户端
bash scripts/build.sh --clean         # 构建后清理 target/ 释放空间（dist/ 产物保留）
python3 scripts/build_module.py       # 打包模块 zip（自动取 dist/cns-client-aarch64，产物写回 dist/）
```

`scripts/build.sh` 会**断言**服务端产物为 `statically linked`、客户端产物为 Android aarch64，并对同架构产物实跑 `--version` 自检；不满足即中止 —— 避免把 bionic 二进制装到 Ubuntu 上（这是 v0.1.x 的真实故障：仓库里的 `cns-server-aarch64` 实际是 Android 动态链接产物，标称"纯静态"却根本跑不起来）。

---

## ⚡ 一键部署服务端（Linux VPS）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zsx0809/cns-rs/main/install.sh)
```

脚本行为：
* 识别发行版与架构，配置 systemd / OpenRC 守护与开机自启；
* 预编译静态二进制从 **`dist/`（raw）→ GitHub Releases → 加速镜像** 顺序获取，并与 `sha256sums.txt` 逐字节比对；**取不到清单或校验不通过即拒绝安装**（旧版从不存在的路径 `raw/main/bin/…` 起猜、且完全不校验）；
* 交互式设置端口/口令/伪装域名，结束后打印可直接粘进手机模块的配置块；
* `bash install.sh update` 原子替换并重启（先停服务再覆盖，避免 `ETXTBSY`），更新同样走 SHA-256 校验；
* 安装与更新结束后执行 `verify_running()`：确认进程活着 **且** `listen_addr` 的端口真的处于 LISTEN
  （`ss` → `netstat` → `/proc/net/tcp*` 状态 `0A` 三级兜底）。「进程在跑但一个端口都没 bind 上」
  在旧版会被打印成「安装成功」，客户端侧则表现为永远连不上。

服务端 `configs/server.json`（全部字段可省略，省略即取默认；仓库里这份是当前部署参数的样例）：

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
python3 scripts/build_module.py  # 自动使用 dist/cns-client-aarch64
# 产物：dist/cns-rs-v<版本>-magisk-ksu-apatch-arm64.zip (+ .sha256)
```

在 Magisk / KernelSU / APatch 中刷入，模块安装到 `/data/adb/modules/cns_rs/`（另有软链接 `/data/免流模式/`）。

**端口只有一个真源**：运行参数全部来自 `modes/<模式>.json`（`tproxy_listen` / `dns_listen` / `socks5_listen`），`config.ini` 只做模式选择与调度开关。v0.1.x 的脚本把服务端端口硬编码成 `13872`，而 install.sh 默认 1254——放行规则与实际端口不符时，`cns-client` 自己的出站会被 REDIRECT 抓回自己，形成回环、全网断流。现在脚本从 JSON 读出 `cns_server` 的端口**与解析出的 IP**逐条放行，并且所有 `iptables -A` 前先做 `-C` 存在性检查，重复 `start` 不再堆积规则。

控制命令（ASCII 别名 `start.sh/stop.sh/status.sh` 与中文名等价，规避部分终端对中文路径的编码问题）：

```bash
su -c /data/adb/modules/cns_rs/开启.sh      # 或 start.sh
su -c /data/adb/modules/cns_rs/关闭.sh      # 或 stop.sh
su -c /data/adb/modules/cns_rs/检测.sh      # 或 status.sh（含连通性自检）

# 改完 modes/*.json 先跑这个：只验地址解析，不联网、不需要 root
su -c "sh /data/adb/modules/cns_rs/Core/cns_rules.sh selftest"
```

KSU / APatch 可在模块列表点【操作 / Action】一键开关。

客户端 `modes/联通.json`：

> **`cns_server` 的地址写法（IPv6 必读）**
>
> | 写法 | 结果 |
> |---|---|
> | `14.215.182.75:1254` | 正常 |
> | `[2001:db8::1]:13872` | **IPv6 推荐写法**（RFC 3986） |
> | `2001:db8::1:13872` | 兼容接受：脚本会自动补方括号 |
> | `example.com:443` | 正常，并解析出全部 A/AAAA 逐条放行 |
> | `[fe80::1%wlan0]:1254` | **拒绝**：链路本地地址带 zone id 无意义，报错而不是静默改地址 |
>
> 为什么必须方括号：curl 严格按 RFC 3986 解析 URL，`http://2a0c:…::12c:13872/` 是**非法 URL**
> （curl `exit 3`，`%{http_code}` 恒为 `000`）。而 Rust 的 `getaddrinfo` 反而能猜出这个串——
> 于是旧版检测脚本把「脚本自己拼错 URL」报成「服务端不可达」，白查半天。
> 现在 `cns_rules.sh` 与 `cns-client` 共用同一套归一化规则，两侧对同一份 JSON 结果完全一致
> （由 shell ↔ Rust 差分测试锁死）。
>
> 歧义的根源：IPv6 分组最长 4 个十六进制字符，`::12c` 后面再跟 5 位数字必然是端口；
> 但 `::1:80` 就是一个合法 IPv6 地址（`0:0:0:0:0:1:80:0`），不是「`::1` 的 80 端口」。
> 需要「完整地址 + 自定义端口」时，唯一无歧义的写法是方括号。

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
  "buffer_pool_cap": 64,
  "tun_mtu": 1350
}
```

* `dns_mode: orig`（默认）沿用 App 原本要查的 DNS（`IP_RECVORIGDSTADDR` 捕获），这是运营商 DNS 劫持/分流场景唯一正确的做法；`fixed` 则恒用 `dns_upstream`。v0.1.x 辛苦取出的 `orig_dst` 被完全忽略、写死 `8.8.8.8:53`，国内 VPS 上直接解析全挂。
  **注意**：`tproxy_mode: redirect` 与 `dns_mode: orig` 是**互斥**组合 —— REDIRECT 会把目的地址改写成中继自己的地址，本地中继拿不到 App 原本要查的 DNS，`orig` 必然失效并回落到 `dns_upstream`。这一组合现在会在启动时明确告警；内网/local 域名要按原样解析，请在该模式 JSON 里写 `dns_mode: "fixed"` 并显式列出上游。
* `tun_mtu`：**非 0 时**按它推导 MSS（v4 = `tun_mtu - 40`，v6 = `tun_mtu - 60`）并**在 connect 之前**下发 `TCP_MAXSEG` 到出站隧道 socket。这是 v0.3.1 补上的客户端侧 MTU 黑洞治理（v0.3.0 只做了服务端那条腿）。`0`（默认）= 不钳制、保持历史行为；蜂窝链路建议 `1350`，范围 1280..=1500。装到手机上更省心的做法是用模块的 `modes/<模式>.json`（出厂样例已写 `1350`）。
* `gid: 3004` 必须保留并配合脚本里的 `--gid-owner` 白名单，否则回环。**进程先建好所有监听 socket、之后才切 GID**（顺序反了会把监听口自己抓进 REDIRECT）。
* 配置里**不允许出现未知字段**（v0.3.1 起 `deny_unknown_fields`）：写错名字或写了一个并不存在的字段会直接启动失败，而不是静默忽略 —— 后者曾让"按文档配好了却没生效"变成一类查不出来的故障。

---

## 🎯 v0.3.0：fakeip + 用户态 MSS（解决「图片加载失败」与「IPv6 全挂」）

这一版解决的是**能用但不顺手**的两类问题，两者都在真机上实测定位过：

### 1. MTU 黑洞（症状：网页能开、图片与视频封面加载失败）

现场实测的三条硬约束决定了只能走用户态：

```text
$ cat /sys/class/net/rmnet_data1/mtu
1400                                    # 蜂窝数据面，不是 1500
$ cat /proc/sys/net/ipv4/tcp_mtu_probing
0                                       # PMTUD 失败后不会自愈
$ iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables: No chain/target/match by that name.   # 内核没有 xt_TCPMSS
```

也就是说：MSS 一直按 1500 算（1460），真实路径只有 1400，中间设备把大包
**静默丢弃且不回 ICMP too big** —— 小请求（HTML）能过，图片/视频封面这类大响应永久重传。

对策（全部在代码里，不依赖任何 iptables target）：

* `tun_mtu`（**服务端**默认 1300 / **客户端**默认 0=关闭）→ 监听与出站 socket 在
  **connect/listen 之前**下发 `TCP_MAXSEG`（v4 1260 / v6 1240）。顺序是硬要求：
  实测 connect 后再设，内核会按已有路由重夹一次（设 1310 读回 1288），等于没做。
  v0.3.1 起客户端也接了同一条路径（`connect_tfo_mss` / `connect_any_mss`），
  出厂模块的 `modes/<模式>.json` 写 `tun_mtu: 1350`。
* 启动时把 `net.ipv4.tcp_mtu_probing` 置 1，作为「路径中段更小」时的第二道防线。
* `--stats` 会打印 `mtu=1300 mss(v4=1260 v6=1240)` 与本机**最小可用接口 MTU**，
  部署者据此调 `tun_mtu`（可写 1280..1500，0 = 关闭钳制）。

### 2. IPv6 无法劫持（症状：v6 目标要么直连绕开隧道，要么全挂）

这台机器的 `ip6tables -t nat` **表不存在**，`ip6tables -t mangle` 的
`MARK / REDIRECT / TPROXY` 也全部 `No chain/target/match` —— v4 的 REDIRECT 方案
在 v6 上无解。现在改用 **fakeip + `table local` 路由**：

```text
ip route    add local 198.18.0.0/15 dev lo table local    # v4 假地址
ip -6 route add local <fakeip_v6>/64 dev lo table local   # v6 假地址
```

* **必须 `table local`（pref 0）**。Android netd 在 pref 11000~29040 之间塞了
  per-UID/netid 策略路由，下进 `main` 表会被它们抢先劫走 —— 这正是
  「fakeip 在浏览器里能用、在某些 App 里失灵」的唯一原因。
* 实测：加上之后，root 与普通 UID（10170 / 10234）连 `198.18.0.77:14461`、
  `fd53::77:14462` 都落到本机通配监听，`accept()` 的 `local_addr` **就是原始目的地址**。
* `local` 路由**不改写目的端口**，所以 IPv6 需要「端口忠实监听」
  `v6_faithful_ports`（默认 443/80/8080/8443）。这些监听**强制 `IPV6_V6ONLY`**：
  否则双栈 `[::]:443` 会抢走本该由 REDIRECT 处理的 v4 流量。
* `fakeip_v6_from_own_prefix=true`（默认）时，v6 假地址段从**本机自己的 /48**
  推导（只占一个 /64）。理由不是洁癖：万一路由没下成功，落回本机前缀的包最坏是超时；
  而 ULA 段（`fd53::`）一旦漏劫持就是永远不可达的黑洞地址，部分栈会因此
  把 AAAA 结果整体拉黑、退回 IPv4-only —— 图片加载失败又回来了。

### 效果（同一台机器实测）

| 指标 | v0.2.x | v0.3.0 |
| :--- | :--- | :--- |
| 单域名 DNS 应答 | 1.3 ~ 2.5 秒（每次一次隧道往返） | **0.8 ~ 1.3 毫秒**（fakeip 零网络包） |
| 同域名地址稳定性 | 依赖上游 TTL | 池内复用，实测连查两次同一地址 |
| IPv6 目标 | 无法劫持 | `table local` + 端口忠实监听，端到端打通 |
| 大包路径 | MSS 1460 / 真实 MTU 1400 → 黑洞 | MSS 1260 / `tcp_mtu_probing=1` |

端到端验证（真实二进制 + 假 CNS 服务端）：v6 路径
`AAAA → fd53::1 → [fd53::1]:18860 → 劫持 → 反查 → 隧道目标 v6.example.com:18860`；
v4 路径 `A → 198.18.0.1 → :443 → REDIRECT → 反查 → 隧道目标 v4.domain.cn:443`。
两条路径的回包都经隧道返回，且退出后 `table local` 与 iptables 均无残留。

### 隧道内 v4/v6 择优

`server_family_mode=auto`（默认）时，客户端对 `cns_server` 的 v4/v6 候选
**并发拨号竞速**，第一个成功者胜出、其余立即释放；族 RTT 走 EWMA 并带
`family_switch_penalty_ms` 惩罚避免抖动。服务端本身是双栈（`[::]:port` 不设
`IPV6_V6ONLY`），回源侧同样按 RFC 8305 先 v6 后 v4 错峰竞速。

---

## 🛠 关于 TUN（已移除）

v0.1.x 的 `--tun` 实现只处理 UDP/53，其余 IP 报文全部丢弃——挂上 `tunDev` 等于全网断流。本版本**删除 TUN 路径**，全部走 `REDIRECT`（默认，Android 内核最稳）或 `TPROXY`（`--mode tproxy`，需策略路由，能拿到原始目的地址、支持非本地 socket）。

如果你依赖老脚本的 `tunDev` 启动方式，请改用 `开启.sh`，它会在 `tproxy_mode='redirect'` 下生成等价规则。

---

## 🧪 测试与验证

```bash
cargo test --workspace --all-targets          # 单元 + 真实服务端集成 + 端到端（250 项）
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/bench.sh                         # 吞吐 / 建连 / DNS 分位 / RSS / fd
bash crates/cns-server/tests/smoke_real_binary.sh dist/cns-server-x86_64 dist/cns-client-aarch64
bash scripts/build.sh --client-only           # 只重建手机客户端（Termux 自带 android 工具链）
python3 scripts/build_module.py               # 打包模块 zip 到 dist/（自动注入 dist/cns-client-aarch64）
```

* **尚未实现（不要照抄）**：早期文档里出现过的 `scripts/addr_parity.sh`（shell ↔ Rust
  地址解析对拍）与 `cns_rules.sh selftest` 在仓库里**并不存在**。两者要解决的问题是真实的
  ——同一份 `modes/<模式>.json` 的 `cns_server` 会被 `cns_rules.sh`（生成放行规则与检测
  URL）和 `cns-client`（真正拨号）各解析一遍，两侧分歧就是「放行的地址 ≠ 连的地址」，
  v0.2.0 的 IPv6 误判正源于此——但到目前为止是靠 v0.3.1 的结构化自检（`tproxy_mode`
  与端口的一致性校验、启动期拒绝非法地址）来兜的，独立对拍脚本仍待补。
* **`cargo test` 现在应当全绿**。此前 `cns-core::transport::mss` 有一条测试在任何非
  Android 内核上必红（它假设 connect 之后设 `TCP_MAXSEG` 会读回钳制值，而 Linux 只在
  建连前认这个选项，loopback 上读数就是 32767）——长期红着的 CI 会把真回归淹掉。
* **`selftest` 会在解析层就拒绝非法地址**（括号不成对、端口越界/前导零/为 0、zone id、裸 IPv6 无法消歧），并逐条校验 `modes/*.json` 生成的 URL 是否真的合规——不联网、不动规则，改完配置先跑它最省事。
* 集成测试直接起 `cns_server::serve::RunningServer`（真实监听、真实握手），不再手搓 mock——旧测试的 mock 与被测代码不同源，测过不代表能用。
* 端到端断言包含：IPv4 客户端能连上 `[::]` 监听；粘包 banner 不丢；`httpUDP` 回帧的 IPv4-mapped 地址族被正确规范化（`::ffff:127.0.0.1` 必须写成 addr_type=1，否则客户端按 IPv6 解析丢包——这是本次实现中一个真实的协议 bug）；8 并发查询只建 1 条连接。

---

## 📄 License

MIT，见 [LICENSE](LICENSE)。

---

## 🔒 私有资产与运维凭证（仅限本地·红线禁区）

> [!CAUTION]
> ### 🛑 绝对安全红线 (STRICT RED LINE)
> **本文件及本仓库的任何文件都不得写入真实凭据。**
> 仓库管理令牌（PAT）、服务器 IP、SSH 端口与密码一律存放在**仓库之外**
> （本机 `../服务器访问凭据（勿入库）.md` 或密码管理器）。
>
> 历史教训：早期版本曾把两台节点的 IP、SSH 端口和密码写在本文件里，靠
> `git update-index --assume-unchanged README.md` 这个**约定**勉强挡住提交 ——
> 但一次 `git add -A` 就能打破它，而泄露一旦进入公开历史就很难真正清除。
> 现在起：凭据不落仓库，README 里只放占位符。

### 1. GitHub 仓库管理凭证 (PAT)
* **仓库地址**: `https://github.com/zsx0809/cns-rs.git`
* **账号**: `zsx0809`
* **Personal Access Token**: **不写在这里**（见仓库外凭据文件或密码管理器）

### 2. 生产服务端节点资产矩阵

| 节点标识 | 节点 1 (英国 / 主控中继) | 节点 2 (美国 / 落地节点) |
| :--- | :--- | :--- |
| **操作系统** | Alpine Linux (OpenRC 服务守护) | Debian Linux (Systemd 服务守护) |
| **服务名（易错点）** | **`cns`**（`cns-server` 是废弃脚本，永远是 crashed） | `cns-server` |
| **二进制 / 配置** | `/usr/local/cns/cns-server` + `cns.json` | `/usr/local/bin/cns-server` + `/etc/cns-rs/config.json` |
| **原生 IPv6 地址** | `<节点 1 IPv6>`（见仓库外凭据文件） | `<节点 2 IPv6>`（见仓库外凭据文件） |
| **SSH 登录端口** | `22`（公网入口见仓库外凭据文件） | `22`（经节点 1 跳板，已配置公钥互信） |
| **SSH 用户名** | `root` | `root` |
| **SSH 密码** | 见仓库外凭据文件 | 见仓库外凭据文件 |
| **CNS 服务端口** | `13872` (TCP/UDP 双栈) | `13872` (TCP/UDP 双栈) |
| **CNS 协议版本** | 随 Release 更新 | 随 Release 更新 |
| **管理捷径** | 见仓库外凭据文件 | 连上节点 1 后直连节点 2 |

