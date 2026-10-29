# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## 0.3.0

> 从「能连上」到「能用」：根治 MTU 黑洞与 IPv6 无法劫持这两个把体验打死的问题。

### 修复（直接对应现场症状：网页慢、图片与视频封面加载失败）

- **MTU 黑洞根治（用户态，不再依赖 iptables）**。现场实测三件事决定了只能这么做：
  `rmnet_data1` 的 MTU 是 **1400**（不是 1500）、`net.ipv4.tcp_mtu_probing` 是 **0**、
  而这台机器的内核**根本没有 `xt_TCPMSS`** —— `iptables -t mangle -j TCPMSS` 报
  `No chain/target/match`。也就是说旧脚本里那行 `--clamp-mss-to-pmtu` 从 v0.2.0 起
  一直在 `2>/dev/null` 的掩护下静默失败，MSS 始终按 1500 算（1460），
  真实路径只有 1400 —— 大包被中间设备**静默丢弃**（连 ICMP too big 都不发），
  于是「小请求能通、图片/视频封面加载失败」。
  现在：
  * `tun_mtu`（默认 1300）→ 监听与出站 socket 一律在 connect/listen **之前**
    下发 `TCP_MAXSEG`（实测 connect 后再设会被内核按路由重夹：设 1310 读回 1288，
    所以顺序错了等于没做）；
  * 启动时把 `net.ipv4.tcp_mtu_probing` 置 1 作第二道防线（路径中段更小时靠它自愈）；
  * 可用 `--stats` 看到 `mtu=1300 mss(v4=1260 v6=1240)` 与最小可用接口 MTU。
- **IPv6 无法劫持 → fakeip + `table local` 路由**。`ip6tables -t nat` 表在这台机器上
  **不存在**，`ip6tables -t mangle` 的 `MARK/REDIRECT/TPROXY` 也全部不可用，
  所以「照抄 v4 的 REDIRECT」在 v6 上无解。现在的做法：
  * 本地 DNS 直接返回 fakeip（v4 `198.18.0.0/15`、v6 默认 `fd53::/48`，
    可配置成从**本机自己的前缀**推导，避免过期段被栈判定不可达）；
  * `ip route add local <段> dev lo table local`（v4/v6 各一条）把假地址吸进本机，
    通配监听拿到的 `local_addr` 就是原始目的地址；
  * **必须是 `table local`（pref 0）**：Android netd 在 pref 11000~29040 塞了
    per-UID/netid 策略路由，下进 `main` 表会被它们抢先劫走 ——
    这正是「fakeip 在浏览器能用、在某些 App 失灵」的唯一原因。
  * `local` 路由**不改写目的端口**，所以新增「端口忠实监听」`v6_faithful_ports`
    （默认 443/80/8080/8443），且这些监听**必须 `IPV6_V6ONLY`**，
    否则双栈 `[::]:443` 会抢走本该由 REDIRECT 处理的 v4 流量。
- **DNS 从「每个域名一次隧道往返」降到毫秒级**：fakeip 命中时**零网络包**，
  实测 1.3~2.5 秒 → **0.8~1.3 毫秒**；同域名同族地址稳定复用（实测连查两次同址）。
  真实解析仍在后台经 tcpDNS 隧道完成，写入 `FakeIpPool::set_real` 供择优使用。
- **隧道内 v4/v6 择优**：`server_family_mode=auto` 时对 `cns_server` 的 v4/v6 候选
  **并发拨号竞速**，第一个成功者胜出，其余立即释放；族 RTT 走 EWMA 并带
  `family_switch_penalty_ms` 惩罚，避免来回抖动（服务端本来就是双栈 `[::]:port`）。
- **服务端回源改 RFC 8305 风格**：v6 首发、`happy_eyeballs_ms` 后错峰并发 v4，
  胜者留下、败者 abort；出站 socket 同样在 connect 前钳 MSS。
- **fakeip 泄漏守卫**：`fakeip_guard_cidrs` 内的目标一律拒绝回源，
  报「目标落在客户端 fakeip 段（疑似回环解析）」，而不是打一个必然失败的回源。

### 修复（正确性 / 生命周期）

- **SIGTERM 现在会优雅退出并撤销 fakeip 路由**。旧实现只挂 `ctrl_c()`，
  而模块脚本、Magisk/KernelSU 的「关闭」、`kill <pid>` 走的都是 SIGTERM ——
  进程直接消失、`Drop` 不执行，`table local` 里的 fakeip 段会**永久留在内核里**
  （实测复现）。后果不只是断网：那一整段 13 万个地址从此被本机吞掉，
  卸了模块也连不上落在该段的真实服务。现在 SIGTERM/SIGHUP/Ctrl-C 三条路径都收尾。
- **路由下发移到所有监听绑定成功之后**。早先放在建池之后、bind 之前，一次
  「端口已被占用」的启动失败会带着 `Drop` 跑掉，把**另一个仍在运行的实例**
  刚下好的路由撤销（实测日志：`bind SOCKS5: Address already in use` 紧跟两行
  `local route removed`）。两个实例互相踩的表现是「DNS 回假地址、连接却超时」。
- **`canonicalize_ip` 下沉到 `net_addr`**：它是地址规范化而非协议编解码，
  放在叶子模块后 `net_addr` 不再反向依赖 `protocol` ——
  否则 `scripts/addr_parity.sh` 那种把 `net_addr.rs` 单独编成 harness 的隔离测试
  会直接编不过。

### 新增

- 客户端配置：`enable_fakeip` `fakeip_v4` `fakeip_v6` `fakeip_v6_from_own_prefix`
  `fakeip_v6_marker` `fakeip_ttl` `fakeip_persist` `fakeip_direct_domains`
  `fakeip_direct_suffixes` `tun_mtu` `enable_mtu_probing` `server_family_mode`
  `family_probe_count` `family_probe_timeout_ms` `family_switch_penalty_ms`
  `enable_local_route` `local_route_table` `v6_faithful_ports` `v6_dns_servers`
- 服务端配置：`prefer_family` `happy_eyeballs_ms` `dial_probe_count` `outbound_mss`
  `fakeip_guard_cidrs`
- `cns-core::dns`（DNS 报文构造/解析，含压缩指针、NODATA/NXDOMAIN/SERVFAIL 最短应答）、
  `cns-core::fakeip 相关`（`IpCidr`、`derive_fakeip_v6_prefix`、`first_usable/nth_usable`）、
  `cns-core::transport::mss`（用户态 MSS 钳制与 MTU 探测开关）。
- 默认上游 DNS 改为**本机实测**下发的运营商地址（广东电信 `202.96.128.86` 等），
  而不是写死公共 DNS；仓库内 `modes/联通.json` 已填入真实服务端参数。

### 测试

- 全量 **336 项**单测/集成测试通过（core 94 + client 146 + server 9 + 其余集成）。
- 新增端到端验证（真实二进制 + 假 CNS 服务端）：
  * v6：`AAAA → fd53::1 → [fd53::1]:18860 → 端口忠实劫持 → 反查 → 隧道目标
    v6.example.com:18860`，回包 `HELLO-FROM-v6.example.com:18860`；
  * v4：`A → 198.18.0.1 → 198.18.0.1:443 → REDIRECT → 反查 → 隧道目标
    v4.domain.cn:443`，回包 `HELLO-FROM-v4.domain.cn:443`；
  * SIGTERM 后 `table local` 与 iptables 均无残留。
- `scripts/addr_parity.sh`（shell ↔ Rust 地址解析）36 条语料全一致；
  `cns_rules.sh selftest` **201 条**断言全绿（含 fakeip 段 CIDR、族判定、
  表名合法性、以及「本机无 v6 nat 时必须走 fakeip 分支」的路径判定）。

## 0.2.1

### 修复（IPv6 地址在 URL / 配置 / bind 三条链路上被误判或失败）

- **模块检测脚本不再把「拼错 URL」报成「服务端不可达」**：`cns_rules.sh` 原先直接拼
  `http://$SERVER_HOST:$SERVER_PORT/`。当 `cns_server` 是 IPv6 时（`2001:db8::1:13872`），
  curl 按 RFC 3986 判定为非法 URL，`exit 3` + `%{http_code}` 恒为 `000`，于是 `[4/4] 服务端可达`
  永远打 `×`，而服务端其实完全可达。现在所有 URL 一律经 `to_url()` 拼装，IPv6 字面量自动加方括号。
- **`probe()` 回传 curl 退出码并翻译成人话**：`000` 有三种完全不同的成因
  （`exit 3` = URL 非法 / `exit 7` = 端口未监听 / `exit 28` = 无回程路径）。
  旧输出只有一句「不可达（检查防火墙）」，把人往错的方向引。现在直接写明原因，
  且 URL 拼装错误会被单独标为脚本 bug，不再冒充网络故障。无 curl 时用 `nc` 做 TCP 层兜底探测。
- **`resolve_server()` 括号感知 + 严格 IP 族判定**：
  * 支持 `[v6]:port`、裸 `v6:port`、`v4:port`、`域名[:port]`、误填 `scheme://` 与路径、
    并显式拒绝 zone id（`fe80::1%wlan0`）与非法端口（`0`、`99999`、前导零、方括号不成对）。
  * 旧的 `case "$SERVER_HOST" in *[0-9]*.*)` 会把 **example.com 当成字面 IP**，
    于是完全跳过 DNS 解析、`SERVER_IPS` 只有一条无法用于 `iptables -d` 的串，
    域名服务端换 IP 后放行规则失效——这是「用域名就偶发断流」的根因。
  * 新增 `selftest` 子命令：`sh Core/cns_rules.sh selftest`，40 条断言无需 root/网络即可跑。
- **客户端配置层统一归一化地址**（新增 `cns-core::net_addr`）：`cns_server` / `dns_listen` /
  `socks5_listen` / `tproxy_listen` / `dns_upstream` 全部在 `validate()` 之前归一化成
  「IPv6 带方括号 + 端口显式存在」。这样 `parse::<SocketAddr>()`、`lookup_host()` 与
  shell 侧看到的是同一个字符串，不再出现「脚本放行 `[2a0c::12c]:13872`、进程连
  `2a0c::12c:13872` 行为不同」的分裂。
- **`2001:db8:0:1:2:3:4:5` 这类完整 8 段地址不再两侧行为不一致**：
  shell 会补默认端口，而 Rust 的 `getaddrinfo` 直接 `Name or service not supported`。
  现在 Rust 侧同样补默认端口并加括号。
- **服务端 `listen_addr` 写错不再静默变空壳**：`bind_listeners()` 原先对无法解析的 spec
  只是 `error!` + `continue`，若全部非法就得到一个「进程活着、端口没监听」的服务端。
  `Config::validate()` 现在启动前直接拒绝。`install.sh` 同步增加：
  * 端口输入的严格校验（旧版完全不校验，`99999` 能直接写进 config.json）；
  * `listen_addr` 语法检查（引号状态 + 括号配对的字符级扫描；`grep -o '"listen_addr"[^]]*]'`
    这类写法会在 `[::]:1254` 的第一个内层 `]` 处截断，只读到半条 spec）；
  * 安装/改配置后 `verify_running()` 真实确认端口处于 LISTEN
    （`ss` → `netstat` → `/proc/net/tcp*` 状态 `0A` 三级兜底，适配无 ss 的最小系统）。

### 变更（部署链路）

- **取消 `bin/` 产物镜像**：`scripts/build.sh` 的 `publish()` 只写仓库根目录一份。
  此前同一二进制存在 3~4 份，是「装了过期那份」的直接成因，也与 README「产物只存一份」自相矛盾。
- **`install.sh` 下载源修正**：旧脚本先猜 `raw/.../main/bin/cns-server-<arch>` 及加速镜像同路径 ——
  仓库里**从来没有** `bin/` 目录（`.gitignore` 只放行根目录三件套），每次安装必然空跑两轮超时才落到
  Releases。现在顺序为「根目录 raw → GitHub Releases → 加速镜像」，三处均指向真实存在的对象。
- **远程二进制强制 SHA-256 校验**（`install.sh::verify_sha256`）：安装与 `update` 两条路径都校验，
  取不到 `sha256sums.txt` 或比对不通过即拒绝落地。旧版首次安装完全不校验 —— 等于把「装什么」交给中间人；
  只有 `update` 拿哈希做过「是否同版本」的比较。本地已存在的预编译产物不做校验（用户自己编译的场景无意义）。
- **`cns_rules.sh` 变量命名规约**：`selftest` 遍历模式配置时改用 `_mf/_mn/_saved_conf`。
  此前循环变量 `_n` 会被 `split_endpoint` 内部的 `_n=$(_colons …)` 覆盖，导致模式名被静默清空
  （实测出现过「ok 后面空白」的输出），这类同名临时变量在 POSIX sh 里没有作用域隔离可依赖。

### 测试

- 新增 `cns-core::net_addr` 56 项单测（含 `::1:80` 是地址而非端口的歧义锁定）。
- 新增 **`scripts/addr_parity.sh`**（shell ↔ Rust 地址解析一致性测试，固化进仓库而非临时脚手架）：
  同一份 36 条语料分别喂给 `cns_rules.sh::split_endpoint` 与 `net_addr::parse_endpoint`，
  逐条比对 host / 端口 / 地址族 / 是否失败。锁死了 `:1254`（仅端口）与 `::1:13899`（裸 IPv6+端口）
  的分支优先级 —— 这个顺序 bug 就是差分测试当场抓出来的。
  脚本按**函数名**抽取 shell 侧纯函数（不用行号锚点，避免代码重排后静默抽错），
  并在抽取失败时明确报错而不是给出假绿。
  **已用变异测试验证它能真的失败**：改默认端口(1254→1255)、移除裸 IPv6 消歧保护、
  zone id 由拒绝改为静默剥离，三种注入全部报警；恢复后归零。
- CI `test` job 增加两个步骤：`bash scripts/addr_parity.sh` 与
  `sh android-module/Core/cns_rules.sh selftest`，让这两类回归在合并前就拦住。
- `cns-client` 新增回归：裸 IPv6 归一化、非法端点在启动期被拒绝、`dns_upstream` 归一化后仍受
  「端口必须 53（tcpDNS 快速通道）」约束。

## 0.2.0

### 修复（会导致连不上/断流级别）

- **服务端双栈监听**：`[::]:port` 不再强制 `IPV6_V6ONLY`。旧实现无条件 `set_only_v6(true)`，IPv4-only 移动网络的客户端**完全连不上**。
- **模块脚本端口不再硬编码**：旧版 `cns_rules.sh` 固定放行 `13872`，而 install.sh 默认 `1254`。不一致时 `cns-client` 的出站被自己的 REDIRECT 抓回，形成回环、全网断流。现在所有端口从 `modes/<模式>.json` 推导，并同时写入 iptables 与命令行。
- **DNS 上游不再写死 8.8.8.8**：改用 `IP_RECVORIGDSTADDR` 捕获到的原始查询目标（`dns_mode: orig`，默认），国内 VPS/被劫持链路不再解析全挂。
- **DNS 应答粘包不再丢弃**：旧实现只 `read()` 一次并丢掉超出响应头的字节，导致后续 `read_exact` 死等 —— 表现为「图片时好时坏」的随机超时。
- **握手残余交回数据泵**：目标端率先推送的数据（SSH banner 等）不再丢失。
- **httpUDP 坏帧不再活锁**：解码失败时旧实现不消费字节，缓冲区永远卡在同一前缀，会话既不报错也不断开。现在直接终止并计数。
- **IPv4-mapped 地址族规范化**：双栈 socket 的 `recv_from` 会把 v4 对端报成 `::ffff:a.b.c.d`，旧实现按 IPv6（addr_type=3）写回帧，客户端解出的对端地址族错误。
- **SOCKS5 UDP 来源白名单按 IP 判定**：按 `IP:port` 精确匹配会把所有正常客户端全部拒绝（UDP 源端口必然不同于 TCP 控制端口）。
- **`SO_ORIGINAL_DST` 环路防护**：Android 内核即使没有 NAT 规则也会让该选项返回成功，旧实现据此可能把「自己的监听地址」当成转发目标造成自连死循环。
- **XOR 向量化路径的未对齐裸指针解引用（UB）** 已移除，改为对齐安全的分块处理。
- **DNS 应答游标**：`tcpDNS` 会话的收发两个方向各自维护连续密钥流；旧实现对每个响应都从 0 重新混淆，一条连接复用第二个查询必然解不开。
- **DNS 竞速任务全部带超时并 abort 落败方**：不再悬挂 socket/fd 直至 EMFILE。
- **`msghdr`/`msg_controllen` 的可移植性**：musl 与 bionic 的 `msghdr` 含私有 padding 字段，结构体字面量写法在这两个目标上直接编译失败。

### 变更（行为与默认值）

- **配置解析失败即拒绝启动**（新增 `--allow-defaults` 显式降级）。默认口令为空 = 明文开放代理，静默回落不可接受。
- **服务端默认拒绝回源到私网/环回/链路本地/云元数据**；`allow_private_targets` / `allow_target_cidrs` 显式放行。
- **`enable_httpdns` 默认 false**：公开递归解析器有滥用面。
- **删除 TUN 虚拟网卡路径**：旧实现只转发 UDP/53、其余 IP 报文全部丢弃，挂上 `tunDev` 等于断网。代理统一走 REDIRECT / TPROXY（`--mode`、`tproxy_mode` 可配）。
- **新增隧道复用**（`outbound::mux`）：一条长连接承载同一目标的多个并发 DNS/httpUDP 请求 + 本地 DNS 缓存。
- **`client.json` 新增**：`dns_mode`、`dns_upstream`、`block_ipv6`、`dns_cache_size`、`enable_udp_tunnel`、`tproxy_mode`、`socks5_udp_listen`、`buffer_pool_cap`、`session_max_age_seconds`。
- **`config.json` 新增**：`max_connections`、`max_connections_per_ip`、`handshake_timeout`、`dial_timeout`、`workers`、`ipv6_only`、`transparent`、`enable_httpdns`、`dns_upstream`、`allow_private_targets`、`allow_target_cidrs`、`default_target_port`、`header_host`。
- CLI 参数优先级改为 **命令行 > 配置文件 > 内置默认**（旧版 `default_value` 使配置文件项永不生效）。
- 客户端出站启用 `TCP_FASTOPEN_CONNECT`（旧版只在服务端开 TFO，所谓 0-RTT 从未生效）；连接加 `SO_KEEPALIVE`/`TCP_KEEPIDLE`。
- 数据泵下沉到 `cns-core::transport::pump`，服务端与客户端共用，半关闭语义与缓冲池统一。
- 服务端默认优雅停机（排水窗口 + 计数），不再 `ctrl_c` 后硬切。
- 服务端产物 `*-linux-musl` 真静态；客户端产物 `aarch64-linux-android`（bionic）。**产物只保存在仓库根目录一份**。

### 安全

- SOCKS5 UDP relay 增加来源白名单，并在控制连接关闭时解除登记（避免成为开放 UDP 反射器）。
- 服务端目标地址守卫（SSRF）。
- `install.sh` 二进制必须通过 `sha256sums.txt` 校验；本地探测拒绝 Android/bionic 产物装到 Linux；更新走 Releases-only，并修复覆盖运行中二进制导致的 `ETXTBSY`。

### 文档

- README 与实现逐条对齐，删除无法复核的宣传数字，改为引用 `scripts/bench.sh` 的可复现方法（含一份实测输出）。
- 明确 XOR 是**混淆**而非加密，并说明已知明文恢复密钥流的前提。
- 补齐 `LICENSE`（此前 README 挂着 MIT badge 但仓库无许可证文件）。

### 测试

- 集成测试改为启动**真实** `RunningServer`（旧测试手搓 mock，与被测代码不同源）。
- 新增回归用例：双栈 IPv4 可达、粘包不丢、8 并发查询只用 1 条连接、坏帧终止会话、IPv4-mapped 规范化、SOCKS5 UDP ASSOCIATE 应答、配置 fail-fast、私网目标拒绝、短 HTTP 前缀不误判 UDP。
- `cargo clippy --workspace --all-targets -- -D warnings` 与 `cargo fmt --check` 全绿。

## 0.1.x

- 初始 Rust 重构：workspace 三组件、Magisk/KernelSU 模块、协议双向兼容。
