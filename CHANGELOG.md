# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

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
