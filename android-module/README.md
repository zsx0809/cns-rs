# cns-rs Android 模块

安装路径：`/data/adb/modules/cns_rs/`（另有软链接 `/data/免流模式/`）

## 配置只有一个真源

运行参数全部来自 `modes/<模式名>.json`。**端口不要写在 `config.ini` 里**——
脚本会从 JSON 推导 `tproxy_listen` / `dns_listen` / `socks5_listen` 的端口，并同时写进
iptables 与 `cns-client` 命令行，因此不可能出现「防火墙抓一个端口、程序听另一个端口」。

必改两项：

```jsonc
{
  "cns_server": "你的服务端IP:1254",     // ← 必填
  "cns_password": "与服务端一致的口令",   // ← 必填
  ...
}
```

`config.ini` 只负责调度：模式选择、开机自启、WiFi 放行、QUIC 拦截、放行 App 列表。

## 开关

```sh
su -c /data/adb/modules/cns_rs/开启.sh      # 或 start.sh
su -c /data/adb/modules/cns_rs/关闭.sh      # 或 stop.sh
su -c /data/adb/modules/cns_rs/检测.sh      # 或 status.sh（含 4 项连通性自检）
```

KernelSU / APatch 可在模块列表点【操作 / Action】一键开关。

> 中文文件名在个别终端 + `su -c` 引号嵌套下编码不稳，因此同时提供 ASCII 别名
> `start.sh` / `stop.sh` / `status.sh`，内容与中文名脚本完全等价。

## 劫持方式

| `config.ini` 中 `tproxy_mode` | 需要的内核能力 | 说明 |
| :--- | :--- | :--- |
| `redirect`（默认） | `xt_REDIRECT` | Android 内核最普遍支持，绝大多数 ROM 可用 |
| `tproxy` | `xt_TPROXY` + `ip rule` 策略路由 | 能拿到原始目的地址与真实源端口，支持非本地 socket；部分 ROM 缺模块 |

`config.ini` 的 `tproxy_mode` 与 `modes/*.json` 的 `tproxy_mode` **必须写成同一个值**，
否则脚本会在启动前中止（详见下面「已知取舍与联动关系」）。

## 防回环机制

`cns-client` 以 GID 3004 运行，iptables 第一条规则就是
`-m owner --gid-owner 3004 -j RETURN`，同时放行「服务端 IP/端口」与「代理自己的监听端口」，
这样程序自己的出站连接不会被自己再抓一遍。

程序内部的顺序是：**先建好所有监听 socket，之后才 `setgid`**。
顺序反了会导致监听 socket 自身被 REDIRECT 抓住，直接死循环。

## 已知取舍与联动关系

### 唯一真源只有一份

`modes/<模式名>.json` 是**运行参数唯一真源**：`cns-client` 直接读它（`-c ../modes/X.json`）。
`config.ini` 只负责「模式选择 + 调度开关」。

脚本会把 JSON 里的值**翻译成命令行参数**再交给客户端（`-t` / `--mode` / `--dns-listen` / `-g`），
所以下面这些字段存在「两边都写」的情况，只改一边不会报错，但会让 iptables 与客户端各按一套规则跑：

| 参数 | 文件 A（决定 iptables 规则） | 文件 B（客户端自己会读） | 改错一边的后果 | v0.3.1 的处理 |
| :--- | :--- | :--- | :--- | :--- |
| 劫持方式 | `config.ini` → `tproxy_mode` | `modes/*.json` → `tproxy_mode` | iptables 用 TPROXY、客户端按 redirect 解析原始目的（或反之）→ **全网断流且 client.log 无任何报错** | **两边不一致直接中止启动**，并打印该改哪个文件的哪个字段 |
| 透明代理端口 | `config.ini` → `tproxy_port`（可留空） | `modes/*.json` → `tproxy_listen` | 不留空时脚本会用 `-t` 把客户端拉过去，运行期仍一致；但手敲命令启动客户端（不带 `-t`）就会听在 JSON 的端口 → 分叉 | 不一致时**警告**并提示同步 JSON（因为脚本确实做了同步，属设计内的覆盖） |
| DNS 端口 | 脚本 `--dns-listen 0.0.0.0:<端口>` | `modes/*.json` → `dns_listen` | 同上，脚本强制覆盖，实际以 JSON 端口为准 | 端口不一致报错；JSON 缺该字段则警告 |
| 防回环 GID | 脚本 `-g 3004` + iptables `--gid-owner 3004` | `modes/*.json` → `gid` | JSON 的 `gid` **永远不生效**（被 `-g` 覆盖）；写别的值不会出问题，但会误导 | 不一致时警告 |
| 服务端 | 无（只有 JSON） | `modes/*.json` → `cns_server` | 放行端口、探活目标都由它推导 | 解析失败即中止 |

`tproxy_mode` 允许写 `auto`：客户端会「先试 `SO_ORIGINAL_DST`，失败再看 `local_addr`」，
能兼容 REDIRECT 与 TPROXY 两套规则，因此 `auto` 不算冲突（脚本仍会按 `redirect` 或 `tproxy` 二选一生成规则）。

### 三条已知取舍（v0.3.1 记录，未改默认行为）

1. **QUIC 拦截与 `block_ipv6` 联动。**
   `blockQuic=1` 且模式 JSON 的 `block_ipv6=true` 时，UDP/443 用 `-j DROP`（软失败）；
   其余情况维持 `-j REJECT --reject-with icmp-port-unreachable`。
   原因：`block_ipv6=true` 已经把 AAAA 打成 NODATA（客户端默认值就是 `true`），
   双栈 App 若再收到 ICMP 不可达，部分实现会判定为「网络错误」直接报错而不回退；
   `DROP` 表现为「没有响应」，App 按超时回退到 TCP/443 —— 而 TCP/443 正是被劫持进隧道的路径。
   `stop` 路径把 DROP 与 REJECT 两种形态**都**清掉，切换该开关不会留下残留规则。

2. **`redirect` 模式下 `tproxy_port` 的 UDP 监听没有流量。**
   出厂规则里只有 `-p tcp -j REDIRECT --to-ports 7750`，UDP 只导了 53（DNS）。
   客户端在 `enable_udp_tunnel=true` 时仍会在 7750 起一个 UDP 透明代理 socket，
   但 `redirect` 模式下没有规则把普通 UDP 送给它，因此它只是「占一个 fd + 一个收包循环」。
   `tproxy` 模式下脚本确实会 `-p udp -j TPROXY --on-port 7750`，那时它才有用。
   **默认值未改动**：打开 REDIRECT 的 UDP 导流会真实改变所有在网设备的 UDP 行为，
   需要客户端侧配套验证（REDIRECT 语义下取原始目的地址走 `IP_RECVORIGDSTADDR`），留待单独评估。

3. **IPv6：`redirect` 模式不劫持 v6。**
   本机实测（Android 内核）**`ip6tables` 没有 `nat` 表**，v6 无法做 REDIRECT；
   脚本据此把 v6 能力拆成三个探测位（`nat` / `mangle` / `filter`）：
   - `redirect` 模式：v6 不劫持（v6 流量直连，行为与旧版一致）；
   - `tproxy` 模式：v6 走 mangle TPROXY（能力位单独判断）；
   - QUIC 拦截落在 `filter` 表，与 `nat` 无关，因此单独用 filter 探测 ——
     旧版用 nat 探测的结果去判断这条 filter 规则，导致它在没有 v6 nat 的设备上永远是死代码。

### 改错了怎么判断

开启脚本会先跑一致性自检，输出形如：

```
❌ 劫持方式的两个真源冲突（会导致全断网且无任何报错）：
     config.ini        : tproxy_mode='redirect'  ← 脚本按它生成 iptables，并用 --mode 传给客户端
     ../modes/联通.json : "tproxy_mode": "tproxy"
   → 修法（二选一，改到两边相同为止）：
       1) 把 ../modes/联通.json 的 "tproxy_mode" 改成 "redirect"
       2) 或把 config.ini 的 tproxy_mode 改成 'tproxy'
```

自检不通过时**不会**改动任何 iptables 规则、也不会启动 `cns-client`（网络保持原状），
所以「开启失败」是安全的失败方式：照着提示改完文件再开启一次即可。

## 检测项

`检测.sh` 依次验证：DNS 解析（UDP 53）→ HTTP（TCP 80）→ HTTPS（TLS 443）→ 服务端端口可达。
任何一项失败都会打印具体状态码，并提示 `client.log` 里的异常条数。

## 排错

| 现象 | 原因 | 处理 |
| :--- | :--- | :--- |
| 开启后全网断流 | 回环：服务端端口没被放行 | 确认 `modes/*.json` 的 `cns_server` 端口写对（脚本会自动放行） |
| 网页图片时好时坏 | DNS 应答粘包/隧道游标错位（v0.1.x 的缺陷） | 升级到 v0.2.0 |
| IPv6-only 网络解析失败 | `block_ipv6: true` 拦截了 AAAA | 改成 `false` |
| `Raw DNS reply failed` | 无 `CAP_NET_RAW` 或内核不支持 `IP_TRANSPARENT` | 必须以 root 运行；模块脚本已用 root |
| 刷入后 `cns-client` 无法执行 | 非 arm64 设备 | 本模块仅支持 aarch64 |
