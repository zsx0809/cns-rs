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

## 防回环机制

`cns-client` 以 GID 3004 运行，iptables 第一条规则就是
`-m owner --gid-owner 3004 -j RETURN`，同时放行「服务端 IP/端口」与「代理自己的监听端口」，
这样程序自己的出站连接不会被自己再抓一遍。

程序内部的顺序是：**先建好所有监听 socket，之后才 `setgid`**。
顺序反了会导致监听 socket 自身被 REDIRECT 抓住，直接死循环。

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
