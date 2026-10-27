# cns-rs Android 极速免流模块 (透明代理架构)

本模块专为 Android Root 环境（Magisk / KernelSU / APatch / Termux Root）设计，采用现代化的 **Linux NAT REDIRECT / TProxy** 透明代理架构，**彻底抛弃了老旧、脆弱且极易发生分片丢包的 TUN 虚拟网卡**。

---

## ⚡ 核心优势

1. **零 TUN 网卡开销：** 不再创建 `tunDev`，直接由 Linux 内核 socket 层接管 TCP，零上下文切换，网速跑满基带上限，大幅降低发热和耗电。
2. **彻底解决 15 秒断流转圈：** 内置全新的纯 Rust 异步客户端 `cns-client`，切除硬编码自杀逻辑，跨国网络微抖动自动静默保活。
3. **极简运维与纯净代码：** 告别原版 10MB 冗余脚本，整个控制脚本仅几十行，支持标准的 `开启.sh`、`关闭.sh`、`检测.sh`。

---

## 🚀 使用方法

### 1. 配置免流参数
在 `modes/` 目录下编辑或新增你的免流节点配置（如 `modes/联通.json`）：
```json
{
  "cns_server": "你的服务器IP或域名:端口",
  "cns_password": "你的连接密码",
  "proxy_key": "Meng",
  "header_host": "mclient.alipay.com"
}
```

### 2. 选择当前使用的模式
在 `config.ini` 中修改 `modeName`：
```ini
modeName='联通'
```

### 3. 一键启停
* 启动免流：运行 `./开启.sh`
* 关闭免流：运行 `./关闭.sh`
* 状态检测：运行 `./检测.sh`
