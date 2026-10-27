# cns-rs 现代化免流透明代理模块 (Magisk / KernelSU / APatch / Termux)

* **作者**：`zsx0809`
* **项目地址**：[https://github.com/zsx0809/cns-rs](https://github.com/zsx0809/cns-rs)
* **架构**：ARM64 (aarch64)

基于纯异步 Rust（Tokio + Socket2）全新重构的工业级 CuteBi 手机免流客户端透明代理套件。采用内核级 NAT REDIRECT 架构，全面告别原版 C 客户端硬编码 15 秒超时自杀、脆弱易崩溃的 `tunDev` 虚拟网卡及 CPU 高占用的历史顽疾。

---

## 📂 模块安装路径

刷入 Magisk / KernelSU / APatch 模块后，文件位于手机系统存储中的：
```text
/data/adb/modules/cns_rs/
(同时自动创建软链接: /data/免流模式/)
```

---

## 📝 首次使用三步指引

### 1. 配置免流节点信息
使用 **MT管理器** 或任意文本编辑器打开模式配置文件：
`/data/adb/modules/cns_rs/modes/联通.json`

将模板中的服务器信息修改为您自己的真实节点：
```json
{
  "socks5_listen": "127.0.0.1:1080",
  "tproxy_listen": "[::]:6650",
  "gid": 3004,
  "cns_server": "1.2.3.4:13872",
  "cns_password": "你的连接密码",
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "header_host": "mclient.alipay.com",
  "enable_tfo": true,
  "timeout_seconds": 60
}
```

### 2. 模式选择与开机自启
在 `/data/adb/modules/cns_rs/config.ini` 中确认：
```ini
modeName='联通'       # 对应 modes/ 目录下 json 文件名
autoStart='0'        # 设为 1 则开机自动启动免流
```

### 3. 一键启停与自检
在终端（Termux / 终端模拟器）中执行：
* **开启免流**：`su -c /data/adb/modules/cns_rs/开启.sh`
* **关闭免流**：`su -c /data/adb/modules/cns_rs/关闭.sh`
* **状态自检**：`su -c /data/adb/modules/cns_rs/检测.sh`

> 💡 **KernelSU / APatch 用户特权**：在管理器模块列表中，可直接点击本模块的【操作 / Action】按钮，实现免流服务的一键开关！
