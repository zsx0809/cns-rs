# shellcheck disable=SC2034  # SKIPUNZIP / MODPATH / ARCH / VERSION 由 Magisk 安装器注入
SKIPUNZIP=0

# 1. 架构检测（仅支持 64 位 ARM）
if [ "$ARCH" != "arm64" ]; then
    ui_print "***********************************************"
    ui_print "! 错误: 本模块仅支持 ARM64 (aarch64) 设备架构！"
    ui_print "! 当前设备架构: $ARCH"
    ui_print "***********************************************"
    abort "不支持的 CPU 架构"
fi

ui_print "- 部署 cns-rs 透明代理模块 (v$VERSION)"
ui_print "- 作者: zsx0809 | https://github.com/zsx0809/cns-rs"

# 2. 保留用户已有配置（升级安装不冲掉真实节点与模式）
OLD_MOD="/data/adb/modules/cns_rs"
if [ -d "$OLD_MOD/modes" ]; then
    ui_print "- 检测到已有模式配置，合并保留（同名的新模式文件不覆盖）"
    mkdir -p "$MODPATH/modes"
    cp -rn "$OLD_MOD/modes/"* "$MODPATH/modes/" 2>/dev/null
fi
if [ -f "$OLD_MOD/config.ini" ]; then
    ui_print "- 保留已有 config.ini"
    cp -f "$OLD_MOD/config.ini" "$MODPATH/config.ini"
fi

# 3. 权限：脚本与二进制 0755，配置/文档 0644
#    （旧版对 README/json 也设 0755，属权限过宽）
set_perm_recursive "$MODPATH" 0 0 0755 0644
for f in customize.sh service.sh action.sh start.sh stop.sh status.sh 开启.sh 关闭.sh 检测.sh; do
    [ -f "$MODPATH/$f" ] && set_perm "$MODPATH/$f" 0 0 0755
done
set_perm "$MODPATH/Core/cns_rules.sh" 0 0 0755
set_perm "$MODPATH/Core/cns-client" 0 0 0755

# 4. SELinux：/data/adb/modules 下的文件由 Magisk/KernelSU 自行处理上下文，
#    这里不强行 chcon（写错反而会让二进制在 Enforcing 下不可执行）。
#    仅在检测到 restorecon 可用时做一次温和修复。
if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$MODPATH" 2>/dev/null || true
fi

# 5. 便利软链接
[ -d "/data/免流模式" ] || ln -sf "$MODPATH" "/data/免流模式" 2>/dev/null

# 6. 自检：二进制真的能跑（避免刷入成功但一开就废）
if "$MODPATH/Core/cns-client" --version >/dev/null 2>&1; then
    ui_print "- ✓ 二进制自检: $("$MODPATH/Core/cns-client" --version 2>/dev/null)"
else
    ui_print "- ✗ 警告: cns-client 无法执行（架构或 linker 不匹配），模块将不可用"
fi

# 7. 内核能力探测（只提示，不阻断）
if [ -e "/proc/net/xt_recent" ] || iptables -w -t nat -L >/dev/null 2>&1; then
    ui_print "- ✓ nat 表可用（REDIRECT 模式）"
else
    ui_print "- ! iptables nat 不可用，请确认内核带 xt_REDIRECT"
fi
if ip6tables -w -t nat -L >/dev/null 2>&1; then
    ui_print "- ✓ IPv6 nat 可用"
else
    ui_print "- ! IPv6 nat 不可用（多数 ROM 正常，脚本会自动跳过 v6）"
fi

ui_print "==============================================="
ui_print "🎉 刷入完成"
ui_print ""
ui_print "1) 编辑节点配置（必填）:"
ui_print "   /data/adb/modules/cns_rs/modes/联通.json"
ui_print "   改 cns_server / cns_password 两项即可，"
ui_print "   端口与 DNS 都由该文件决定（唯一真源）。"
ui_print ""
ui_print "2) 开关（Termux / 终端模拟器）:"
ui_print "   su -c /data/adb/modules/cns_rs/开启.sh"
ui_print "   su -c /data/adb/modules/cns_rs/关闭.sh"
ui_print "   su -c /data/adb/modules/cns_rs/检测.sh"
ui_print "   （ASCII 别名 start.sh / stop.sh / status.sh 等价）"
ui_print ""
ui_print "3) KSU / APatch 可直接点模块列表里的【操作】一键开关。"
ui_print "==============================================="
