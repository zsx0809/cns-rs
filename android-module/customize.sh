SKIPUNZIP=0

# 1. 架构检测 (仅支持 64 位 ARM)
if [ "$ARCH" != "arm64" ]; then
    ui_print "***********************************************"
    ui_print "! 错误: 本模块仅支持 ARM64 (aarch64) 设备架构！"
    ui_print "! 当前设备架构: $ARCH"
    ui_print "***********************************************"
    abort "不支持的 CPU 架构"
fi

ui_print "- 正在部署 cns-rs 现代化免流透明代理模块..."
ui_print "- 作者: zsx0809"
ui_print "- GitHub: https://github.com/zsx0809/cns-rs"

# 2. 检查并保留用户已有配置 (升级安装防冲掉)
OLD_MOD="/data/adb/modules/cns_rs"
if [ -d "$OLD_MOD/modes" ]; then
    ui_print "- 检测到已存在的模式配置，正在自动备份合并..."
    mkdir -p "$MODPATH/modes"
    cp -rn "$OLD_MOD/modes/"* "$MODPATH/modes/" 2>/dev/null
fi
if [ -f "$OLD_MOD/config.ini" ]; then
    ui_print "- 保留已有 config.ini 配置..."
    cp -f "$OLD_MOD/config.ini" "$MODPATH/config.ini"
fi

# 3. 设置核心文件与脚本权限
ui_print "- 正在校验并授予执行权限 (0755)..."
set_perm_recursive "$MODPATH" 0 0 0755 0755
set_perm "$MODPATH/Core/cns-client" 0 0 0755
set_perm "$MODPATH/Core/cns_rules.sh" 0 0 0755
set_perm "$MODPATH/开启.sh" 0 0 0755
set_perm "$MODPATH/关闭.sh" 0 0 0755
set_perm "$MODPATH/检测.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755 2>/dev/null

# 4. 创建软链接便利访问 (可选)
if [ ! -d "/data/免流模式" ]; then
    ln -sf "$MODPATH" "/data/免流模式" 2>/dev/null
fi

ui_print "==============================================="
ui_print "🎉 cns-rs 模块刷入成功！"
ui_print "-----------------------------------------------"
ui_print "📂 模块主目录路径:"
ui_print "   /data/adb/modules/cns_rs/"
ui_print "   (或便捷软链接: /data/免流模式/)"
ui_print ""
ui_print "📝 首次使用请按以下步骤配置:"
ui_print "   1. 使用 MT管理器 或 文本编辑器 打开:"
ui_print "      /data/adb/modules/cns_rs/modes/联通.json"
ui_print "   2. 将 YOUR_SERVER_IP 与 your_password_here"
ui_print "      修改为您自己的 CNS 服务端真实 IP 与密码。"
ui_print ""
ui_print "🚀 终端控制命令 (Termux / 终端模拟器):"
ui_print "   ● 开启免流: su -c /data/adb/modules/cns_rs/开启.sh"
ui_print "   ● 关闭免流: su -c /data/adb/modules/cns_rs/关闭.sh"
ui_print "   ● 状态检测: su -c /data/adb/modules/cns_rs/检测.sh"
ui_print ""
ui_print "💡 KSU / APatch 用户:"
ui_print "   可在管理器模块列表中直接点击【操作/Action】按钮"
ui_print "   实现免流服务的一键开关！"
ui_print "==============================================="
