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

# ==============================================================================
# 安全加固：排查并修复 /data/adb/modules/ 中可能导致 KernelSU LazyColumn 崩溃的重复模块
#
# 背景说明：
# KernelSU v3.2.x 模块列表采用 Jetpack Compose LazyColumn 渲染，列表 key 绑定 module.id。
# 当 /data/adb/modules/ 下存在同名备份目录（如 *.bak, *.old）或升级遗留的重复 ID 目录时，
# Compose 会直接抛出 java.lang.IllegalArgumentException: Key "xxx" was already used，
# 导致用户点击模块页面时 100% 闪退崩溃。
# ==============================================================================
fix_ksu_duplicate_modules() {
    local modules_dir="/data/adb/modules"
    local backup_dir="/data/adb/modules_backup"

    [ -d "$modules_dir" ] || return 0

    ui_print "- 正在检查 /data/adb/modules/ 模块目录健康状态与重复 ID..."
    mkdir -p "$backup_dir"

    # 1. 扫描并隔离常见备份命名后缀的模块目录（如 *.bak, *_bak, *.old, *_old, *.backup, *_backup 等）
    for dir in "$modules_dir"/*; do
        [ -d "$dir" ] || continue
        [ "$dir" = "$MODPATH" ] && continue
        local dirname="${dir##*/}"

        case "$dirname" in
            *.bak|*_bak|*.old|*_old|*.backup|*_backup|*.orig|*_orig)
                if [ -f "$dir/module.prop" ]; then
                    ui_print "! 发现冲突备份模块目录: $dirname"
                    local dest="$backup_dir/${dirname}_$(date +%Y%m%d%H%M%S)"
                    if mv "$dir" "$dest" 2>/dev/null; then
                        ui_print "  -> 已安全隔离至: $dest"
                        ui_print "  -> 成功排除 KernelSU 重复 Key (LazyColumn) 闪退风险！"
                    fi
                fi
                ;;
        esac
    done

    # 2. 全盘排查重复 module.prop 中的 id（防止任意不同目录共用相同 id）
    local seen_ids=""
    for prop in "$modules_dir"/*/module.prop; do
        [ -f "$prop" ] || continue
        local m_dir="${prop%/module.prop}"
        [ "$m_dir" = "$MODPATH" ] && continue
        local m_name="${m_dir##*/}"

        local m_id
        m_id=$(grep -E '^id=' "$prop" 2>/dev/null | head -n 1 | cut -d '=' -f 2 | tr -d ' \r\n')
        [ -n "$m_id" ] || continue

        # 检查是否已记录过该 ID
        case " $seen_ids " in
            *" $m_id:"*)
                local prev_dir=""
                for pair in $seen_ids; do
                    case "$pair" in
                        "$m_id:"*) prev_dir="${pair#*:}" ;;
                    esac
                done

                ui_print "! 警告: 检测到重复模块 ID: [$m_id]"
                ui_print "  现有模块目录: $prev_dir"
                ui_print "  冲突模块目录: $m_name"

                local to_move="$m_dir"
                local to_move_name="$m_name"
                # 若当前目录名就是标准 id，而旧记录不是，则优先保留标准命名的目录
                if [ "$m_name" = "$m_id" ] && [ "$prev_dir" != "$m_id" ] && [ -d "$modules_dir/$prev_dir" ]; then
                    to_move="$modules_dir/$prev_dir"
                    to_move_name="$prev_dir"
                    seen_ids=$(echo "$seen_ids" | sed "s/$m_id:$prev_dir/$m_id:$m_name/")
                fi

                local dest="$backup_dir/${to_move_name}_dup_$(date +%Y%m%d%H%M%S)"
                if mv "$to_move" "$dest" 2>/dev/null; then
                    ui_print "  -> 已自动将冲突目录迁移至: $dest"
                    ui_print "  -> 修复 Compose LazyColumn 重复 Key 崩溃完成。"
                fi
                ;;
            *)
                seen_ids="$seen_ids $m_id:$m_name"
                ;;
        esac
    done
}

# 执行安全检查
fix_ksu_duplicate_modules

# 2. 保留用户已有配置（升级安装不冲掉真实节点与模式）
OLD_MOD="/data/adb/modules/cns_rs"
if [ -d "$OLD_MOD" ] && [ "$MODPATH" != "$OLD_MOD" ]; then
    if [ -d "$OLD_MOD/modes" ]; then
        ui_print "- 检测到已有模式配置，合并保留（同名的新模式文件不覆盖）"
        mkdir -p "$MODPATH/modes"
        cp -rn "$OLD_MOD/modes/"* "$MODPATH/modes/" 2>/dev/null || true
    fi
    if [ -f "$OLD_MOD/config.ini" ]; then
        ui_print "- 保留已有 config.ini"
        cp -f "$OLD_MOD/config.ini" "$MODPATH/config.ini" 2>/dev/null || true
    fi
fi

# 3. 权限：脚本与二进制 0755，配置/文档 0644
# 兼容降级定义
if ! command -v set_perm >/dev/null 2>&1; then
    set_perm() {
        chown "$2:$3" "$1" 2>/dev/null || true
        chmod "$4" "$1" 2>/dev/null || true
    }
fi
if ! command -v set_perm_recursive >/dev/null 2>&1; then
    set_perm_recursive() {
        chown -R "$2:$3" "$1" 2>/dev/null || true
        find "$1" -type d -exec chmod "$4" {} + 2>/dev/null || true
        find "$1" -type f -exec chmod "$5" {} + 2>/dev/null || true
    }
fi

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

# 5. 便利软链接（指向最终模块安装路径，严禁在 /data/adb/modules 内部创建任何符号链接或副本）
FINAL_PATH="/data/adb/modules/cns_rs"
if [ ! -e "/data/免流模式" ] || [ -L "/data/免流模式" ]; then
    ln -sf "$FINAL_PATH" "/data/免流模式" 2>/dev/null || true
fi

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
