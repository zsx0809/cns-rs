#!/system/bin/sh
# KernelSU / APatch / Magisk WebUI Action 一键开关免流
#
# 特性：
# 1. 严格防重入：使用 PID 锁，防止用户频繁连点导致 iptables 竞争或重复启动
# 2. 健壮路径解析：自动定位模块真实路径，容忍符号链接与不同调用环境
# 3. 完整状态反馈：输出清晰的执行日志，始终安全退出 (exit 0)

# 1. 解析真实路径并切换目录
MODDIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -z "$MODDIR" ] && MODDIR="/data/adb/modules/cns_rs"
if ! cd "$MODDIR" 2>/dev/null; then
    echo "✗ 错误: 无法进入模块目录 $MODDIR"
    exit 0
fi

# 2. 防重入保护
LOCK_FILE="/dev/cns_action.lock"
if [ -f "$LOCK_FILE" ]; then
    OLD_PID=$(cat "$LOCK_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && [ -d "/proc/$OLD_PID" ]; then
        echo "⏳ 提示: 上一次开关操作仍在执行中 (PID: $OLD_PID)，请稍候..."
        exit 0
    fi
fi
echo "$$" > "$LOCK_FILE" 2>/dev/null
trap 'rm -f "$LOCK_FILE" 2>/dev/null' EXIT INT TERM

# 3. 核心调度脚本校验
RULES="$MODDIR/Core/cns_rules.sh"
if [ ! -f "$RULES" ]; then
    echo "✗ 错误: 找不到核心规则脚本: $RULES"
    exit 0
fi
[ -x "$RULES" ] || chmod 0755 "$RULES" 2>/dev/null

# 4. 状态判断与操作执行
PID=""
[ -f "$MODDIR/Core/client.pid" ] && PID=$(cat "$MODDIR/Core/client.pid" 2>/dev/null)

if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
    echo "=========================================="
    echo "🛑 正在关闭 cns-rs 免流代理 (PID: $PID)..."
    echo "=========================================="
    if "$RULES" stop; then
        echo "✓ 免流代理及防火墙规则已成功关闭。"
    else
        echo "⚠️ 关闭过程产生警告，请检查网络。"
    fi
else
    echo "=========================================="
    echo "🚀 正在开启 cns-rs 免流代理..."
    echo "=========================================="
    if "$RULES" start; then
        echo "✓ 免流代理已成功启动！"
    else
        echo "✗ 启动失败，请检查配置文件与 Core/client.log。"
    fi
fi

exit 0
