#!/system/bin/sh
# KernelSU / APatch / Magisk WebUI Action 一键开关免流
MODDIR="${0%/*}"
cd "$MODDIR" || exit 1

PID=$(cat Core/client.pid 2>/dev/null)
if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
    echo "🛑 正在关闭 cns-rs 免流代理..."
    "$MODDIR/Core/cns_rules.sh" stop
    echo "✓ 已成功关闭免流模式。"
else
    echo "🚀 正在开启 cns-rs 免流代理..."
    "$MODDIR/Core/cns_rules.sh" start
fi
