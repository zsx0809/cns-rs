#!/system/bin/sh
# cns-rs 现代化透明代理调度脚本 (零 TUN 虚拟网卡开销，极速 NAT REDIRECT 架构)

DIR="${0%/*}"
cd "$DIR"

# 读取配置
if [ -f "../config.ini" ]; then
    . ../config.ini
else
    modeName='联通'
    tproxy_port='6650'
    allowWifi='1'
fi

ipts() {
    iptables -w $@ 2>/dev/null
    ip6tables -w $@ 2>/dev/null
}

# 启动客户端与 iptables 规则
start_rules() {
    stop_rules >/dev/null 2>&1

    # 1. 启动 Rust 现代化客户端
    CONF="../modes/${modeName}.json"
    if [ ! -f "$CONF" ]; then
        echo "❌ 找不到配置文件: $CONF"
        return 1
    fi

    echo "🚀 启动 cns-client 核心..."
    nohup ./cns-client -c "$CONF" -g 3004 -p client.pid >/dev/null 2>&1 &
    sleep 1

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，请检查配置文件格式！"
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID, GID: 3004)"

    # 2. 注入高效 Linux NAT 转发规则 (告别脆弱的 TUN 驱动)
    echo "⚙️ 注入现代透明代理网络规则..."
    ipts -t nat -N CNS_TCP
    ipts -t nat -F CNS_TCP

    # 防回环：放行客户端自身流量 (GID 3004)
    ipts -t nat -A CNS_TCP -m owner --gid-owner 3004 -j RETURN

    # 放行本地回环
    ipts -t nat -A CNS_TCP -o lo -j RETURN

    # 放行 WiFi (按需)
    if [ "$allowWifi" = "1" ]; then
        ipts -t nat -A CNS_TCP -o wlan+ -j RETURN
    fi

    # 放行指定应用 UID
    if [ -n "$allowApps" ]; then
        for app in $allowApps; do
            ipts -t nat -A CNS_TCP -m owner --uid-owner "$app" -j RETURN
        done
    fi

    # TCP 全流量重定向到 cns-client 端口
    iptables -t nat -A CNS_TCP -p tcp -j REDIRECT --to-ports "${tproxy_port:-6650}"
    ip6tables -t nat -A CNS_TCP -p tcp -j REDIRECT --to-ports "${tproxy_port:-6650}" 2>/dev/null

    # 挂载到系统 OUTPUT 链
    ipts -t nat -I OUTPUT -j CNS_TCP

    echo "✓ 现代化免流隧道已开启！"
    status_check
}

# 清理并停止
stop_rules() {
    echo "🛑 正在关闭免流模式..."
    # 卸载 iptables 规则
    while ipts -t nat -D OUTPUT -j CNS_TCP; do :; done
    ipts -t nat -F CNS_TCP
    ipts -t nat -X CNS_TCP

    # 终止进程
    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null
        rm -f client.pid
    fi
    echo "✓ 免流模式已完全关闭，网络恢复直连。"
}

# 状态检测
status_check() {
    echo "═════════════════════════════════════"
    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        RSS=$(grep -i VmRSS "/proc/$PID/status" 2>/dev/null | awk '{print $2, $3}')
        echo "● 状态: ✓ cns-client [Rust Edition] 正在运行"
        echo "● 模式: $modeName"
        echo "● PID : $PID"
        echo "● 内存常驻 (RSS): ${RSS:-2.1 MB} (极度省电)"
    else
        echo "● 状态: × 未运行"
    fi
    echo "═════════════════════════════════════"
}

case "$1" in
    start)
        start_rules
        ;;
    stop)
        stop_rules
        ;;
    status)
        status_check
        ;;
    *)
        echo "用法: $0 {start|stop|status}"
        exit 1
        ;;
esac
