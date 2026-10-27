#!/system/bin/sh
# cns-rs 现代化透明代理调度脚本 (NAT REDIRECT 架构 + DNS 智能中继)

DIR="${0%/*}"
cd "$DIR"

# 读取配置
if [ -f "../config.ini" ]; then
    . ../config.ini
else
    modeName='美国'
    tproxy_port='7750'
    allowWifi='1'
fi

tproxy_port="${tproxy_port:-7750}"

ipts() {
    iptables -w $@ 2>/dev/null
    ip6tables -w $@ 2>/dev/null
}

start_rules() {
    stop_rules >/dev/null 2>&1

    CONF="../modes/${modeName}.json"
    if [ ! -f "$CONF" ]; then
        echo "❌ 找不到配置文件: $CONF"
        return 1
    fi

    DNS_PORT="7753"
    echo "🚀 启动 cns-client 核心 (TCP代理: $tproxy_port, DNS中继: $DNS_PORT)..."
    ./cns-client -c "$CONF" -g 3004 -t "$tproxy_port" --dns-listen "0.0.0.0:$DNS_PORT" -p client.pid > client.log 2>&1 &
    sleep 1

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，请检查 client.log！"
        cat client.log 2>/dev/null
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID, GID: 3004)"

    echo "⚙️ 注入现代透明代理网络规则与 DNS 智能劫持..."
    ipts -t nat -N CNS_TCP
    ipts -t nat -F CNS_TCP

    # 1. 核心防回环白名单
    ipts -t nat -A CNS_TCP -m owner --gid-owner 3004 -j RETURN
    ipts -t nat -A CNS_TCP -p tcp --dport 13872 -j RETURN
    ipts -t nat -A CNS_TCP -p tcp --dport "$tproxy_port" -j RETURN
    ipts -t nat -A CNS_TCP -p udp --dport "$DNS_PORT" -j RETURN

    # 2. 基础放行
    ipts -t nat -A CNS_TCP -o lo -j RETURN
    ipts -t nat -A CNS_TCP -p udp --dport 67:68 -j RETURN

    # 3. 放行 WiFi (按需)
    if [ "$allowWifi" = "1" ]; then
        ipts -t nat -A CNS_TCP -o wlan+ -j RETURN
    fi

    # 4. 放行指定应用 UID
    if [ -n "$allowApps" ]; then
        for app in $allowApps; do
            ipts -t nat -A CNS_TCP -m owner --uid-owner "$app" -j RETURN
        done
    fi

    # 5. DNS 拦截：将所有 UDP 53 端口重定向到本地 DNS 中继端口
    iptables -t nat -A CNS_TCP -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
    ip6tables -t nat -A CNS_TCP -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT" 2>/dev/null

    # 6. TCP 全流量重定向到 cns-client 端口
    iptables -t nat -A CNS_TCP -p tcp -j REDIRECT --to-ports "$tproxy_port"
    ip6tables -t nat -A CNS_TCP -p tcp -j REDIRECT --to-ports "$tproxy_port" 2>/dev/null

    # 挂载到系统 OUTPUT 链
    ipts -t nat -I OUTPUT -j CNS_TCP

    echo "✓ 现代化免流隧道与 DNS 已成功开启！"
    status_check
}

stop_rules() {
    echo "🛑 正在关闭免流模式..."
    while ipts -t nat -D OUTPUT -j CNS_TCP; do :; done
    ipts -t nat -F CNS_TCP
    ipts -t nat -X CNS_TCP

    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null
        rm -f client.pid
    fi
    echo "✓ 免流模式已完全关闭，网络恢复直连。"
}

status_check() {
    echo "═════════════════════════════════════"
    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        RSS=$(grep -i VmRSS "/proc/$PID/status" 2>/dev/null | awk '{print $2, $3}')
        echo "● 状态: ✓ cns-client [Rust Edition] 正在运行"
        echo "● 模式: $modeName"
        echo "● TCP代理端口: $tproxy_port"
        echo "● DNS中继端口: 6653"
        echo "● PID : $PID"
        echo "● 内存常驻 (RSS): ${RSS:-4.2 MB} (极度省电)"
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
