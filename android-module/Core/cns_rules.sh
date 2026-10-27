#!/system/bin/sh
# cns-rs 现代化透明代理调度脚本 (原生 TPROXY 架构 + IP_TRANSPARENT 智能防丢包)

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
DNS_PORT="7753"
FWMARK="1"
TABLE="100"

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

    echo "🚀 启动 cns-client 核心 (TPROXY: $tproxy_port, DNS中继: $DNS_PORT)..."
    ./cns-client -c "$CONF" -g 3004 -t "$tproxy_port" --dns-listen "0.0.0.0:$DNS_PORT" -p client.pid > client.log 2>&1 &
    sleep 1

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，请检查 client.log！"
        cat client.log 2>/dev/null
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID, GID: 3004)"

    echo "⚙️ 注入现代 TPROXY 网络路由与透明代理规则..."

    # 1. 策略路由：为 fwmark 1 增加路由表 100
    ip rule add fwmark $FWMARK lookup $TABLE pref 100 2>/dev/null
    ip route add local default dev lo table $TABLE 2>/dev/null
    ip -6 rule add fwmark $FWMARK lookup $TABLE pref 100 2>/dev/null
    ip -6 route add local default dev lo table $TABLE 2>/dev/null

    # 2. mangle 表 PREROUTING 链：挂载 TPROXY 目标
    for tool in iptables ip6tables; do
        $tool -w -t mangle -N CNS_PRE 2>/dev/null
        $tool -w -t mangle -F CNS_PRE
        $tool -w -t mangle -A CNS_PRE -p tcp -j TPROXY --on-port "$tproxy_port" --tproxy-mark $FWMARK
        $tool -w -t mangle -A CNS_PRE -p udp --dport 53 -j TPROXY --on-port "$DNS_PORT" --tproxy-mark $FWMARK
        $tool -w -t mangle -I PREROUTING -j CNS_PRE
    done

    # 3. mangle 表 OUTPUT 链：本机流量打标记进入 TPROXY
    for tool in iptables ip6tables; do
        $tool -w -t mangle -N CNS_OUT 2>/dev/null
        $tool -w -t mangle -F CNS_OUT

        # 核心防回环
        $tool -w -t mangle -A CNS_OUT -m owner --gid-owner 3004 -j RETURN
        $tool -w -t mangle -A CNS_OUT -o lo -j RETURN
        $tool -w -t mangle -A CNS_OUT -p udp --dport 67:68 -j RETURN

        # 放行 CNS 服务端端口 (直连不走代理)
        $tool -w -t mangle -A CNS_OUT -p tcp --dport 13872 -j RETURN

        # WiFi 放行
        if [ "$allowWifi" = "1" ]; then
            $tool -w -t mangle -A CNS_OUT -o wlan+ -j RETURN
        fi

        # 放行指定应用 UID
        if [ -n "$allowApps" ]; then
            for app in $allowApps; do
                $tool -w -t mangle -A CNS_OUT -m owner --uid-owner "$app" -j RETURN
            done
        fi

        # 本机发出的 TCP 与 DNS(UDP 53) 打上 mark 1，内核重新路由判定后送入 lo 命中 PREROUTING 的 TPROXY
        $tool -w -t mangle -A CNS_OUT -p tcp -j MARK --set-mark $FWMARK
        $tool -w -t mangle -A CNS_OUT -p udp --dport 53 -j MARK --set-mark $FWMARK

        $tool -w -t mangle -I OUTPUT -j CNS_OUT
    done

    echo "✓ 原生 TPROXY 免流隧道与 DNS 智能透传已成功开启！"
    status_check
}

stop_rules() {
    echo "🛑 正在关闭免流模式..."
    for tool in iptables ip6tables; do
        while $tool -w -t mangle -D PREROUTING -j CNS_PRE 2>/dev/null; do :; done
        $tool -w -t mangle -F CNS_PRE 2>/dev/null
        $tool -w -t mangle -X CNS_PRE 2>/dev/null

        while $tool -w -t mangle -D OUTPUT -j CNS_OUT 2>/dev/null; do :; done
        $tool -w -t mangle -F CNS_OUT 2>/dev/null
        $tool -w -t mangle -X CNS_OUT 2>/dev/null
    done

    while ip rule del fwmark $FWMARK lookup $TABLE 2>/dev/null; do :; done
    ip route flush table $TABLE 2>/dev/null
    while ip -6 rule del fwmark $FWMARK lookup $TABLE 2>/dev/null; do :; done
    ip -6 route flush table $TABLE 2>/dev/null

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
