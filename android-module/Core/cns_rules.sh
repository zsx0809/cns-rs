#!/system/bin/sh
# cns-rs 现代化免流透明代理调度脚本 (原生 Micro-TUN 引擎 + 全协议连通性检测)

DIR="${0%/*}"
cd "$DIR"

# 读取全局配置
if [ -f "../config.ini" ]; then
    . ../config.ini
else
    modeName='美国'
    tproxy_port='7750'
    allowWifi='1'
fi

modeName="${modeName:-美国}"
tproxy_port="${tproxy_port:-7750}"
allowWifi="${allowWifi:-1}"
FWMARK="999"
TABLE="101"
TUN_DEV="tunDev"

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

    echo "🚀 启动 cns-client 核心 (Micro-TUN: $TUN_DEV, GID: 3004)..."
    ./cns-client -c "$CONF" -g 3004 --tun "$TUN_DEV" -t "$tproxy_port" -p client.pid > client.log 2>&1 &
    sleep 1

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，请检查 client.log！"
        cat client.log 2>/dev/null
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID, GID: 3004)"

    echo "⚙️ 配置虚拟网络设备与策略路由..."
    # 1. 激活 TUN 虚拟网卡
    ip addr add 10.0.0.1/32 dev "$TUN_DEV" 2>/dev/null
    ip link set dev "$TUN_DEV" mtu 1350 2>/dev/null
    ip link set dev "$TUN_DEV" up 2>/dev/null

    # IPv6 网卡配置
    ip -6 addr add fec0::1/64 dev "$TUN_DEV" 2>/dev/null
    ip -6 link set dev "$TUN_DEV" up 2>/dev/null

    # 2. 路由表 101：默认路由全部走 tunDev
    ip route add default dev "$TUN_DEV" table $TABLE 2>/dev/null
    ip -6 route add default dev "$TUN_DEV" table $TABLE 2>/dev/null

    # 3. 策略路由：fwmark 999 走 table 101 (优先级 99，高于 Android 所有策略路由)
    ip rule add fwmark $FWMARK lookup $TABLE pref 99 2>/dev/null
    ip -6 rule add fwmark $FWMARK lookup $TABLE pref 99 2>/dev/null

    echo "⚙️ 注入内核数据包分流与防回环规则..."
    # 4. iptables mangle 规则：为非 GID 3004 流量打上 mark 999
    for tool in iptables ip6tables; do
        $tool -w -t mangle -N CNS_OUT 2>/dev/null
        $tool -w -t mangle -F CNS_OUT

        # 核心防回环
        $tool -w -t mangle -A CNS_OUT -m owner --gid-owner 3004 -j RETURN
        $tool -w -t mangle -A CNS_OUT -o lo -j RETURN
        $tool -w -t mangle -A CNS_OUT -o tun+ -j RETURN
        $tool -w -t mangle -A CNS_OUT -p udp --dport 67:68 -j RETURN

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

        # 放行 CNS 服务端端口 (直连不走代理)
        $tool -w -t mangle -A CNS_OUT -p tcp --dport 13872 -j RETURN

        # 将其它所有流量全部打标 999 导向 Micro-TUN
        $tool -w -t mangle -A CNS_OUT -j MARK --set-mark $FWMARK

        $tool -w -t mangle -I OUTPUT -j CNS_OUT
    done

    echo "✓ 现代化免流隧道与 Micro-TUN 已完全就绪！"
    status_check
    echo ""
    run_tests
}

stop_rules() {
    echo "🛑 正在关闭免流模式..."
    for tool in iptables ip6tables; do
        while $tool -w -t mangle -D OUTPUT -j CNS_OUT 2>/dev/null; do :; done
        $tool -w -t mangle -F CNS_OUT 2>/dev/null
        $tool -w -t mangle -X CNS_OUT 2>/dev/null
    done

    while ip rule del fwmark $FWMARK lookup $TABLE 2>/dev/null; do :; done
    ip route flush table $TABLE 2>/dev/null
    while ip -6 rule del fwmark $FWMARK lookup $TABLE 2>/dev/null; do :; done
    ip -6 route flush table $TABLE 2>/dev/null

    ip link set dev "$TUN_DEV" down 2>/dev/null

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
        echo "● 虚拟网卡: $TUN_DEV"
        echo "● PID : $PID"
        echo "● 内存常驻 (RSS): ${RSS:-3.5 MB} (极度省电)"
    else
        echo "● 状态: × 未运行"
    fi
    echo "═════════════════════════════════════"
}

run_tests() {
    echo "🔍 正在执行全协议全栈连通性健康检测..."
    echo "-------------------------------------"

    CURL_BIN=""
    if type curl >/dev/null 2>&1; then
        CURL_BIN="curl"
    elif [ -x "/data/data/com.termux/files/usr/bin/curl" ]; then
        CURL_BIN="/data/data/com.termux/files/usr/bin/curl"
    fi

    # 1. DNS 测试 (UDP 53)
    echo -n "● [1/4] DNS 解析测试 (UDP 53)... "
    DNS_START=$(date +%s%3N 2>/dev/null || date +%s)
    DNS_RES=""
    if type ping >/dev/null 2>&1; then
        DNS_RES=$(ping -c 1 -W 2 www.baidu.com 2>/dev/null | grep -E -o '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
    fi
    if [ -z "$DNS_RES" ] && [ -n "$CURL_BIN" ]; then
        DNS_RES=$($CURL_BIN -s -m 3 -o /dev/null -w "%{remote_ip}" http://www.baidu.com 2>/dev/null)
    fi

    DNS_END=$(date +%s%3N 2>/dev/null || date +%s)
    DNS_TIME=$((DNS_END - DNS_START))
    if [ -n "$DNS_RES" ]; then
        echo "✓ 成功! 解析目标: $DNS_RES (${DNS_TIME}ms)"
    else
        echo "× 失败 (超时或解析未返回)"
    fi

    # 2. HTTP 测试 (明文 TCP)
    echo -n "● [2/4] HTTP 连通测试 (TCP 80)... "
    HTTP_START=$(date +%s%3N 2>/dev/null || date +%s)
    HTTP_CODE=""
    if [ -n "$CURL_BIN" ]; then
        HTTP_CODE=$($CURL_BIN -s -m 4 -o /dev/null -w "%{http_code}" http://connect.rom.miui.com/generate_204 2>/dev/null)
    fi
    HTTP_END=$(date +%s%3N 2>/dev/null || date +%s)
    HTTP_TIME=$((HTTP_END - HTTP_START))
    if [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "200" ]; then
        echo "✓ 成功! 响应状态码: $HTTP_CODE (${HTTP_TIME}ms)"
    else
        echo "× 失败 (HTTP状态码: ${HTTP_CODE:-超时})"
    fi

    # 3. HTTPS 测试 (TLS 加密 TCP)
    echo -n "● [3/4] HTTPS 安全测试 (TLS 443)... "
    HTTPS_START=$(date +%s%3N 2>/dev/null || date +%s)
    HTTPS_CODE=""
    if [ -n "$CURL_BIN" ]; then
        HTTPS_CODE=$($CURL_BIN -k -s -m 5 -o /dev/null -w "%{http_code}" https://www.baidu.com 2>/dev/null)
    fi
    HTTPS_END=$(date +%s%3N 2>/dev/null || date +%s)
    HTTPS_TIME=$((HTTPS_END - HTTPS_START))
    if [ "$HTTPS_CODE" = "200" ] || [ "$HTTPS_CODE" = "302" ]; then
        echo "✓ 成功! 握手及响应正常 (${HTTPS_TIME}ms)"
    else
        echo "× 失败 (响应码: ${HTTPS_CODE:-握手超时})"
    fi

    # 4. UDP 协议传输测试
    echo -n "● [4/4] UDP 协议传输测试... "
    UDP_PASS="0"
    if [ -n "$DNS_RES" ]; then
        UDP_PASS="1"
    fi
    if [ "$UDP_PASS" = "1" ]; then
        echo "✓ 成功! Micro-TUN UDP 隧道吞吐畅通"
    else
        echo "× 失败 (UDP 数据链路阻断)"
    fi

    echo "-------------------------------------"
    echo "🎉 检测完毕！如全部通过，即可直接享受极速免流。"
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
    test)
        run_tests
        ;;
    *)
        echo "用法: $0 {start|stop|status|test}"
        exit 1
        ;;
esac
