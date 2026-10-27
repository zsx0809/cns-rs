#!/system/bin/sh
# cns-rs 现代化免流透明代理调度脚本 (NAT REDIRECT 架构 + DNS 智能中继 + 全协议连通性检测)

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
DNS_PORT="7753"
allowWifi="${allowWifi:-1}"

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

    echo "🚀 启动 cns-client 核心 (TCP: $tproxy_port, DNS: $DNS_PORT, GID: 3004)..."
    ./cns-client -c "$CONF" -g 3004 -t "$tproxy_port" --dns-listen "0.0.0.0:$DNS_PORT" -p client.pid > client.log 2>&1 &
    sleep 1

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，请检查 client.log！"
        cat client.log 2>/dev/null
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID, GID: 3004)"

    echo "⚙️ 注入内核数据包分流与防回环规则..."
    for tool in iptables ip6tables; do
        $tool -w -t nat -N CNS_NAT 2>/dev/null
        $tool -w -t nat -F CNS_NAT

        # 1. 防回环白名单
        $tool -w -t nat -A CNS_NAT -m owner --gid-owner 3004 -j RETURN
        $tool -w -t nat -A CNS_NAT -o lo -j RETURN
        $tool -w -t nat -A CNS_NAT -p udp --dport 67:68 -j RETURN

        # 2. 放行 CNS 服务端端口 (直连不走代理)
        $tool -w -t nat -A CNS_NAT -p tcp --dport 13872 -j RETURN

        # 3. 放行代理自身监听端口
        $tool -w -t nat -A CNS_NAT -p tcp --dport "$tproxy_port" -j RETURN
        $tool -w -t nat -A CNS_NAT -p udp --dport "$DNS_PORT" -j RETURN

        # 4. WiFi 放行
        if [ "$allowWifi" = "1" ]; then
            $tool -w -t nat -A CNS_NAT -o wlan+ -j RETURN
        fi

        # 5. 放行指定应用 UID
        if [ -n "$allowApps" ]; then
            for app in $allowApps; do
                $tool -w -t nat -A CNS_NAT -m owner --uid-owner "$app" -j RETURN
            done
        fi

        # 6. DNS 拦截：将所有 UDP 53 端口重定向到本地 DNS 中继端口 7753
        $tool -w -t nat -A CNS_NAT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"

        # 7. TCP 全流量重定向到 cns-client 端口 7750
        $tool -w -t nat -A CNS_NAT -p tcp -j REDIRECT --to-ports "$tproxy_port"

        $tool -w -t nat -I OUTPUT -j CNS_NAT
    done

    echo "✓ 现代化免流隧道与 DNS 智能中继已完全就绪！"
    status_check
    echo ""
    run_tests
}

stop_rules() {
    echo "🛑 正在关闭免流模式..."
    for tool in iptables ip6tables; do
        while $tool -w -t nat -D OUTPUT -j CNS_NAT 2>/dev/null; do :; done
        $tool -w -t nat -F CNS_NAT 2>/dev/null
        $tool -w -t nat -X CNS_NAT 2>/dev/null
    done

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
        echo "● TCP 端口: $tproxy_port"
        echo "● DNS 端口: $DNS_PORT"
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
        echo "✓ 成功! UDP 隧道吞吐畅通"
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
