#!/system/bin/sh
# cns-rs 透明代理调度脚本
#
# 关键修复（相对 v0.1.x）：
#   1. 服务端端口不再硬编码 13872 —— 从 modes/<模式>.json 里读，避免
#      「放行端口与实际端口不符 -> cns-client 自己的出站被 REDIRECT 抓回自己」的回环死锁。
#   2. 所有 add 规则先做存在性检查（-C），重复 start 不再堆积规则。
#   3. stop 用「整表删除 + 链回收」并幂等，异常中断后也能干净复原。
#   4. DNS 拦截端口取自配置，而不是与 config.ini 脱节的第二个数字。
#   5. 支持 redirect / tproxy 两种劫持方式，并按内核能力自动降级。

DIR="${0%/*}"
cd "$DIR" || exit 1

# ---------- 配置载入 ----------
if [ -f "../config.ini" ]; then
    # shellcheck disable=SC1091
    . "../config.ini"
fi

modeName="${modeName:-联通}"
TPORT_OVERRIDE="${tproxy_port:-}"
allowWifi="${allowWifi:-1}"
allowApps="${allowApps:-}"
# 劫持方式：redirect（默认，兼容性最好）| tproxy
tproxy_mode="${tproxy_mode:-redirect}"
# 是否拦截 QUIC（UDP 443）：1=REJECT 促使回退 TCP TLS，0=放行
blockQuic="${blockQuic:-1}"
# 是否放行本机 DNS（有些 ROM 的 netd 走 127.0.0.1:53，被劫持会解析全挂）
protectLocalDns="${protectLocalDns:-1}"

CONF="../modes/${modeName}.json"

# ---------- 极简 JSON 取值（无 jq 依赖）----------
# 用法: json_get <文件> <键>  -> 输出字符串值或空
json_get() {
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$1" 2>/dev/null | head -n 1
}

json_get_bool() {
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$1" 2>/dev/null | head -n 1
}

# ---------- iptables 封装 ----------
HAS_V6=0
if ip6tables -w -t nat -L >/dev/null 2>&1; then
    HAS_V6=1
fi
TOOLS="iptables"
[ "$HAS_V6" = "1" ] && TOOLS="iptables ip6tables"

# add <tool> <table> <chain> <rule...>：不存在才加，避免重复堆积
add() {
    tool="$1"; shift
    table="$1"; shift
    chain="$1"; shift
    if $tool -w -t "$table" -C "$chain" "$@" >/dev/null 2>&1; then
        return 0
    fi
    $tool -w -t "$table" -A "$chain" "$@" 2>/dev/null
}

del_all() {
    tool="$1"; shift
    table="$1"; shift
    chain="$1"; shift
    while $tool -w -t "$table" -D "$chain" "$@" >/dev/null 2>&1; do :; done
}

# ---------- 从模式配置推导服务端地址与端口 ----------
SERVER_ENDPOINT=""
SERVER_HOST=""
SERVER_PORT=""
SERVER_IPS=""
resolve_server() {
    SERVER_ENDPOINT=$(json_get "$CONF" cns_server)
    if [ -z "$SERVER_ENDPOINT" ]; then
        return 1
    fi
    # 去掉可能的方括号，再拆 host/port
    _ep=$(echo "$SERVER_ENDPOINT" | tr -d '[]')
    case "$_ep" in
        *:*)
            SERVER_HOST="${_ep%:*}"
            SERVER_PORT="${_ep##*:}"
            ;;
        *)
            SERVER_HOST="$_ep"
            SERVER_PORT="1254"
            ;;
    esac
    case "$SERVER_PORT" in
        ''|*[!0-9]*) return 1 ;;
    esac
    # 域名则解析出全部 A/AAAA，逐条放行（否则放行规则只能按端口，域名换 IP 就断）
    SERVER_IPS=""
    case "$SERVER_HOST" in
        *[0-9]*.*|*:*:*)
            SERVER_IPS="$SERVER_HOST"
            ;;
        *)
            if command -v getent >/dev/null 2>&1; then
                SERVER_IPS=$(getent hosts "$SERVER_HOST" 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
            fi
            [ -z "$SERVER_IPS" ] && command -v nslookup >/dev/null 2>&1 && \
                SERVER_IPS=$(nslookup "$SERVER_HOST" 2>/dev/null | awk '/^Address: /{print $2}' | tr '\n' ' ')
            ;;
    esac
    return 0
}

# ---------- 端口一律以模式 JSON 为唯一真源 ----------
# config.ini 里的 tproxy_port 只在用户显式填写时才作为覆盖项，
# 避免出现「iptables 抓一个端口、cns-client 听另一个端口」的经典断流。
derive_ports() {
    _tp=$(json_get "$CONF" tproxy_listen)
    case "$_tp" in
        *:*) _tp="${_tp##*:}" ;;
    esac
    case "$_tp" in
        ''|*[!0-9]*) _tp="7750" ;;
    esac

    _dp=$(json_get "$CONF" dns_listen)
    case "$_dp" in
        *:*) _dp="${_dp##*:}" ;;
    esac
    case "$_dp" in
        ''|*[!0-9]*) _dp="7753" ;;
    esac

    _sp=$(json_get "$CONF" socks5_listen)
    case "$_sp" in
        *:*) _sp="${_sp##*:}" ;;
        *)   _sp="" ;;
    esac

    # config.ini 显式覆盖 tproxy 端口时，同步改写传给客户端的 -t，两边永远一致
    case "$TPORT_OVERRIDE" in
        ''|*[!0-9]*) : ;;
        *) _tp="$TPORT_OVERRIDE" ;;
    esac

    tproxy_port="$_tp"
    DNS_PORT="$_dp"
    SOCKS_PORT="$_sp"
}

GID_OWNER="${GID_OWNER:-3004}"

start_rules() {
    stop_rules >/dev/null 2>&1

    if [ ! -f "$CONF" ]; then
        echo "❌ 找不到模式配置: $CONF"
        echo "   可用模式: $(ls ../modes 2>/dev/null | sed 's/\.json$//' | tr '\n' ' ')"
        return 1
    fi
    derive_ports
    if ! resolve_server; then
        echo "❌ 无法从 $CONF 解析 cns_server（请填成 IP:端口 或 域名:端口）"
        return 1
    fi
    case "$SERVER_HOST" in
        YOUR_SERVER_IP*)
            echo "❌ 请先在 $CONF 里把 YOUR_SERVER_IP 改成你的真实服务端地址"
            return 1
            ;;
    esac

    echo "🚀 启动 cns-client（TCP:$tproxy_port  DNS:$DNS_PORT  GID:$GID_OWNER  mode:$tproxy_mode）"
    echo "   服务端: $SERVER_HOST:$SERVER_PORT"

    ./cns-client -c "$CONF" -g "$GID_OWNER" -t "$tproxy_port" \
        --mode "$tproxy_mode" --dns-listen "0.0.0.0:$DNS_PORT" \
        -p client.pid >client.log 2>&1 &

    # 等待就绪（最多 5 秒），不靠固定 sleep
    i=0
    while [ $i -lt 25 ]; do
        PID=$(cat client.pid 2>/dev/null)
        if [ -n "$PID" ] && [ -d "/proc/$PID" ] && netstat -lntu 2>/dev/null | grep -q ":$tproxy_port "; then
            break
        fi
        if [ -n "$PID" ] && [ ! -d "/proc/$PID" ]; then
            break
        fi
        i=$((i + 1))
        sleep 0.2
    done

    PID=$(cat client.pid 2>/dev/null)
    if [ -z "$PID" ] || [ ! -d "/proc/$PID" ]; then
        echo "❌ cns-client 启动失败，client.log 末尾："
        tail -n 15 client.log 2>/dev/null
        return 1
    fi
    echo "✓ cns-client 已就绪 (PID: $PID)"

    echo "⚙️ 注入分流规则..."
    for tool in $TOOLS; do
        $tool -w -t nat -N CNS_NAT 2>/dev/null
        $tool -w -t nat -F CNS_NAT

        # 1. 防回环：本进程组 / 回环口
        add "$tool" nat CNS_NAT -m owner --gid-owner "$GID_OWNER" -j RETURN
        add "$tool" nat CNS_NAT -o lo -j RETURN
        [ "$protectLocalDns" = "1" ] && add "$tool" nat CNS_NAT -d 127.0.0.0/8 -j RETURN
        add "$tool" nat CNS_NAT -p udp --dport 67:68 -j RETURN

        # 2. 放行 CNS 服务端本身（按端口 + 已解析出的每个 IP），这是回环修复的关键
        add "$tool" nat CNS_NAT -p tcp --dport "$SERVER_PORT" -j RETURN
        for ip in $SERVER_IPS; do
            case "$ip" in
                *:*)
                    [ "$tool" = "ip6tables" ] && add "$tool" nat CNS_NAT -d "$ip" -p tcp -j RETURN
                    ;;
                *)
                    [ "$tool" = "iptables" ] && add "$tool" nat CNS_NAT -d "$ip" -p tcp -j RETURN
                    ;;
            esac
        done

        # 3. 放行代理自己的监听端口，避免自连
        add "$tool" nat CNS_NAT -p tcp --dport "$tproxy_port" -j RETURN
        add "$tool" nat CNS_NAT -p udp --dport "$DNS_PORT" -j RETURN
        [ -n "$SOCKS_PORT" ] && add "$tool" nat CNS_NAT -p tcp --dport "$SOCKS_PORT" -j RETURN

        # 4. WiFi 放行
        [ "$allowWifi" = "1" ] && add "$tool" nat CNS_NAT -o wlan+ -j RETURN
        [ "$allowWifi" = "1" ] && add "$tool" nat CNS_NAT -o p2p+ -j RETURN
        [ "$allowWifi" = "1" ] && add "$tool" nat CNS_NAT -o ap+ -j RETURN

        # 5. 放行指定 App（UID 或包名）
        for app in $allowApps; do
            [ -z "$app" ] && continue
            case "$app" in
                *[!0-9]*)
                    # 包名 -> UID
                    uid=$(cmd package list packages -U 2>/dev/null | grep -F "$app" | grep -oE 'uid: [0-9]+' | awk '{print $2}' | head -n 1)
                    [ -n "$uid" ] && add "$tool" nat CNS_NAT -m owner --uid-owner "$uid" -j RETURN
                    ;;
                *)
                    add "$tool" nat CNS_NAT -m owner --uid-owner "$app" -j RETURN
                    ;;
            esac
        done

        # 6. 劫持
        if [ "$tproxy_mode" = "tproxy" ]; then
            # TPROXY 需要 mangle，nat 表不参与
            $tool -w -t mangle -N CNS_TP 2>/dev/null
            $tool -w -t mangle -F CNS_TP
            add "$tool" mangle CNS_TP -m owner --gid-owner "$GID_OWNER" -j RETURN
            add "$tool" mangle CNS_TP -o lo -j RETURN
            add "$tool" mangle CNS_TP -p udp --dport 67:68 -j RETURN
            add "$tool" mangle CNS_TP -p tcp --dport "$SERVER_PORT" -j RETURN
            add "$tool" mangle CNS_TP -p tcp --dport "$tproxy_port" -j RETURN
            add "$tool" mangle CNS_TP -p udp --dport "$DNS_PORT" -j RETURN
            [ "$allowWifi" = "1" ] && add "$tool" mangle CNS_TP -o wlan+ -j RETURN
            add "$tool" mangle CNS_TP -p udp --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port "$DNS_PORT" --tproxy-mark 0x1/0x1
            add "$tool" mangle CNS_TP -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
            add "$tool" mangle PREROUTING -j CNS_TP
        else
            # REDIRECT：Android 内核最稳的路径
            add "$tool" nat CNS_NAT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
            add "$tool" nat CNS_NAT -p tcp -j REDIRECT --to-ports "$tproxy_port"
            add "$tool" nat OUTPUT -j CNS_NAT
        fi
    done

    # 7. TPROXY 需要策略路由把标记包本地投递
    if [ "$tproxy_mode" = "tproxy" ]; then
        command -v ip >/dev/null 2>&1 || { echo "⚠️  缺少 ip 命令，TPROXY 策略路由无法配置"; }
        ip rule add fwmark 0x1/0x1 lookup 100 2>/dev/null
        ip -6 rule add fwmark 0x1/0x1 lookup 100 2>/dev/null
        ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null
        ip -6 route add local ::/0 dev lo table 100 2>/dev/null
        # TPROXY 模式还要给本机放行原始目的地址
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    fi

    # 8. QUIC：拒绝 UDP 443 促使 App 秒级回退到 TCP TLS（不断流的关键之一）
    if [ "$blockQuic" = "1" ]; then
        add iptables filter OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
        [ "$HAS_V6" = "1" ] && add ip6tables filter OUTPUT -p udp --dport 443 -j REJECT
    fi

    # 9. MSS 钳制，避免跨国链路大包分片丢包
    add iptables mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    echo "✓ 分流规则已就绪"
    status_check
    echo ""
    run_tests
}

stop_rules() {
    echo "🛑 关闭免流模式..."
    for tool in $TOOLS; do
        del_all "$tool" nat OUTPUT -j CNS_NAT
        $tool -w -t nat -F CNS_NAT 2>/dev/null
        $tool -w -t nat -X CNS_NAT 2>/dev/null
        del_all "$tool" mangle PREROUTING -j CNS_TP
        $tool -w -t mangle -F CNS_TP 2>/dev/null
        $tool -w -t mangle -X CNS_TP 2>/dev/null
        del_all "$tool" filter OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
        del_all "$tool" filter OUTPUT -p udp --dport 443 -j REJECT
    done
    del_all iptables mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    if command -v ip >/dev/null 2>&1; then
        while ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null; do :; done
        while ip -6 rule del fwmark 0x1/0x1 lookup 100 2>/dev/null; do :; done
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
        ip -6 route del local ::/0 dev lo table 100 2>/dev/null
    fi

    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        kill "$PID" 2>/dev/null
        # 等它自己收尾（半关闭 + 删除 pid 文件）
        i=0
        while [ -d "/proc/$PID" ] && [ $i -lt 20 ]; do
            i=$((i + 1)); sleep 0.1
        done
        [ -d "/proc/$PID" ] && kill -9 "$PID" 2>/dev/null
    fi
    rm -f client.pid
    echo "✓ 规则已清理，网络恢复直连。"
}

status_check() {
    echo "═════════════════════════════════════"
    PID=$(cat client.pid 2>/dev/null)
    if [ -n "$PID" ] && [ -d "/proc/$PID" ]; then
        RSS=$(grep -i VmRSS "/proc/$PID/status" 2>/dev/null | awk '{print $2, $3}')
        [ -z "$RSS" ] && RSS="未知"
        echo "● 状态  : ✓ cns-client 运行中"
        echo "● PID   : $PID"
        echo "● 模式  : $modeName ($tproxy_mode)"
        echo "● 内存  : $RSS"
        echo "● 服务端: ${SERVER_HOST:-未解析}:${SERVER_PORT:-未解析}"
        echo "● 端口  : TCP $tproxy_port / DNS $DNS_PORT"
    else
        echo "● 状态  : × 未运行"
    fi
    echo "═════════════════════════════════════"
}

# probe <url> [超时秒] -> HTTP 码 / 000 / skip
probe() {
    [ -z "$CURL_BIN" ] && { echo skip; return 0; }
    code=$("$CURL_BIN" -k -s -m "${2:-8}" -o /dev/null -w "%{http_code}" "$1" 2>/dev/null)
    echo "${code:-000}"
}

# 取第二个候选：第一个失败(000/skip)时才试
probe2() {
    a=$(probe "$1" "${3:-8}")
    case "$a" in
        000|skip) probe "$2" "${3:-8}" ;;
        *) echo "$a" ;;
    esac
}

run_tests() {
    echo "🔍 全栈连通性检测..."
    echo "-------------------------------------"

    CURL_BIN=""
    if command -v curl >/dev/null 2>&1; then
        CURL_BIN="curl"
    elif [ -x "/data/data/com.termux/files/usr/bin/curl" ]; then
        CURL_BIN="/data/data/com.termux/files/usr/bin/curl"
    fi

    # 1. DNS
    printf "● [1/4] DNS 解析 .......... "
    RESOLVED=""
    if [ -n "$CURL_BIN" ]; then
        RESOLVED=$("$CURL_BIN" -s -m 6 -o /dev/null -w "%{remote_ip}" http://www.baidu.com 2>/dev/null)
    fi
    if [ -z "$RESOLVED" ] && command -v ping >/dev/null 2>&1; then
        RESOLVED=$(ping -c 1 -W 2 www.baidu.com 2>/dev/null | grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    fi
    if [ -n "$RESOLVED" ]; then echo "✓ $RESOLVED"; else echo "× 解析失败"; fi

    # 2. HTTP
    # 2. HTTP（明文 TCP 走隧道）
    printf "● [2/4] HTTP (TCP 80) ..... "
    C=$(probe2 "http://connect.rom.miui.com/generate_204" "http://www.google.com/generate_204" 5)
    case "$C" in 204|200|302) echo "✓ $C";; skip) echo "skip (无 curl)";; *) echo "× ($C)";; esac

    # 3. HTTPS（TLS 隧道）
    printf "● [3/4] HTTPS (TLS 443) ... "
    C=$(probe2 "https://www.baidu.com" "https://www.google.com" 8)
    case "$C" in 200|301|302|403) echo "✓ $C";; skip) echo "skip (无 curl)";; *) echo "× ($C)";; esac

    # 4. 服务端可达性：直连 CNS 端口（这条不通就说明放行规则或端口配错了）
    printf "● [4/4] 服务端可达 ........ "
    if [ -z "$CURL_BIN" ]; then
        echo "skip (无 curl)"
    elif [ -z "$SERVER_HOST" ] || [ -z "$SERVER_PORT" ]; then
        echo "× 未解析到服务端地址"
    else
        # 任意 HTTP 响应（含 4xx/5xx）都代表端口可达；000 才是连不上（IPv6 地址须加方括号）
        _target_host="$SERVER_HOST"
        case "$_target_host" in
            *:*) _target_host="[$_target_host]" ;;
        esac
        C=$(probe "http://$_target_host:$SERVER_PORT/" 5)
        case "$C" in
            000|skip) echo "× $SERVER_HOST:$SERVER_PORT 不可达（检查防火墙与 cns_server 配置）" ;;
            *) echo "✓ $SERVER_HOST:$SERVER_PORT 可达" ;;
        esac
    fi

    echo "-------------------------------------"
    [ -f client.log ] && {
        LASTERR=$(grep -icE "error|refused|timed out" client.log 2>/dev/null)
        [ "${LASTERR:-0}" != "0" ] && echo "⚠️  client.log 中有 ${LASTERR} 条异常记录，建议查看"
    }
    echo "🎉 检测完毕。"
}

case "$1" in
    start)  start_rules ;;
    stop)   stop_rules ;;
    status) derive_ports 2>/dev/null; resolve_server 2>/dev/null; status_check ;;
    test)   derive_ports 2>/dev/null; resolve_server 2>/dev/null; run_tests ;;
    restart) stop_rules >/dev/null 2>&1; start_rules ;;
    *)
        echo "用法: $0 {start|stop|restart|status|test}"
        exit 1
        ;;
esac
