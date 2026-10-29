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
#
# v0.3.1 追加：
#   6. 启动前一致性自检 preflight_check()：
#      modes/<模式>.json 与 config.ini（以及实际传给 cns-client 的 -t / --mode /
#      --dns-listen / -g）必须一致。不一致时**中止启动**并打印「改哪个文件的哪个字段」，
#      而不是静默生成自相矛盾的规则（那种情况的表现是全断网且 client.log 无任何报错）。
#      自检在 stop_rules 之前执行：配置写错时不会先把一个正在工作的会话拆掉。
#   7. QUIC 拦截策略与 block_ipv6 联动：
#      blockQuic=1 且模式 JSON 的 block_ipv6=true 时用 -j DROP（软失败，促 App 按
#      「网络慢」回退 TCP），否则维持 REJECT；stop 路径把 DROP / REJECT 两种形态全清。
#   8. IPv6 能力分开探测：本机实测 ip6tables **没有 nat 表**，v6 无法做 REDIRECT，
#      因此 HAS_V6_NAT / HAS_V6_MANGLE / HAS_V6_FILTER 三个能力位分开判断，
#      QUIC 拦截（filter 表）不再被 nat 的探测结果误杀。

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
# 劫持方式：留空 = 以 modes/<模式>.json 的 tproxy_mode 为准（推荐）；
#           填写则**必须与 JSON 里的值相同**，不一致会在 preflight_check 报错中止。
tproxy_mode="${tproxy_mode:-}"
# 是否拦截 QUIC（UDP 443）：1=拦截（促使回退 TCP TLS），0=放行
# 拦截形态由 quic_policy() 决定：block_ipv6=true 时为 DROP，否则 REJECT。
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

# 取数字型字段（JSON 里不带引号的值，如 "gid": 3004）
json_get_num() {
    sed -n 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | head -n 1
}

# 从 "0.0.0.0:7750" / "[::]:7750" / "7750" 里取出端口号；非法或空 -> 空串
port_of() {
    _p="$1"
    case "$_p" in
        *:*) _p="${_p##*:}" ;;
    esac
    case "$_p" in
        ''|*[!0-9]*) _p="" ;;
    esac
    printf '%s' "$_p"
}

# ---------- 内核能力探测 ----------
# 注意（本机实测）：Android 内核的 ip6tables **没有 nat 表**，所以
#   · REDIRECT（nat）模式下 v6 根本无法劫持 -> HAS_V6_NAT=0，ip6tables 整个跳过；
#   · TPROXY 走 mangle 表，v6 在 mangle 上是可用的（HAS_V6_MANGLE）；
#   · QUIC 拦截落在 filter 表，与 nat 无关 -> 单独用 HAS_V6_FILTER 判断，
#     否则「v6 没有 nat」会把一条纯 filter 规则误杀成死代码。
probe_v6() {
    HAS_V6_NAT=0; HAS_V6_MANGLE=0; HAS_V6_FILTER=0
    ip6tables -w -t nat -L    >/dev/null 2>&1 && HAS_V6_NAT=1
    ip6tables -w -t mangle -L >/dev/null 2>&1 && HAS_V6_MANGLE=1
    ip6tables -w -L           >/dev/null 2>&1 && HAS_V6_FILTER=1
}

# ---------- iptables 封装 ----------
HAS_V6_NAT=0; HAS_V6_MANGLE=0; HAS_V6_FILTER=0
probe_v6
# HAS_V6 保持旧语义：REDIRECT 模式下 v6 是否可用（决定 $TOOLS 是否包含 ip6tables）
HAS_V6="$HAS_V6_NAT"
TOOLS="iptables"
[ "$HAS_V6" = "1" ] && TOOLS="iptables ip6tables"

# stop 路径的工具集合：比 $TOOLS 更宽。
# 换过模式 / 换过配置之后，上一条命留下的 v6 规则也必须能被清掉（否则残留断网）。
TOOLS_CLEAN="iptables"
if [ "$HAS_V6_NAT" = "1" ] || [ "$HAS_V6_MANGLE" = "1" ] || [ "$HAS_V6_FILTER" = "1" ]; then
    TOOLS_CLEAN="iptables ip6tables"
fi

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
    _tp=$(port_of "$(json_get "$CONF" tproxy_listen)")
    [ -z "$_tp" ] && _tp="7750"

    _dp=$(port_of "$(json_get "$CONF" dns_listen)")
    [ -z "$_dp" ] && _dp="7753"

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

# ---------- QUIC 拦截策略（纯函数，不碰 iptables，便于自测）----------
# 输出：none（放行 UDP 443）| reject（硬失败）| drop（软失败）
# 规则：
#   blockQuic != 1                     -> none
#   blockQuic == 1 且 block_ipv6=true  -> drop
#     理由：block_ipv6=true 时客户端把 AAAA 打成 NODATA，双栈 App 已经拿不到 IPv6；
#     若再对 UDP/443 回 ICMP port-unreachable，部分 App 不判定为「QUIC 不可用」而是
#     判定为「网络错误」直接报错，不再回退。DROP 则是「没有响应」，App 会按超时
#     回退到 TCP 443 —— 而 TCP 443 正是被劫持进隧道的路径。
#   blockQuic == 1 且 block_ipv6 显式为 false -> reject（维持旧行为）
#     注意缺省语义：客户端 ClientConfig::block_ipv6 的 serde default = true，
#     所以 JSON 里没写该字段时按 true 处理（走 DROP），与客户端保持一致。
quic_policy() {
    if [ "$blockQuic" != "1" ]; then
        echo none
        return 0
    fi
    _bi=$(json_get_bool "$CONF" block_ipv6)
    case "$_bi" in
        true|false) : ;;
        *) _bi="true" ;;   # 缺省 = 客户端内置默认 true
    esac
    if [ "$_bi" = "true" ]; then echo drop; else echo reject; fi
}

# ---------- 启动期一致性自检（A 项）----------
# 背景：同一批运行参数有两个副本 —— config.ini 与 modes/<模式>.json。
#       只改一边不会有任何报错，但会让「iptables 按 A 抓包、客户端按 B 解析原始目的」，
#       表现为全断网且 client.log 里没有 error（最难排查的那类故障）。
# 本函数在生成任何规则之前把这些值对齐。返回 0 = 可以继续；1 = 必须中止启动。
preflight_check() {
    _bad=0

    # ---- 1) 劫持方式 tproxy_mode：config.ini（脚本用它生成 iptables、并用 --mode 传给客户端）
    #         必须与 modes/<模式>.json 的 tproxy_mode 相同 ----
    _jm=$(json_get "$CONF" tproxy_mode)
    case "$_jm" in
        redirect|tproxy|auto) : ;;
        '')
            _jm="auto"   # 客户端 ClientConfig::default_tproxy_mode() = "auto"
            echo "⚠️  $CONF 未声明 tproxy_mode，客户端内置默认是 'auto'（先试 SO_ORIGINAL_DST 再试 local_addr）"
            ;;
        *)
            echo "❌ $CONF 的 \"tproxy_mode\": \"$_jm\" 非法（只支持 redirect | tproxy | auto）"
            echo "   → 修法：把 $CONF 的 tproxy_mode 改成 redirect 或 tproxy"
            _bad=1
            ;;
    esac

    # config.ini 没写 tproxy_mode 时，JSON 就是唯一真源，直接采用
    if [ -z "$tproxy_mode" ]; then
        case "$_jm" in
            tproxy) tproxy_mode="tproxy" ;;
            *)      tproxy_mode="redirect" ;;
        esac
        echo "ℹ️  config.ini 未指定 tproxy_mode，采用 $CONF 的 '$_jm' → iptables 按 '$tproxy_mode' 生成"
    fi
    [ "$_jm" = "auto" ] && \
        echo "ℹ️  $CONF 为 auto，建议显式写成 \"tproxy_mode\": \"$tproxy_mode\"（当前 iptables 即按 $tproxy_mode 生成）"

    # 两边都明确写了就必须相同（auto 能兼容两种规则，不算冲突）
    case "$_jm" in
        redirect|tproxy)
            if [ "$_bad" = "0" ] && [ "$tproxy_mode" != "$_jm" ]; then
                echo "❌ 劫持方式的两个真源冲突（会导致全断网且无任何报错）："
                echo "     config.ini        : tproxy_mode='$tproxy_mode'  ← 脚本按它生成 iptables，并用 --mode 传给客户端"
                echo "     $CONF : \"tproxy_mode\": \"$_jm\""
                echo "   → 修法（二选一，改到两边相同为止）："
                echo "       1) 把 $CONF 的 \"tproxy_mode\" 改成 \"$tproxy_mode\""
                echo "       2) 或把 config.ini 的 tproxy_mode 改成 '$_jm'"
                _bad=1
            fi
            ;;
    esac

    # ---- 2) 透明代理端口：脚本/规则实际用的 $tproxy_port vs JSON tproxy_listen ----
    _jlp=$(port_of "$(json_get "$CONF" tproxy_listen)")
    if [ -z "$_jlp" ]; then
        echo "⚠️  $CONF 未声明合法端口：\"tproxy_listen\": \"$(json_get "$CONF" tproxy_listen)\""
        echo "    本次按脚本内置默认 $tproxy_port 监听并放行（客户端由 -t 覆盖，运行期一致）；"
        echo "   → 建议：补上 \"tproxy_listen\": \"[::]:$tproxy_port\" 明确唯一真源"
    elif [ "$tproxy_port" != "$_jlp" ]; then
        if [ -n "$TPORT_OVERRIDE" ]; then
            echo "⚠️  config.ini 的 tproxy_port='$TPORT_OVERRIDE' 正在覆盖 $CONF 的 tproxy_listen（$_jlp）"
            echo "    脚本已用 -t $tproxy_port 让客户端跟随，运行期两边一致；"
            echo "    但 JSON 里仍是 $_jlp —— 任何不带 -t 的启动方式（手敲命令 / 旧脚本）会听在 $_jlp，届时两边分叉。"
            echo "   → 建议：把 $CONF 的 tproxy_listen 端口同步改成 $tproxy_port"
        else
            echo "❌ 透明代理端口不一致：规则用 $tproxy_port，$CONF 写的是 $_jlp"
            echo "   → 修法：检查 $CONF 的 tproxy_listen 与脚本的 derive_ports()"
            _bad=1
        fi
    fi

    # ---- 3) DNS 端口：JSON dns_listen vs 实际传给 --dns-listen 的 $DNS_PORT ----
    _jdp=$(port_of "$(json_get "$CONF" dns_listen)")
    if [ -z "$_jdp" ]; then
        echo "⚠️  $CONF 未声明 dns_listen（客户端内置默认 127.0.0.1:6653）"
        echo "    本次由 --dns-listen 0.0.0.0:$DNS_PORT 覆盖并按 $DNS_PORT 放行，运行期一致"
        echo "   → 建议：补上 \"dns_listen\": \"0.0.0.0:$DNS_PORT\""
    elif [ "$DNS_PORT" != "$_jdp" ]; then
        echo "❌ DNS 端口不一致：规则/--dns-listen 用 $DNS_PORT，$CONF 写的是 $_jdp"
        _bad=1
    fi

    # ---- 4) 进程 GID：脚本 -g $GID_OWNER 与 iptables 的 --gid-owner 配套，JSON gid 不生效 ----
    _jgid=$(json_get_num "$CONF" gid)
    if [ -z "$_jgid" ]; then
        echo "⚠️  $CONF 未声明 gid（客户端靠脚本传入的 -g $GID_OWNER 防回环）"
    elif [ "$_jgid" != "$GID_OWNER" ]; then
        echo "⚠️  GID 不一致：脚本用 -g $GID_OWNER 启动并在 iptables 里按 $GID_OWNER 放行，"
        echo "    但 $CONF 写的是 \"gid\": $_jgid（被 -g 覆盖，不生效）"
        echo "   → 建议：把 $CONF 的 gid 改成 $GID_OWNER，或直接删掉该字段"
    fi

    # ---- 5) 服务端：cns_server 是唯一真源，其余（放行端口、探活目标）都由它推导 ----
    if [ -z "$SERVER_PORT" ] || [ -z "$SERVER_HOST" ]; then
        echo "❌ 无法从 $CONF 的 cns_server 解析出 主机:端口"
        echo "   → 修法：写成 \"cns_server\": \"你的服务端IP:1254\"（域名也支持）"
        _bad=1
    else
        echo "ℹ️  服务端真源: $CONF cns_server=$SERVER_ENDPOINT → 放行 TCP $SERVER_PORT（$SERVER_HOST）"
    fi

    # ---- 6) 只读核对「当前已生效的规则」是否就是本次要生成的规则 ----
    # 这一段只读（iptables -S），不增删任何规则；不一致仅提示，
    # 因为 start_rules 在自检通过后会整表清理并重建（残留会被顺手带走）。
    if [ -n "$SERVER_PORT" ] && command -v iptables >/dev/null 2>&1; then
        _live_nat=$(iptables -w -t nat -S CNS_NAT 2>/dev/null)
        if [ -n "$_live_nat" ]; then
            echo "ℹ️  检测到当前已生效的旧 CNS 规则（本次启动会先清理再重建）："
            echo "$_live_nat" | grep -E -- "--dport ($SERVER_PORT|$tproxy_port) -j (RETURN|REDIRECT)" | sed 's/^-A /     /' | head -n 6
            case "$_live_nat" in
                *"-j REDIRECT --to-ports $tproxy_port"*) : ;;
                *) echo "   ⚠️  旧规则的 REDIRECT 端口不是本次要用的 $tproxy_port（上次运行 / 上次模式残留，会被清理）" ;;
            esac
            case "$_live_nat" in
                *"--dport $SERVER_PORT -j RETURN"*) : ;;
                *) echo "   ⚠️  旧规则里没有放行服务端端口 $SERVER_PORT（本次会按 $CONF 的 cns_server 重建）" ;;
            esac
        fi
        if iptables -w -t mangle -S CNS_TP_OUT >/dev/null 2>&1; then
            echo "ℹ️  检测到残留的 mangle CNS_TP_* 规则（上一次是 tproxy 模式），本次启动会一并清理"
        fi
    fi

    if [ "$_bad" != "0" ]; then
        echo ""
        echo "❌ 一致性自检未通过，已中止启动：没有改动任何 iptables 规则，也没有启动 cns-client。"
        echo "   当前网络保持原状；按上面提示改完文件后再执行一次开启即可。"
        return 1
    fi
    return 0
}

start_rules() {
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

    # A 项：自检必须在「拆旧会话 / 生成新规则」之前。配错时什么都不动，最省事也最安全。
    if ! preflight_check; then
        return 1
    fi

    stop_rules >/dev/null 2>&1

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
    if [ "$tproxy_mode" = "tproxy" ]; then
        echo "   模式: TPROXY (内核级透明代理 + 策略路由)"
        # 1. 策略路由：将带有 0x1/0x1 标记的数据包重定向到本地 lo
        command -v ip >/dev/null 2>&1 || { echo "⚠️  缺少 ip 命令，TPROXY 策略路由无法配置"; }
        ip rule add fwmark 0x1/0x1 lookup 100 pref 100 2>/dev/null
        ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null
        if [ "$HAS_V6" = "1" ]; then
            ip -6 rule add fwmark 0x1/0x1 lookup 100 pref 100 2>/dev/null
            ip -6 route add local ::/0 dev lo table 100 2>/dev/null
        fi
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

        for tool in $TOOLS; do
            # 2. PREROUTING 链：捕获流量并交由本地 TPROXY Socket 处理
            $tool -w -t mangle -N CNS_TP_PRE 2>/dev/null
            $tool -w -t mangle -F CNS_TP_PRE

            # 2.1 放行自身 GID 与基础端口
            add "$tool" mangle CNS_TP_PRE -m owner --gid-owner "$GID_OWNER" -j RETURN 2>/dev/null || true
            add "$tool" mangle CNS_TP_PRE -p udp --dport 67:68 -j RETURN
            add "$tool" mangle CNS_TP_PRE -p tcp --dport "$SERVER_PORT" -j RETURN
            add "$tool" mangle CNS_TP_PRE -p tcp --dport "$tproxy_port" -j RETURN
            add "$tool" mangle CNS_TP_PRE -p udp --dport "$DNS_PORT" -j RETURN
            [ -n "$SOCKS_PORT" ] && add "$tool" mangle CNS_TP_PRE -p tcp --dport "$SOCKS_PORT" -j RETURN

            # 2.2 服务端 IP 放行
            for ip in $SERVER_IPS; do
                case "$ip" in
                    *:*) [ "$tool" = "ip6tables" ] && add "$tool" mangle CNS_TP_PRE -d "$ip" -p tcp -j RETURN ;;
                    *)   [ "$tool" = "iptables" ]  && add "$tool" mangle CNS_TP_PRE -d "$ip" -p tcp -j RETURN ;;
                esac
            done

            # 2.3 TPROXY 规则注入 (区分 IPv4 与 IPv6 的 --on-ip)
            if [ "$tool" = "iptables" ]; then
                add iptables mangle CNS_TP_PRE -p udp --dport 53 -j TPROXY --on-ip 127.0.0.1 --on-port "$DNS_PORT" --tproxy-mark 0x1/0x1
                add iptables mangle CNS_TP_PRE -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
                add iptables mangle CNS_TP_PRE -p udp -j TPROXY --on-ip 127.0.0.1 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
            else
                add ip6tables mangle CNS_TP_PRE -p udp --dport 53 -j TPROXY --on-ip ::1 --on-port "$DNS_PORT" --tproxy-mark 0x1/0x1
                add ip6tables mangle CNS_TP_PRE -p tcp -j TPROXY --on-ip ::1 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
                add ip6tables mangle CNS_TP_PRE -p udp -j TPROXY --on-ip ::1 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
            fi
            add "$tool" mangle PREROUTING -j CNS_TP_PRE

            # 3. OUTPUT 链：拦截本机应用出站流量并打 mark 重新路由至 lo
            $tool -w -t mangle -N CNS_TP_OUT 2>/dev/null
            $tool -w -t mangle -F CNS_TP_OUT

            # 3.1 防回环：本进程组 / 回环网卡（非 mark 流量）
            add "$tool" mangle CNS_TP_OUT -m owner --gid-owner "$GID_OWNER" -j RETURN
            add "$tool" mangle CNS_TP_OUT -o lo -m mark ! --mark 0x1/0x1 -j RETURN
            add "$tool" mangle CNS_TP_OUT -p udp --dport 67:68 -j RETURN

            # 3.2 CNS 服务端 IP/端口放行
            add "$tool" mangle CNS_TP_OUT -p tcp --dport "$SERVER_PORT" -j RETURN
            for ip in $SERVER_IPS; do
                case "$ip" in
                    *:*) [ "$tool" = "ip6tables" ] && add "$tool" mangle CNS_TP_OUT -d "$ip" -p tcp -j RETURN ;;
                    *)   [ "$tool" = "iptables" ]  && add "$tool" mangle CNS_TP_OUT -d "$ip" -p tcp -j RETURN ;;
                esac
            done

            # 3.3 代理自身监听端口放行
            add "$tool" mangle CNS_TP_OUT -p tcp --dport "$tproxy_port" -j RETURN
            add "$tool" mangle CNS_TP_OUT -p udp --dport "$DNS_PORT" -j RETURN
            [ -n "$SOCKS_PORT" ] && add "$tool" mangle CNS_TP_OUT -p tcp --dport "$SOCKS_PORT" -j RETURN

            # 3.4 私网与保留地址直连（避免路由器管理页与局域网设备无法访问）
            if [ "$tool" = "iptables" ]; then
                for rip in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4; do
                    add iptables mangle CNS_TP_OUT -d "$rip" -j RETURN
                done
            else
                for rip in ::1/128 fe80::/10 fc00::/7 ff00::/8; do
                    add ip6tables mangle CNS_TP_OUT -d "$rip" -j RETURN
                done
            fi

            # 3.5 WiFi 放行
            [ "$allowWifi" = "1" ] && add "$tool" mangle CNS_TP_OUT -o wlan+ -j RETURN
            [ "$allowWifi" = "1" ] && add "$tool" mangle CNS_TP_OUT -o p2p+ -j RETURN
            [ "$allowWifi" = "1" ] && add "$tool" mangle CNS_TP_OUT -o ap+ -j RETURN

            # 3.6 放行指定 App
            for app in $allowApps; do
                [ -z "$app" ] && continue
                case "$app" in
                    *[!0-9]*)
                        uid=$(cmd package list packages -U 2>/dev/null | grep -F "$app" | grep -oE 'uid: [0-9]+' | awk '{print $2}' | head -n 1)
                        [ -n "$uid" ] && add "$tool" mangle CNS_TP_OUT -m owner --uid-owner "$uid" -j RETURN
                        ;;
                    *)
                        add "$tool" mangle CNS_TP_OUT -m owner --uid-owner "$app" -j RETURN
                        ;;
                esac
            done

            # 3.7 打 mark 触发策略路由
            add "$tool" mangle CNS_TP_OUT -p tcp -j MARK --set-xmark 0x1/0x1
            add "$tool" mangle CNS_TP_OUT -p udp -j MARK --set-xmark 0x1/0x1
            add "$tool" mangle OUTPUT -j CNS_TP_OUT
        done
    else
        echo "   模式: REDIRECT (NAT 重定向)"
        for tool in $TOOLS; do
            $tool -w -t nat -N CNS_NAT 2>/dev/null
            $tool -w -t nat -F CNS_NAT

            # 1. 防回环：本进程组 / 回环口
            add "$tool" nat CNS_NAT -m owner --gid-owner "$GID_OWNER" -j RETURN
            add "$tool" nat CNS_NAT -o lo -j RETURN
            [ "$protectLocalDns" = "1" ] && add "$tool" nat CNS_NAT -d 127.0.0.0/8 -j RETURN
            add "$tool" nat CNS_NAT -p udp --dport 67:68 -j RETURN

            # 2. 放行 CNS 服务端本身
            add "$tool" nat CNS_NAT -p tcp --dport "$SERVER_PORT" -j RETURN
            for ip in $SERVER_IPS; do
                case "$ip" in
                    *:*) [ "$tool" = "ip6tables" ] && add "$tool" nat CNS_NAT -d "$ip" -p tcp -j RETURN ;;
                    *)   [ "$tool" = "iptables" ]  && add "$tool" nat CNS_NAT -d "$ip" -p tcp -j RETURN ;;
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

            # 5. 放行指定 App
            for app in $allowApps; do
                [ -z "$app" ] && continue
                case "$app" in
                    *[!0-9]*)
                        uid=$(cmd package list packages -U 2>/dev/null | grep -F "$app" | grep -oE 'uid: [0-9]+' | awk '{print $2}' | head -n 1)
                        [ -n "$uid" ] && add "$tool" nat CNS_NAT -m owner --uid-owner "$uid" -j RETURN
                        ;;
                    *)
                        add "$tool" nat CNS_NAT -m owner --uid-owner "$app" -j RETURN
                        ;;
                esac
            done

            # 6. REDIRECT 拦截
            add "$tool" nat CNS_NAT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
            add "$tool" nat CNS_NAT -p tcp -j REDIRECT --to-ports "$tproxy_port"
            add "$tool" nat OUTPUT -j CNS_NAT
        done
    fi

    # 8. QUIC：拦截 UDP 443，促使 App 秒级回退到 TCP TLS（不断流的关键之一）
    #    形态由 quic_policy() 决定（B 项）：
    #      blockQuic=1 且 block_ipv6=true -> DROP（软失败，App 按超时回退 TCP）
    #      其余 -> REJECT --reject-with icmp-port-unreachable（原行为，快速失败）
    #    v6 用 HAS_V6_FILTER 判断（filter 表可用性），与 nat 表无关：
    #    本机 ip6tables 没有 nat 表，旧代码用 HAS_V6(=nat) 判断让这条 v6 规则成了死代码。
    _quic=$(quic_policy)
    case "$_quic" in
        drop)
            echo "🚧 QUIC 拦截: DROP（软失败，促 App 回退 TCP）—— blockQuic=1 且 block_ipv6 生效值为 true"
            add iptables filter OUTPUT -p udp --dport 443 -j DROP
            if [ "$HAS_V6_FILTER" = "1" ]; then
                add ip6tables filter OUTPUT -p udp --dport 443 -j DROP
            else
                echo "   ⚠️  ip6tables filter 不可用，跳过 v6 的 UDP/443 拦截（v6 QUIC 直连）"
            fi
            ;;
        reject)
            echo "🚧 QUIC 拦截: REJECT --reject-with icmp-port-unreachable（block_ipv6 不为 true，保持原策略）"
            add iptables filter OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
            if [ "$HAS_V6_FILTER" = "1" ]; then
                add ip6tables filter OUTPUT -p udp --dport 443 -j REJECT
            fi
            ;;
        *)
            echo "🚧 QUIC 拦截: 关闭（blockQuic=$blockQuic，UDP/443 直连放行）"
            ;;
    esac

    # 9. MSS 钳制，避免跨国链路大包分片丢包
    add iptables mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    echo "✓ 分流规则已就绪"
    status_check
    echo ""
    run_tests
}

stop_rules() {
    echo "🛑 关闭免流模式..."
    # 用 $TOOLS_CLEAN 而不是 $TOOLS：上一条命可能是 tproxy 模式（v6 走 mangle）
    # 或 blockQuic 的另一形态，只清 $TOOLS 会留下清不掉的残留规则。
    for tool in $TOOLS_CLEAN; do
        del_all "$tool" nat OUTPUT -j CNS_NAT
        $tool -w -t nat -F CNS_NAT 2>/dev/null
        $tool -w -t nat -X CNS_NAT 2>/dev/null

        del_all "$tool" mangle PREROUTING -j CNS_TP_PRE
        $tool -w -t mangle -F CNS_TP_PRE 2>/dev/null
        $tool -w -t mangle -X CNS_TP_PRE 2>/dev/null

        del_all "$tool" mangle OUTPUT -j CNS_TP_OUT
        $tool -w -t mangle -F CNS_TP_OUT 2>/dev/null
        $tool -w -t mangle -X CNS_TP_OUT 2>/dev/null

        del_all "$tool" mangle PREROUTING -j CNS_TP
        $tool -w -t mangle -F CNS_TP 2>/dev/null
        $tool -w -t mangle -X CNS_TP 2>/dev/null

        # QUIC 拦截的两种形态都要清：block_ipv6 改动后形态会在 DROP / REJECT 之间切换，
        # 只删一种就会把另一种留在表里（残留 REJECT/DROP 会一直掐着 UDP 443）。
        del_all "$tool" filter OUTPUT -p udp --dport 443 -j DROP
        del_all "$tool" filter OUTPUT -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
        del_all "$tool" filter OUTPUT -p udp --dport 443 -j REJECT
    done
    del_all iptables mangle POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

    if command -v ip >/dev/null 2>&1; then
        while ip rule del fwmark 0x1/0x1 lookup 100 pref 100 2>/dev/null; do :; done
        while ip rule del fwmark 0x1/0x1 lookup 100 2>/dev/null; do :; done
        while ip -6 rule del fwmark 0x1/0x1 lookup 100 pref 100 2>/dev/null; do :; done
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

# status / test 用：只把 tproxy_mode 补全用于显示，不做任何校验、不生成规则
# （start 路径由 preflight_check 负责严格校验并可能在必要时改写它）
resolve_mode_soft() {
    [ -n "$tproxy_mode" ] && return 0
    case "$(json_get "$CONF" tproxy_mode)" in
        tproxy) tproxy_mode="tproxy" ;;
        *)      tproxy_mode="redirect" ;;
    esac
    return 0
}

case "$1" in
    start)  start_rules ;;
    stop)   stop_rules ;;
    status) derive_ports 2>/dev/null; resolve_server 2>/dev/null; resolve_mode_soft; status_check ;;
    test)   derive_ports 2>/dev/null; resolve_server 2>/dev/null; resolve_mode_soft; run_tests ;;
    restart) stop_rules >/dev/null 2>&1; start_rules ;;
    *)
        echo "用法: $0 {start|stop|restart|status|test}"
        exit 1
        ;;
esac
