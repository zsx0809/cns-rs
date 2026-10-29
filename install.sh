#!/usr/bin/env bash
# ==============================================================================
# cns-rs 一键快速安装与管理脚本 (CuteBi Network Suite - Rust Edition)
# GitHub: https://github.com/zsx0809/cns-rs
# 支持系统: Ubuntu / Debian / Alpine / CentOS / AlmaLinux / Rocky / Fedora / Arch
# 架构支持: x86_64 (amd64) / aarch64 (arm64) 全平台纯静态免依赖二进制
# ==============================================================================

set -e

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

CONF_DIR="/etc/cns-rs"
CONF_FILE="${CONF_DIR}/config.json"
BIN_PATH="/usr/local/bin/cns-server"
SYSTEMD_FILE="/etc/systemd/system/cns-server.service"
OPENRC_FILE="/etc/init.d/cns-server"
LOG_FILE="/var/log/cns-server.log"

GITHUB_RAW_ROOT="https://raw.githubusercontent.com/zsx0809/cns-rs/main"
GITHUB_PROXY_ROOT="https://ghfast.top/https://raw.githubusercontent.com/zsx0809/cns-rs/main"
# 产物在仓库的 dist/ 下（v0.3.1 起从仓库根移入），raw 路径必须带这个前缀
GITHUB_RAW="${GITHUB_RAW_ROOT}/dist"
GITHUB_PROXY_RAW="${GITHUB_PROXY_ROOT}/dist"

color_echo() {
    echo -e "${1}${2}${PLAIN}"
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        color_echo "$RED" "❌ 错误: 此脚本必须以 root 权限运行！请使用 sudo 或切换至 root 用户。"
        exit 1
    fi
}

detect_os() {
    OS_TYPE="unknown"
    INIT_SYSTEM="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_LIKE="${ID_LIKE:-}"
    elif [ -f /etc/alpine-release ]; then
        OS_ID="alpine"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
    else
        OS_ID="unknown"
    fi

    case "$OS_ID" in
        alpine)
            OS_TYPE="alpine"
            ;;
        ubuntu|debian|kali|raspbian)
            OS_TYPE="debian"
            ;;
        centos|rhel|almalinux|rocky|fedora|ol)
            OS_TYPE="rhel"
            ;;
        arch|manjaro)
            OS_TYPE="arch"
            ;;
        *)
            if echo "$OS_LIKE" | grep -qi "debian"; then
                OS_TYPE="debian"
            elif echo "$OS_LIKE" | grep -qi "rhel\|fedora\|centos"; then
                OS_TYPE="rhel"
            else
                OS_TYPE="linux"
            fi
            ;;
    esac

    # 识别服务管理器
    if [ -d /run/systemd/system ] || [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; then
        INIT_SYSTEM="systemd"
    elif [ -x /sbin/openrc-run ] || [ -f /etc/alpine-release ]; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="sysvinit"
    fi
}

detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            TARGET_ARCH="x86_64"
            ;;
        aarch64|arm64)
            TARGET_ARCH="aarch64"
            ;;
        *)
            color_echo "$RED" "❌ 抱歉，目前仅支持 x86_64 与 aarch64 架构！当前架构: $ARCH"
            exit 1
            ;;
    esac
}

install_dependencies() {
    color_echo "$BLUE" "正在安装基础组件依赖..."
    case "$OS_TYPE" in
        alpine)
            apk update
            apk add --no-cache curl tar ca-certificates
            ;;
        debian)
            apt-get update -y
            apt-get install -y curl tar ca-certificates
            ;;
        rhel)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl tar ca-certificates
            else
                yum install -y curl tar ca-certificates
            fi
            ;;
        arch)
            pacman -Sy --noconfirm curl tar ca-certificates
            ;;
        *)
            ;;
    esac
}

svc_start() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl start cns-server
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service cns-server start
    else
        ${BIN_PATH} -c ${CONF_FILE} > ${LOG_FILE} 2>&1 &
    fi
}

svc_stop() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl stop cns-server 2>/dev/null || true
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service cns-server stop 2>/dev/null || true
    else
        pkill -f "${BIN_PATH}" 2>/dev/null || true
    fi
}

svc_restart() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl restart cns-server
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service cns-server restart 2>/dev/null || rc-service cns-server start
    else
        svc_stop 2>/dev/null || true
        sleep 1
        svc_start
    fi
}

svc_status() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl status cns-server --no-pager
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-service cns-server status
    else
        if pgrep -f "${BIN_PATH}" >/dev/null; then
            color_echo "$GREEN" "● cns-server 正在运行中 (PID: $(pgrep -f ${BIN_PATH}))"
        else
            color_echo "$RED" "○ cns-server 已停止"
        fi
    fi
}

svc_enable() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        systemctl daemon-reload
        systemctl enable cns-server
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        rc-update add cns-server default 2>/dev/null || true
    fi
}

show_banner() {
    clear 2>/dev/null || true
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "       cns-rs 极速免流服务端一键安装管理脚本              "
    echo "       CuteBi Network Suite - Modern Rust Edition         "
    echo "       零 GC 抖动 | 1.5MB 微内核 | 纯静态多发行版免编译   "
    echo "=========================================================="
    echo -e "${PLAIN}"
}

# ============ 二进制来源清单与校验 ============
# 三件套（cns-server-x86_64 / cns-server-aarch64 / cns-client-aarch64）与
# sha256sums.txt 都在**仓库 dist/ 目录**入库（见 .gitignore 的 !/dist/cns-server-*）。
# 所以 raw 下载路径必须带 dist/ 前缀，见上面的 GITHUB_RAW / GITHUB_PROXY_RAW。
# 旧版这里下的是 raw/main/bin/cns-server-<arch>（更早是 raw/main/cns-server-<arch>）：
# 仓库里没有 bin/ 目录、v0.3.1 起根目录也不再放产物，前缀对不上的 URL 每次安装
# 必然 404 一轮才落到 Releases，白等两次超时。
# 顺序：raw 的 dist/ -> Releases -> raw 加速镜像(dist/) -> 根目录旧位置（过渡兜底）。
# 最后那两条只在「脚本已更新、仓库还没推送 dist/」的窗口期起作用（实测远端根目录
# 旧清单与新产物的哈希一致，兜底不会装到过期版本）；确认远端 dist/ 可访问后即可删。
binary_urls() {
    # $1 = 文件名
    local name="$1"
    printf '%s\n' \
        "${GITHUB_RAW}/${name}" \
        "https://github.com/zsx0809/cns-rs/releases/latest/download/${name}" \
        "${GITHUB_PROXY_RAW}/${name}" \
        "${GITHUB_RAW_ROOT}/${name}" \
        "${GITHUB_PROXY_ROOT}/${name}"
}

fetch_one() {
    # $1 = 文件名  $2 = 落地路径；命中即返回 0
    local name="$1" out="$2" url
    while IFS= read -r url; do
        color_echo "$YELLOW" "尝试下载: $url"
        if curl -fsSL --connect-timeout 10 --retry 2 "$url" -o "$out"; then
            [ -s "$out" ] || continue
            echo "    ✓ 来源: $url" >&2
            return 0
        fi
    done < <(binary_urls "$name")
    return 1
}

# 用 sha256sums.txt 校验下载到的二进制。
# 清单取不到 = 拒绝安装：没有校验的远程二进制等于把「装什么」交给中间人。
# （本地已存在的文件不走这里 —— 那是用户自己编译/准备的，校验无意义）
verify_sha256() {
    local name="$1" file="$2"
    local man="/tmp/cns-sha256sums.$$.txt"
    rm -f "$man"
    # 静默取清单：二进制那一步已经打印过来源了，这里再刷三行「尝试下载」纯属噪音
    if ! fetch_one "sha256sums.txt" "$man" >/dev/null 2>&1; then
        color_echo "$RED" "❌ 无法获取 sha256sums.txt，拒绝安装未校验的二进制。"
        color_echo "$YELLOW" "   离线安装方式：把 cns-server-${TARGET_ARCH} 放到本脚本同目录的 dist/ 下（或直接与本脚本同级）再执行。"
        rm -f "$man"
        return 1
    fi
    local want got
    want=$(awk -v n="$name" '$2 == n {print $1; exit}' "$man")
    rm -f "$man"
    if [ -z "$want" ]; then
        color_echo "$RED" "❌ sha256sums.txt 里没有 $name 的条目（清单与产物不匹配），拒绝安装。"
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        got=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        color_echo "$RED" "❌ 本机没有 sha256sum/shasum，无法完成校验，拒绝安装。"
        return 1
    fi
    if [ "$want" != "$got" ]; then
        color_echo "$RED" "❌ SHA-256 不匹配，文件可能被篡改或下载不完整！"
        echo "     期望: $want"
        echo "     实际: $got"
        return 1
    fi
    color_echo "$GREEN" "✓ SHA-256 校验通过 ($name)"
    return 0
}

download_binary() {
    detect_arch
    mkdir -p /usr/local/bin
    color_echo "$YELLOW" "正在获取适合当前系统的静态二进制服务端 (架构: ${TARGET_ARCH})..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
    # dist/ 是权威位置（README 与 raw 下载路径都指向它）
    LOCAL_CANDS=(
        "${SCRIPT_DIR}/dist/cns-server-${TARGET_ARCH}"
        # 后两个只为兼容旧克隆：v0.2.1 起产物在仓库根存一份，更早还有 bin/ 镜像
        "${SCRIPT_DIR}/cns-server-${TARGET_ARCH}"
        "${SCRIPT_DIR}/bin/cns-server-${TARGET_ARCH}"
    )

    for cand in "${LOCAL_CANDS[@]}"; do
        [ -f "$cand" ] || continue
        color_echo "$GREEN" "✓ 发现本地已存在预编译二进制: $cand"
        install -m 755 "$cand" "$BIN_PATH"
        return 0
    done

    local BIN_NAME="cns-server-${TARGET_ARCH}"
    TMP_BIN="/tmp/${BIN_NAME}.$$"
    if ! fetch_one "$BIN_NAME" "$TMP_BIN"; then
        color_echo "$RED" "❌ 无法自动下载预构建二进制，请检查网络连接。"
        rm -f "$TMP_BIN"
        exit 1
    fi

    if ! verify_sha256 "$BIN_NAME" "$TMP_BIN"; then
        rm -f "$TMP_BIN"
        exit 1
    fi

    # 停止旧服务并使用 install 命令进行原子覆盖，避免运行中写入触发 'Text file busy'
    svc_stop 2>/dev/null || true
    install -m 755 "$TMP_BIN" "$BIN_PATH"
    rm -f "$TMP_BIN"
}

setup_service() {
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        color_echo "$BLUE" "配置 systemd 后台守护服务..."
        cat > "$SYSTEMD_FILE" <<EOF
[Unit]
Description=CuteBi Network Suite Rust Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=${BIN_PATH} -c ${CONF_FILE}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable cns-server
    elif [ "$INIT_SYSTEM" = "openrc" ]; then
        color_echo "$BLUE" "配置 OpenRC 后台守护服务 (Alpine Linux)..."
        cat > "$OPENRC_FILE" <<'EOF'
#!/sbin/openrc-run

name="cns-server"
description="CuteBi Network Suite Rust Server"
command="/usr/local/bin/cns-server"
command_args="-c /etc/cns-rs/config.json"
command_background="yes"
pidfile="/run/cns-server.pid"
output_log="/var/log/cns-server.log"
error_log="/var/log/cns-server.log"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "$OPENRC_FILE"
        rc-update add cns-server default 2>/dev/null || true
    fi
}

install_cns_server() {
    check_root
    detect_os
    detect_arch
    show_banner
    color_echo "$GREEN" "🚀 开始安装 cns-rs 服务端 (系统: ${OS_ID}, 架构: ${TARGET_ARCH}, 服务: ${INIT_SYSTEM})..."

    # 1. 引导用户输入核心免流参数
    echo ""
    # 端口必须校验：空/非数字/越界若放过去，会写出一个 bind 必败的 config.json，
    # 而 svc_restart 不检查返回值 —— 结果是「服务在跑、端口没监听」这种最难查的静默失败。
    while true; do
        read -p "请输入服务端监听端口 [默认 1254]: " INPUT_PORT
        LISTEN_PORT="${INPUT_PORT:-1254}"
        if [[ "$LISTEN_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$LISTEN_PORT" -le 65535 ]; then
            break
        fi
        color_echo "$RED" "✗ 端口非法: '$LISTEN_PORT'（必须是 1-65535 的纯数字，不允许前导零）"
    done

    DEFAULT_PWD=$(head /dev/urandom 2>/dev/null | tr -dc A-Za-z0-9 | head -c 8 || echo "666888")
    read -p "请输入免流连接密码 [默认随机: $DEFAULT_PWD]: " INPUT_PWD
    CNS_PASSWORD="${INPUT_PWD:-$DEFAULT_PWD}"

    read -p "请输入代理头字段名 (Proxy-Key) [默认 Meng]: " INPUT_KEY
    PROXY_KEY="${INPUT_KEY:-Meng}"

    read -p "请输入默认伪装域名 (Host) [默认 mclient.alipay.com]: " INPUT_HOST
    HEADER_HOST="${INPUT_HOST:-mclient.alipay.com}"

    # 2. 安装目录与依赖
    mkdir -p "$CONF_DIR"
    install_dependencies

    # 3. 获取并安装完全静态二进制
    download_binary

    # 4. 写入服务端配置文件
    cat > "$CONF_FILE" <<EOF
{
  "listen_addr": [":${LISTEN_PORT}"],
  "proxy_key": "${PROXY_KEY}",
  "udp_flag": "httpUDP",
  "encrypt_password": "${CNS_PASSWORD}",
  "tcp_timeout": 300,
  "udp_timeout": 30,
  "enable_dns_tcp_over_udp": true,
  "enable_tfo": true
}
EOF

    # 5. 配置服务并启动
    setup_service
    svc_restart
    # 关键：安装流程必须验证「真的监听上了」。旧实现只看 svc_restart 是否报错，
    # 而 unit 里 ExecStart 失败会被 systemd 吞掉，用户看到「安装成功」却是空壳服务。
    sleep 1
    if ! verify_running; then
        color_echo "$RED" "❌ 服务端安装完成但未能正常监听，已保留配置供排查：$CONF_FILE"
        return 1
    fi

    # 6. 获取服务器真实可访问的公网 IP / 节点地址
    # 策略：优先判断物理网卡是否存在真正的公网 IPv4（排除 RFC1918 私网如 192.168/10/172 等）
    LOCAL_IPV4=$(ip -4 addr show scope global 2>/dev/null | grep -o 'inet [0-9.]*' | awk '{print $2}' | grep -vE '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)' | head -n 1 || true)
    LOCAL_IPV6=$(ip -6 addr show scope global 2>/dev/null | grep -o 'inet6 [0-9a-f:]*' | awk '{print $2}' | grep -E '^2[0-9a-f]{3}:' | head -n 1 || true)

    if [ -n "$LOCAL_IPV4" ]; then
        SERVER_IP="$LOCAL_IPV4"
        SERVER_ENDPOINT="${SERVER_IP}:${LISTEN_PORT}"
    elif [ -n "$LOCAL_IPV6" ]; then
        SERVER_IP="$LOCAL_IPV6"
        SERVER_ENDPOINT="[${SERVER_IP}]:${LISTEN_PORT}"
    else
        # 兜底查询公网 API
        SERVER_IP=$(curl -s4 --connect-timeout 2 https://api.ipify.org 2>/dev/null || \
                    curl -s6 --connect-timeout 2 https://api64.ipify.org 2>/dev/null || \
                    echo "你的服务器公网IP")
        if [[ "$SERVER_IP" =~ : ]]; then
            SERVER_ENDPOINT="[${SERVER_IP}]:${LISTEN_PORT}"
        else
            SERVER_ENDPOINT="${SERVER_IP}:${LISTEN_PORT}"
        fi
    fi

    echo ""
    color_echo "$GREEN" "=========================================================="
    color_echo "$GREEN" "🎉 cns-rs 服务端已安装并成功启动！"
    color_echo "$GREEN" "=========================================================="
    echo -e "● 操作系统 : ${BLUE}${OS_ID} (${INIT_SYSTEM})${PLAIN}"
    echo -e "● 硬件架构 : ${BLUE}${TARGET_ARCH}${PLAIN}"
    echo -e "● 监听端口 : ${BLUE}${LISTEN_PORT}${PLAIN}"
    echo -e "● 连接密码 : ${BLUE}${CNS_PASSWORD}${PLAIN}"
    echo -e "● 代理 Key : ${BLUE}${PROXY_KEY}${PLAIN}"
    echo -e "● 伪装域名 : ${BLUE}${HEADER_HOST}${PLAIN}"
    echo -e "● 配置文件 : ${YELLOW}${CONF_FILE}${PLAIN}"
    echo ""
    color_echo "$YELLOW" "📱 客户端 (Android 免流模块) 节点配置请填写:"
    echo "----------------------------------------------------------"
    echo -e "{"
    echo -e "  \"cns_server\": \"${SERVER_ENDPOINT}\","
    echo -e "  \"cns_password\": \"${CNS_PASSWORD}\","
    echo -e "  \"proxy_key\": \"${PROXY_KEY}\","
    echo -e "  \"header_host\": \"${HEADER_HOST}\""
    echo -e "}"
    echo "----------------------------------------------------------"
}

start_service() {
    check_root
    detect_os
    svc_start
    color_echo "$GREEN" "✓ cns-rs 服务端已启动！"
}

stop_service() {
    check_root
    detect_os
    svc_stop
    color_echo "$GREEN" "✓ cns-rs 服务端已停止！"
}

restart_service() {
    check_root
    detect_os
    svc_restart
    color_echo "$GREEN" "✓ cns-rs 服务端已重启！"
}

status_service() {
    check_root
    detect_os
    show_banner
    svc_status
}

view_logs() {
    detect_os
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        journalctl -u cns-server -f -n 50
    elif [ -f "$LOG_FILE" ]; then
        tail -n 50 -f "$LOG_FILE"
    else
        color_echo "$YELLOW" "暂无日志记录。"
    fi
}

# ---------- 配置/运行状态自检 ----------
# listen_addr 的提取不能用 "grep -o '"listen_addr"[^]]*]'"：
# 数组元素本身含方括号（"[::]:1254"），[^]] 会在第一个内层 ']' 处截断，
# 于是只读到半条 spec，端口校验与监听检查双双落空。
# 这里用「引号状态 + 括号配对」的字符级扫描，兼容单行与多行数组。
listen_specs() {
    awk '
        { buf = buf $0 " " }
        END {
            key = "\"listen_addr\""
            i = index(buf, key)
            if (i == 0) exit 1
            rest = substr(buf, i + length(key))
            # 跳到数组左括号
            b = 0
            for (j = 1; j <= length(rest); j++) {
                c = substr(rest, j, 1)
                if (c == "[") { b = j; break }
            }
            if (b == 0) exit 1
            body = substr(rest, b + 1)

            depth = 1;inq = 0;cur = "";out = ""
            for (j = 1; j <= length(body); j++) {
                c = substr(body, j, 1)
                if (inq) {
                    if (c == "\"") { inq = 0; if (cur != "") out = out cur "\n"; cur = "" }
                    else cur = cur c
                    continue
                }
                if (c == "\"") { inq = 1; continue }
                if (c == "[") { depth++; continue }
                if (c == "]") { depth--; if (depth == 0) break; continue }
            }
            if (out == "") exit 1
            printf "%s", out
        }' "$CONF_FILE"
}

# 从 spec 取端口（最后一个引号外冒号后的数字；括号内 IPv6 不受影响）
spec_port() {
    case "$1" in
        \[*\]*) printf '%s' "${1##*\]}" | sed 's/^://' ;;
        *)      printf '%s' "${1##*:}" ;;
    esac
}

# listen_addr 语法检查：IPv6 必须带方括号；裸 IPv6 会导致 bind 必败
check_listen_addr_syntax() {
    local spec port bad=0
    local specs
    specs=$(listen_specs) || { color_echo "$RED" "✗ $CONF_FILE 里没有可解析的 listen_addr 数组"; return 1; }
    if [ -z "$specs" ]; then
        color_echo "$RED" "✗ listen_addr 为空数组"; return 1
    fi
    while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        port=$(spec_port "$spec")
        case "$port" in
            ''|*[!0-9]*)
                color_echo "$RED" "✗ listen_addr '$spec' 缺少合法端口"; bad=1; continue ;;
        esac
        if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            color_echo "$RED" "✗ listen_addr '$spec' 端口越界（$port）"; bad=1
        fi
        case "$spec" in
            \[*\]*:*) : ;;                                  # [::]:1254 / [2a0c::1]:1254
            \[*|*\]*) color_echo "$RED" "✗ listen_addr '$spec' 方括号不成对"; bad=1 ;;
            *:*:*)
                color_echo "$RED" "✗ listen_addr '$spec' 里的 IPv6 必须加方括号（应写成 [${spec%:*}]:${port}）"
                bad=1 ;;
            *.*)  : ;;                                      # 0.0.0.0:1254 / 1.2.3.4:1254
            :*)   : ;;                                      # :1254 双栈通配
            *)    color_echo "$RED" "✗ listen_addr '$spec' 无法解析"; bad=1 ;;
        esac
    done <<EOF
$specs
EOF
    return $bad
}

# 服务进程是否活着（systemd / openrc / sysv / 裸进程 四层兜底）
svc_status_running() {
    case "$INIT_SYSTEM" in
        systemd) systemctl is-active --quiet cns-server 2>/dev/null && return 0 ;;
        openrc)  rc-service cns-server status >/dev/null 2>&1 && return 0 ;;
    esac
    if [ -f /run/cns-server.pid ]; then
        kill -0 "$(cat /run/cns-server.pid)" 2>/dev/null && return 0
    fi
    pgrep -f 'cns-server' >/dev/null 2>&1
}

# 重启后必须确认「真的在监听」：进程活着 != 端口 bind 成功。
# 旧实现只判断 svc_restart 是否报错，而 unit 里 ExecStart 失败会被 init 吞掉，
# 用户看到「安装成功」，实际是个空壳服务（客户端永远连不上）。
verify_running() {
    local port found=0 ports="" checked=0
    if ! svc_status_running; then
        color_echo "$RED" "✗ 服务进程未运行，日志尾部："
        tail -n 20 "$LOG_FILE" 2>/dev/null
        return 1
    fi
    while IFS= read -r spec; do
        [ -z "$spec" ] && continue
        port=$(spec_port "$spec")
        case "$port" in ''|*[!0-9]*) continue ;; esac
        checked=$((checked + 1))
        ports="$ports $port"
        if command -v ss >/dev/null 2>&1; then
            ss -lnt 2>/dev/null | grep -q ":$port " && found=1
        elif command -v netstat >/dev/null 2>&1; then
            netstat -lnt 2>/dev/null | grep -q ":$port " && found=1
        else
            # 退化路径：/proc/net/tcp*，状态 0A = LISTEN，本地地址尾段是端口的大写十六进制
            if awk '$4 == "0A" {print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null |
                   grep -q ":$(printf '%04X' "$port")\$"; then
                found=1
            fi
        fi
    done <<EOF
$(listen_specs 2>/dev/null)
EOF
    if [ "$found" = "1" ]; then
        color_echo "$GREEN" "✓ 监听正常（端口:${ports:- 未识别}）"
        return 0
    fi
    if [ "$checked" = "0" ]; then
        color_echo "$YELLOW" "⚠️  未能从 $CONF_FILE 提取端口，跳过监听检查"
        return 0
    fi
    color_echo "$RED" "✗ 进程在运行，但 listen_addr 的端口没有一个处于监听状态！"
    color_echo "$YELLOW" "  常见原因：IPv6 未加方括号导致 bind 失败 / 端口被占用 / 本机无该族地址"
    tail -n 20 "$LOG_FILE" 2>/dev/null
    return 1
}

modify_config() {
    check_root
    detect_os
    if [ ! -f "$CONF_FILE" ]; then
        color_echo "$RED" "❌ 未找到配置文件，请先执行安装！"
        return
    fi
    if command -v nano >/dev/null 2>&1; then
        nano "$CONF_FILE"
    else
        vi "$CONF_FILE"
    fi
    # 改完先验语法再重启：非法配置一旦重启成功但 bind 失败，服务就成了空壳
    if ! check_listen_addr_syntax; then
        color_echo "$RED" "✗ listen_addr 语法有误，已取消重启（避免把服务打成空壳）"
        color_echo "$YELLOW" "  正确写法：\":1254\"（双栈）、\"0.0.0.0:1254\"、\"[::]:1254\"、\"[2001:db8::1]:13872\""
        return 1
    fi
    svc_restart
    if verify_running; then
        color_echo "$GREEN" "✓ 配置文件已更新并重启服务！"
    else
        color_echo "$RED" "⚠️  服务已重启但未通过监听检查，请核对上面的日志"
        return 1
    fi
}

update_cns_server() {
    check_root
    detect_os
    detect_arch
    show_banner
    color_echo "$BLUE" "🔍 正在检查 cns-server 服务端更新 (架构: ${TARGET_ARCH})..."

    if [ ! -f "$BIN_PATH" ]; then
        color_echo "$YELLOW" "未检测到已安装的 cns-server，将直接进入安装流程。"
        install_cns_server
        return
    fi

    CURRENT_VER=$("${BIN_PATH}" --version 2>/dev/null || echo "未知版本")
    LOCAL_HASH=$(sha256sum "$BIN_PATH" 2>/dev/null | awk '{print $1}' || md5sum "$BIN_PATH" 2>/dev/null | awk '{print $1}' || echo "none")

    echo -e "● 当前已安装版本: ${YELLOW}${CURRENT_VER}${PLAIN} (特征码: ${LOCAL_HASH:0:8})"

    # 尝试多源获取最新远程静态二进制（顺序与安装路径一致：dist/ -> Releases -> 加速镜像）
    local UP_NAME="cns-server-${TARGET_ARCH}"
    TMP_BIN="/tmp/cns-server-update-${TARGET_ARCH}.$$"
    if ! fetch_one "$UP_NAME" "$TMP_BIN"; then
        color_echo "$RED" "❌ 获取最新服务端版本失败，请检查网络连接。"
        rm -f "$TMP_BIN"
        return 1
    fi

    # 更新路径同样必须校验：这是「把运行中的服务端二进制换掉」，被篡改的后果比首次安装更严重
    if ! verify_sha256 "$UP_NAME" "$TMP_BIN"; then
        rm -f "$TMP_BIN"
        return 1
    fi

    REMOTE_HASH=$(sha256sum "$TMP_BIN" 2>/dev/null | awk '{print $1}' || md5sum "$TMP_BIN" 2>/dev/null | awk '{print $1}' || echo "none2")
    chmod +x "$TMP_BIN"
    REMOTE_VER=$("$TMP_BIN" --version 2>/dev/null || echo "最新版本")

    if [ "$LOCAL_HASH" = "$REMOTE_HASH" ] && [ "$LOCAL_HASH" != "none" ]; then
        color_echo "$GREEN" "✓ 当前安装的服务端已经是最新版本，无需更新！"
        echo ""
        read -p "是否仍然强制重新替换并重启服务？(y/N): " FORCE_UPDATE
        if [[ ! "$FORCE_UPDATE" =~ ^[Yy]$ ]]; then
            rm -f "$TMP_BIN"
            return 0
        fi
    else
        color_echo "$GREEN" "🎉 检测到新版本服务端！准备执行平滑替换..."
        echo -e "● 本地当前版本: ${YELLOW}${CURRENT_VER}${PLAIN} (${LOCAL_HASH:0:8})"
        echo -e "● 远程最新版本: ${GREEN}${REMOTE_VER}${PLAIN} (${REMOTE_HASH:0:8})"
    fi

    color_echo "$BLUE" "正在替换旧服务端文件并重启服务..."
    # 停止服务并使用 install 命令原子覆盖，避免 Text file busy
    svc_stop 2>/dev/null || true
    install -m 755 "$TMP_BIN" "$BIN_PATH"
    rm -f "$TMP_BIN"

    # 重启并显示状态
    svc_restart
    sleep 1

    echo ""
    color_echo "$GREEN" "=========================================================="
    color_echo "$GREEN" "🎉 cns-server 服务端已成功更新并重启生效！"
    color_echo "$GREEN" "=========================================================="
    svc_status
}

uninstall_cns() {
    check_root
    detect_os
    read -p "确定要彻底卸载 cns-rs 服务端吗？(y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        svc_stop
        if [ "$INIT_SYSTEM" = "systemd" ]; then
            systemctl disable cns-server 2>/dev/null || true
            rm -f "$SYSTEMD_FILE"
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" = "openrc" ]; then
            rc-update del cns-server default 2>/dev/null || true
            rm -f "$OPENRC_FILE"
        fi
        rm -rf "$CONF_DIR" "$BIN_PATH" "$LOG_FILE"
        color_echo "$GREEN" "✓ cns-rs 已完全卸载干净！"
    fi
}

main_menu() {
    show_banner
    echo -e " 1. ${GREEN}安装 cns-server 服务端${PLAIN}"
    echo -e " 2. ${GREEN}检测并更新 cns-server 服务端${PLAIN}"
    echo -e " 3. ${BLUE}启动服务${PLAIN}"
    echo -e " 4. ${YELLOW}停止服务${PLAIN}"
    echo -e " 5. ${BLUE}重启服务${PLAIN}"
    echo -e " 6. 查看运行状态"
    echo -e " 7. 查看实时日志"
    echo -e " 8. 修改配置文件"
    echo -e " 9. ${RED}彻底卸载 cns-server${PLAIN}"
    echo -e " 0. 退出脚本"
    echo "----------------------------------------------------------"
    read -p "请输入选项 [0-9]: " OPTION
    case "$OPTION" in
        1) install_cns_server ;;
        2) update_cns_server ;;
        3) start_service ;;
        4) stop_service ;;
        5) restart_service ;;
        6) status_service ;;
        7) view_logs ;;
        8) modify_config ;;
        9) uninstall_cns ;;
        0) exit 0 ;;
        *) color_echo "$RED" "无效输入！" ;;
    esac
}

case "$1" in
    install)
        install_cns_server
        ;;
    update|upgrade)
        update_cns_server
        ;;
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        status_service
        ;;
    *)
        main_menu
        ;;
esac
