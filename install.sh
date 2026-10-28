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

GITHUB_RAW="https://raw.githubusercontent.com/zsx0809/cns-rs/main"
GITHUB_PROXY_RAW="https://ghfast.top/https://raw.githubusercontent.com/zsx0809/cns-rs/main"

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
    clear
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "       cns-rs 极速免流服务端一键安装管理脚本              "
    echo "       CuteBi Network Suite - Modern Rust Edition         "
    echo "       零 GC 抖动 | 1.5MB 微内核 | 纯静态多发行版免编译   "
    echo "=========================================================="
    echo -e "${PLAIN}"
}

download_binary() {
    detect_arch
    mkdir -p /usr/local/bin
    color_echo "$YELLOW" "正在获取适合当前系统的静态二进制服务端 (架构: ${TARGET_ARCH})..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
    LOCAL_BIN="${SCRIPT_DIR}/bin/cns-server-${TARGET_ARCH}"
    LOCAL_DIRECT="${SCRIPT_DIR}/cns-server-${TARGET_ARCH}"

    if [ -f "$LOCAL_BIN" ]; then
        color_echo "$GREEN" "✓ 发现本地已存在预编译二进制: $LOCAL_BIN"
        install -m 755 "$LOCAL_BIN" "$BIN_PATH"
        return 0
    fi

    if [ -f "$LOCAL_DIRECT" ]; then
        color_echo "$GREEN" "✓ 发现本地已存在预编译二进制: $LOCAL_DIRECT"
        install -m 755 "$LOCAL_DIRECT" "$BIN_PATH"
        return 0
    fi

    # 尝试多源下载预编译静态二进制
    URLS=(
        "${GITHUB_RAW}/bin/cns-server-${TARGET_ARCH}"
        "${GITHUB_PROXY_RAW}/bin/cns-server-${TARGET_ARCH}"
        "https://github.com/zsx0809/cns-rs/releases/latest/download/cns-server-${TARGET_ARCH}"
    )

    TMP_BIN="/tmp/cns-server-${TARGET_ARCH}.$$"
    DOWNLOADED=false
    for URL in "${URLS[@]}"; do
        color_echo "$YELLOW" "尝试下载: $URL"
        if curl -fSL --connect-timeout 10 --retry 2 "$URL" -o "$TMP_BIN"; then
            DOWNLOADED=true
            color_echo "$GREEN" "✓ 静态二进制下载完成！"
            break
        fi
    done

    if [ "$DOWNLOADED" != "true" ]; then
        color_echo "$RED" "❌ 无法自动下载预构建二进制，请检查网络连接。"
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
    read -p "请输入服务端监听端口 [默认 1254]: " INPUT_PORT
    LISTEN_PORT="${INPUT_PORT:-1254}"

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

    # 6. 获取服务器公网 IP (兼容 IPv4/IPv6，单 IPv6 环境优先使用物理网卡公网 IP)
    SERVER_IP=$(curl -s4 --connect-timeout 2 https://api.ipify.org 2>/dev/null || \
                curl -s6 --connect-timeout 2 https://api64.ipify.org 2>/dev/null || \
                ip -6 addr show scope global 2>/dev/null | grep -E "inet6 2[0-9a-f]{3}:" | awk '{print $2}' | cut -d/ -f1 | head -n 1 || \
                echo "你的服务器公网IP")

    if [[ "$SERVER_IP" =~ : ]]; then
        SERVER_ENDPOINT="[${SERVER_IP}]:${LISTEN_PORT}"
    else
        SERVER_ENDPOINT="${SERVER_IP}:${LISTEN_PORT}"
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
    svc_restart
    color_echo "$GREEN" "✓ 配置文件已更新并重启服务！"
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
    echo -e " 2. ${BLUE}启动服务${PLAIN}"
    echo -e " 3. ${YELLOW}停止服务${PLAIN}"
    echo -e " 4. ${BLUE}重启服务${PLAIN}"
    echo -e " 5. 查看运行状态"
    echo -e " 6. 查看实时日志"
    echo -e " 7. 修改配置文件"
    echo -e " 8. ${RED}彻底卸载 cns-server${PLAIN}"
    echo -e " 0. 退出脚本"
    echo "----------------------------------------------------------"
    read -p "请输入选项 [0-8]: " OPTION
    case "$OPTION" in
        1) install_cns_server ;;
        2) start_service ;;
        3) stop_service ;;
        4) restart_service ;;
        5) status_service ;;
        6) view_logs ;;
        7) modify_config ;;
        8) uninstall_cns ;;
        0) exit 0 ;;
        *) color_echo "$RED" "无效输入！" ;;
    esac
}

if [ "$1" = "install" ]; then
    install_cns_server
else
    main_menu
fi
