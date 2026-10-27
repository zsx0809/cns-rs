#!/usr/bin/env bash
# ==============================================================================
# cns-rs 一键快速安装与管理脚本 (CuteBi Network Suite - Rust Edition)
# GitHub: https://github.com/zsx0809/cns-rs
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
SERVICE_FILE="/etc/systemd/system/cns-server.service"

color_echo() {
    echo -e "${1}${2}${PLAIN}"
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        color_echo "$RED" "❌ 错误: 此脚本必须以 root 权限运行！请使用 sudo 或切换至 root 用户。"
        exit 1
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
        armv7l|armhf)
            TARGET_ARCH="armv7"
            ;;
        *)
            color_echo "$YELLOW" "⚠️ 未知架构 $ARCH，将尝试从源码编译或兼容模式安装。"
            TARGET_ARCH="unknown"
            ;;
    esac
}

show_banner() {
    clear
    echo -e "${BLUE}"
    echo "=========================================================="
    echo "       cns-rs 极速免流服务端一键安装管理脚本              "
    echo "       CuteBi Network Suite - Modern Rust Edition         "
    echo "       零 GC 抖动 | 1.5MB 微内核 | 4K 直播防断流          "
    echo "=========================================================="
    echo -e "${PLAIN}"
}

install_cns_server() {
    check_root
    show_banner
    color_echo "$GREEN" "🚀 开始安装 cns-rs 服务端..."

    # 1. 引导用户输入核心免流参数
    echo ""
    read -p "请输入服务端监听端口 [默认 1254]: " INPUT_PORT
    LISTEN_PORT="${INPUT_PORT:-1254}"

    DEFAULT_PWD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8 || echo "666888")
    read -p "请输入免流连接密码 [默认随机: $DEFAULT_PWD]: " INPUT_PWD
    CNS_PASSWORD="${INPUT_PWD:-$DEFAULT_PWD}"

    read -p "请输入代理头字段名 (Proxy-Key) [默认 Meng]: " INPUT_KEY
    PROXY_KEY="${INPUT_KEY:-Meng}"

    read -p "请输入默认伪装域名 (Host) [默认 mclient.alipay.com]: " INPUT_HOST
    HEADER_HOST="${INPUT_HOST:-mclient.alipay.com}"

    # 2. 安装目录与依赖
    mkdir -p "$CONF_DIR"
    if [ -x "$(command -v apt-get)" ]; then
        apt-get update -y && apt-get install -y curl tar
    elif [ -x "$(command -v yum)" ]; then
        yum install -y curl tar
    elif [ -x "$(command -v apk)" ]; then
        apk add curl tar
    fi

    # 3. 安装服务端二进制
    detect_arch
    color_echo "$YELLOW" "正在获取最新 cns-server 二进制 (${TARGET_ARCH})..."

    # 优先检测本地是否有现存编译产物，否则从 GitHub Release 下载
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "${SCRIPT_DIR}/target/release/cns-server" ]; then
        cp -f "${SCRIPT_DIR}/target/release/cns-server" "$BIN_PATH"
    elif [ -f "${SCRIPT_DIR}/cns-server" ]; then
        cp -f "${SCRIPT_DIR}/cns-server" "$BIN_PATH"
    else
        # 从官方 GitHub 发布版本下载预编译二进制
        DOWNLOAD_URL="https://github.com/zsx0809/cns-rs/releases/latest/download/cns-server-${TARGET_ARCH}"
        if curl -sL --fail "$DOWNLOAD_URL" -o "$BIN_PATH"; then
            color_echo "$GREEN" "✓ 从 GitHub Release 下载成功！"
        else
            color_echo "$YELLOW" "Release 暂未就绪，正在快速安装 Rust 并执行本地编译..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            source "$HOME/.cargo/env"
            cargo build --release -p cns-server --manifest-path "${SCRIPT_DIR}/Cargo.toml"
            cp -f "${SCRIPT_DIR}/target/release/cns-server" "$BIN_PATH"
        fi
    fi

    chmod +x "$BIN_PATH"

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

    # 5. 配置 systemd 后台守护服务
    cat > "$SERVICE_FILE" <<EOF
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
    systemctl restart cns-server

    # 6. 获取服务器公网 IP
    SERVER_IP=$(curl -s4 https://api.ipify.org || curl -s6 https://api64.ipify.org || echo "你的服务器公网IP")

    echo ""
    color_echo "$GREEN" "=========================================================="
    color_echo "$GREEN" "🎉 cns-rs 服务端已安装并成功启动！"
    color_echo "$GREEN" "=========================================================="
    echo -e "● 监听端口 : ${BLUE}${LISTEN_PORT}${PLAIN}"
    echo -e "● 连接密码 : ${BLUE}${CNS_PASSWORD}${PLAIN}"
    echo -e "● 代理 Key : ${BLUE}${PROXY_KEY}${PLAIN}"
    echo -e "● 伪装域名 : ${BLUE}${HEADER_HOST}${PLAIN}"
    echo -e "● 配置文件 : ${YELLOW}${CONF_FILE}${PLAIN}"
    echo ""
    color_echo "$YELLOW" "📱 客户端 (Android 免流模块) 节点配置请填写:"
    echo "----------------------------------------------------------"
    echo -e "{"
    echo -e "  \"cns_server\": \"${SERVER_IP}:${LISTEN_PORT}\","
    echo -e "  \"cns_password\": \"${CNS_PASSWORD}\","
    echo -e "  \"proxy_key\": \"${PROXY_KEY}\","
    echo -e "  \"header_host\": \"${HEADER_HOST}\""
    echo -e "}"
    echo "----------------------------------------------------------"
}

start_service() {
    check_root
    systemctl start cns-server
    color_echo "$GREEN" "✓ cns-rs 服务端已启动！"
}

stop_service() {
    check_root
    systemctl stop cns-server
    color_echo "$GREEN" "✓ cns-rs 服务端已停止！"
}

restart_service() {
    check_root
    systemctl restart cns-server
    color_echo "$GREEN" "✓ cns-rs 服务端已重启！"
}

status_service() {
    show_banner
    systemctl status cns-server --no-pager
}

view_logs() {
    journalctl -u cns-server -f -n 50
}

modify_config() {
    check_root
    if [ ! -f "$CONF_FILE" ]; then
        color_echo "$RED" "❌ 未找到配置文件，请先执行安装！"
        return
    fi
    if [ -x "$(command -v nano)" ]; then
        nano "$CONF_FILE"
    else
        vi "$CONF_FILE"
    fi
    systemctl restart cns-server
    color_echo "$GREEN" "✓ 配置文件已更新并重启服务！"
}

uninstall_cns() {
    check_root
    read -p "确定要彻底卸载 cns-rs 服务端吗？(y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop cns-server 2>/dev/null || true
        systemctl disable cns-server 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        rm -rf "$CONF_DIR" "$BIN_PATH"
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
