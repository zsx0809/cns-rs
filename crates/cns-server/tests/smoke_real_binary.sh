#!/usr/bin/env bash
# 真二进制端到端冒烟测试（不依赖 cargo，可在任意 Linux 上手动跑）：
#   1. 起 mock HTTP 目标
#   2. 起真实 cns-server 二进制
#   3. 起真实 cns-client 二进制（SOCKS5 入口）
#   4. curl --socks5-hostname 走完整隧道
#   5. 断言拿到目标返回内容
# 用法: bash crates/cns-server/tests/smoke_real_binary.sh [server_bin] [client_bin]
#       （在仓库根执行；默认取 dist/cns-server-<arch> 与 dist/cns-client-<arch>）
set -uo pipefail

# 裸文件名（如 cns-server-aarch64）会被当成 PATH 查找而报 command not found，
# 这里统一解析成相对路径，保证按 README 抄的命令能直接跑。
# 产物只存放在仓库的 dist/ 下（scripts/build.sh 的输出目录），所以裸名先看 dist/，
# 再看当前目录 —— 旧文档里的 `... smoke_real_binary.sh cns-server-aarch64 ...` 依然可用。
# 含任意 "/" 即视为路径（绝对或相对），原样使用。
resolve_bin() {
    case "$1" in
        */*) printf '%s\n' "$1" ;;
        *)   if [ -f "dist/$1" ]; then printf 'dist/%s\n' "$1"
             else printf './%s\n' "$1"; fi ;;
    esac
}
SERVER_BIN="$(resolve_bin "${1:-cns-server-$(uname -m)}")"
CLIENT_BIN="$(resolve_bin "${2:-cns-client-$(uname -m)}")"
PASS="cns-smoke-$(date +%s)"
TMP="$(mktemp -d)"
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

fail() { echo "✗ $*" >&2; exit 1; }
step() { echo "── $*"; }

[ -x "$SERVER_BIN" ] || fail "找不到可执行的服务端: $SERVER_BIN"
[ -x "$CLIENT_BIN" ] || fail "找不到可执行的客户端: $CLIENT_BIN"

PORT_S=12599; PORT_S5=10899; PORT_T=18099; DNS_PORT=16653

step "写入服务端配置（口令非空，关私网拦截以便测环回）"
cat > "$TMP/server.json" <<JSON
{
  "listen_addr": ["127.0.0.1:${PORT_S}"],
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "encrypt_password": "${PASS}",
  "tcp_timeout": 15,
  "udp_timeout": 5,
  "handshake_timeout": 5,
  "dial_timeout": 5,
  "enable_dns_tcp_over_udp": true,
  "enable_tfo": false,
  "allow_private_targets": true,
  "max_connections": 64,
  "max_connections_per_ip": 16
}
JSON

cat > "$TMP/client.json" <<JSON
{
  "socks5_listen": "127.0.0.1:${PORT_S5}",
  "dns_listen": "127.0.0.1:${DNS_PORT}",
  "cns_server": "127.0.0.1:${PORT_S}",
  "cns_password": "${PASS}",
  "proxy_key": "Meng",
  "udp_flag": "httpUDP",
  "header_host": "mclient.alipay.com",
  "enable_tfo": false,
  "timeout_seconds": 10,
  "dns_upstream": ["223.5.5.5:53"],
  "block_ipv6": true,
  "enable_udp_tunnel": true
}
JSON

step "启动 mock HTTP 目标"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$PORT_T" "$TMP/mock.txt" <<'PY' &
import sys, http.server, socketserver
port, note = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"CNS-SMOKE-OK " + open(note, "rb").read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
open(note, "wb").write(b"payload-v1")
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", port), H) as s:
    s.serve_forever()
PY
    PIDS+=("$!"); echo " 18099"
else
    fail "需要 python3 或 nc 作为 mock 目标"
fi
sleep 1

step "启动 cns-server"
"$SERVER_BIN" -c "$TMP/server.json" >"$TMP/server.log" 2>&1 &
SP=$!; PIDS+=("$SP")

step "启动 cns-client"
# 不设 -g：非 root 下切 GID 会失败，测试只要 SOCKS5 路径
# --no-dns：本用例只验证 TCP 隧道主链路；DNS 隧道路径需要占用 UDP 53，
#           由 scripts/bench.sh（root 环境）覆盖
"$CLIENT_BIN" -c "$TMP/client.json" --no-dns -t 17750 >"$TMP/client.log" 2>&1 &
CP=$!; PIDS+=("$CP")

for i in $(seq 1 30); do
    kill -0 "$SP" 2>/dev/null || { echo "--- server.log ---"; cat "$TMP/server.log"; fail "服务端进程退出"; }
    kill -0 "$CP" 2>/dev/null || { echo "--- client.log ---"; cat "$TMP/client.log"; fail "客户端进程退出"; }
    if command -v curl >/dev/null 2>&1 && curl -s -m 3 --socks5-hostname "127.0.0.1:${PORT_S5}" "http://127.0.0.1:${PORT_T}/" 2>/dev/null | grep -q "CNS-SMOKE-OK"; then
        step "✅ 端到端隧道可用（第 ${i} 次探测）"
        curl -s -m 3 --socks5-hostname "127.0.0.1:${PORT_S5}" "http://127.0.0.1:${PORT_T}/"
        echo
        exit 0
    fi
    sleep 1
done

echo "--- server.log ---"; tail -20 "$TMP/server.log"
echo "--- client.log ---"; tail -20 "$TMP/client.log"
fail "60 秒内未通过隧道取回内容"
