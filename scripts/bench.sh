#!/usr/bin/env bash
# ============================================================================
# cns-rs 可复现实测：吞吐 / 并发建连 / DNS 延迟 / 常驻内存
#
# 为什么需要它：README 曾写「1.5MB 微内核」「内存降低 10 倍」这类无法复核的数字。
# 本脚本把测量方法固化下来，任何人都能在自己的机器上重跑得到自己平台的数据。
#
# 用法:
#   bash scripts/bench.sh                     # 需要已存在 target/release 产物
#   CARGO_PATH=/opt/rust199/bin:$PATH bash scripts/bench.sh --build
#   BENCH_CONCURRENCY=512 BENCH_DURATION=20 bash scripts/bench.sh
#
# 依赖: bash / python3 / awk，无需外部压测工具。
#
# 方法学说明（关键，否则数字没有意义）：
# * 吞吐用**单向** source / sink 目标，不用 echo —— 同步回显会把带宽限制成
#   「一次往返传一片」，测出来的是延迟而不是吞吐。
# * 并发建连测的是「SOCKS5 握手 + 隧道 HTTP 伪装头 + 目标连接」的完整链路。
# * DNS 用一个本地 mock 上游，保证在无外网的机器上也能测出真实数据。
# * RSS 在负载之后读取，静置后会更低。
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

CONCURRENCY="${BENCH_CONCURRENCY:-256}"
DURATION="${BENCH_DURATION:-10}"
ROUNDS="${BENCH_ROUNDS:-50}"
SKIP_BUILD=1
[ "${1:-}" = "--build" ] && SKIP_BUILD=0
[ "${1:-}" = "--skip-build" ] && SKIP_BUILD=1
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && { sed -n '2,24p' "$0"; exit 0; }

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m ✓\033[0m %s\n' "$*"; }
die() { printf '\033[31m ✗\033[0m %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "需要 python3"

SERVER_BIN="${SERVER_BIN:-target/release/cns-server}"
CLIENT_BIN="${CLIENT_BIN:-target/release/cns-client}"

if [ "$SKIP_BUILD" = "0" ]; then
    say "构建 release"
    cargo build --release -p cns-server -p cns-client >/dev/null 2>&1 || die "构建失败"
fi
[ -x "$SERVER_BIN" ] || die "找不到 $SERVER_BIN（先跑 cargo build --release 或加 --build）"
[ -x "$CLIENT_BIN" ] || die "找不到 $CLIENT_BIN"
say "被测产物: $("$SERVER_BIN" --version 2>/dev/null) / $("$CLIENT_BIN" --version 2>/dev/null)"

WORK="$(mktemp -d)"
cleanup() {
    for f in "$WORK"/*.pid; do
        [ -e "$f" ] || continue
        kill "$(cat "$f")" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
P_S=$(free_port); P_S5=$(free_port); P_DNS=$(free_port)
P_SRC=$(free_port); P_SINK=$(free_port); P_ECHO=$(free_port)
# 隧道里的 tcpDNS 快速通道只认 :53（服务端按目标端口是否 53 分流），
# 所以 mock DNS 必须占 53；占不到就明确跳过 DNS 隧道项，而不是给出假数据。
P_FAKE_DNS=53
if python3 -c "
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
try:
    s.bind(('127.0.0.1',53))
except OSError:
    sys.exit(1)
finally:
    s.close()
" 2>/dev/null; then
    DNS_TUNNEL_TEST=1
    say "UDP 127.0.0.1:53 可用，将实测 DNS 隧道路径"
else
    DNS_TUNNEL_TEST=0
    P_FAKE_DNS=$(free_port)
    printf '\033[33m !\033[0m UDP 127.0.0.1:53 不可占用（需 root），DNS 的 A 记录隧道项将标记为 skip\n'
fi
PASS="bench-$$"

cat > "$WORK/server.json" <<JSON
{
  "listen_addr": ["127.0.0.1:${P_S}"],
  "proxy_key": "Meng", "udp_flag": "httpUDP",
  "encrypt_password": "${PASS}",
  "tcp_timeout": 60, "udp_timeout": 10,
  "handshake_timeout": 10, "dial_timeout": 10,
  "enable_tfo": false, "allow_private_targets": true,
  "max_connections": 4096, "max_connections_per_ip": 0
}
JSON

cat > "$WORK/client.json" <<JSON
{
  "socks5_listen": "127.0.0.1:${P_S5}",
  "dns_listen": "127.0.0.1:${P_DNS}",
  "cns_server": "127.0.0.1:${P_S}", "cns_password": "${PASS}",
  "proxy_key": "Meng", "udp_flag": "httpUDP",
  "header_host": "mclient.alipay.com",
  "enable_tfo": false, "timeout_seconds": 30,
  "dns_mode": "fixed", "dns_upstream": ["127.0.0.1:${P_FAKE_DNS}"],
  "block_ipv6": true, "enable_udp_tunnel": true
}
JSON

# ---------------- mock 目标群 ----------------
python3 - "$P_SRC" "$P_SINK" "$P_ECHO" "$P_FAKE_DNS" > "$WORK/target.log" 2>&1 <<'PY' &
import socket, threading, struct, sys
src_p, sink_p, echo_p, dns_p = (int(a) for a in sys.argv[1:5])
BLOB = b"\0" * (1 << 20)

def serve(port, handler):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(2048)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()

def source(c):
    try:
        while True:
            c.sendall(BLOB)
    except Exception:
        pass
    finally:
        c.close()

def sink(c):
    try:
        while True:
            if not c.recv(1 << 20):
                break
    except Exception:
        pass
    finally:
        c.close()

def echo(c):
    try:
        while True:
            d = c.recv(1 << 16)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
    finally:
        c.close()

def fake_dns():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", dns_p))
    except OSError as e:
        print(f"mock DNS bind :{dns_p} failed: {e}", flush=True)
        return
    print(f"mock DNS on :{dns_p}", flush=True)
    while True:
        data, addr = u.recvfrom(4096)
        if len(data) < 16:
            continue
        qtype = struct.unpack(">H", data[-4:-2])[0]
        qname = data[12:-4]
        head = data[0:2] + b"\x81\x80" + data[4:6]
        if qtype == 1:
            ancnt = b"\x00\x01"
            ans = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                   + bytes([127, 0, 0, 1]))
        else:
            ancnt = b"\x00\x00"; ans = b""
        u.sendto(head + ancnt + b"\x00\x00\x00\x00" + qname + data[-4:] + ans, addr)

threading.Thread(target=fake_dns, daemon=True).start()
for port, handler in ((src_p, source), (sink_p, sink), (echo_p, echo)):
    threading.Thread(target=serve, args=(port, handler), daemon=True).start()
threading.Event().wait()
PY
echo $! > "$WORK/target.pid"
sleep 0.6

"$SERVER_BIN" -c "$WORK/server.json" > "$WORK/s.log" 2>&1 &
echo $! > "$WORK/server.pid"
"$CLIENT_BIN" -c "$WORK/client.json" > "$WORK/c.log" 2>&1 &
echo $! > "$WORK/client.pid"
sleep 1.2
for f in server client target; do
    pid=$(cat "$WORK/$f.pid")
    [ -d "/proc/$pid" ] || die "$f 未能启动，见 $WORK/$f.log"
done

# ---------------- 1. 吞吐 ----------------
export PYTHONUNBUFFERED=1
say "1/4 吞吐（单向，各 ${DURATION}s；echo 回环仅作参照）"
python3 - "$P_S5" "$P_SRC" "$P_SINK" "$P_ECHO" "$DURATION" <<'PY'
import socket, sys, time
port, src_p, sink_p, echo_p, dur = (int(sys.argv[1]), int(sys.argv[2]),
                                    int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]))
CHUNK = b"\0" * 65536

def session(tport):
    sk = socket.create_connection(("127.0.0.1", port), timeout=15)
    # connect 之后 socket 回到阻塞模式：必须重新设定超时，否则 recv 可能永远等
    sk.settimeout(15)
    sk.sendall(b"\x05\x01\x00")
    if sk.recv(2) != b"\x05\x00":
        raise RuntimeError("socks auth")
    sk.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + tport.to_bytes(2, "big"))
    r = sk.recv(32)
    if len(r) < 3 or r[1] != 0:
        raise RuntimeError(f"connect rejected {r!r}")
    sk.settimeout(dur + 5)
    return sk

def run(tport, mode):
    total = 0
    sk = None
    try:
        sk = session(tport)
        deadline = time.time() + dur
        if mode == "down":
            while time.time() < deadline:
                d = sk.recv(1 << 16)
                if not d:
                    break
                total += len(d)
        else:
            while time.time() < deadline:
                sk.sendall(CHUNK)
                total += len(CHUNK)
    except Exception as e:
        print(f"    {mode} 中断: {e}")
    finally:
        if sk:
            try:
                sk.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sk.close()
    return total

for label, tport, mode in (("下载", src_p, "down"), ("上传", sink_p, "up")):
    t = run(tport, mode)
    print(f"  {label} 经隧道: {t/1e6:7.1f} MB / {dur:.0f}s => {t*8/dur/1e6:8.1f} Mbit/s")
PY
echo "  （回环带宽不是本项目的瓶颈；数字用于跨版本对比）"

# ---------------- 2. 并发建连 ----------------
say "2/4 并发建连 ${CONCURRENCY} 条（SOCKS5 + 隧道握手 + 目标连接）"
python3 - "$P_S5" "$P_ECHO" "$CONCURRENCY" <<'PY'
import socket, sys, threading, time
port, tport, n = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
ok = err = 0
lock = threading.Lock()
rejected = {}

def one():
    global ok, err
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=20)
        s.settimeout(20)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise RuntimeError("auth")
        s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + tport.to_bytes(2, "big"))
        r = s.recv(32)
        if len(r) < 3 or r[1] != 0:
            with lock:
                rejected[r[1] if len(r) > 1 else -1] = rejected.get(r[1] if len(r) > 1 else -1, 0) + 1
            raise RuntimeError("rejected")
        s.sendall(b"ping")
        s.recv(64)
        with lock:
            ok += 1
        s.close()
    except Exception:
        with lock:
            err += 1

ts = [threading.Thread(target=one) for _ in range(n)]
t0 = time.perf_counter()
for t in ts:
    t.start()
for t in ts:
    t.join()
el = time.perf_counter() - t0
rate = n / el if el > 0 else 0
print(f"  成功 {ok} / 失败 {err} / 总 {n}    用时 {el:.2f}s  建连速率 {rate:.0f} 会话/s")
if rejected:
    print(f"  SOCKS 拒绝码分布: {rejected}")
PY

# ---------------- 3. DNS ----------------
say "3/4 DNS 延迟（${ROUNDS} 次采样，中位数/min/max）"
DNS_TUNNEL_TEST=$DNS_TUNNEL_TEST python3 - "$P_DNS" "$ROUNDS" <<'PY'
import socket, struct, sys, time
port, rounds = int(sys.argv[1]), int(sys.argv[2])

def q(name, t, txid):
    b = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for l in name.split('.'):
        b += bytes([len(l)]) + l.encode()
    return b + b'\x00' + struct.pack(">HH", t, 1)

def probe(name, t, label, fresh_id=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    ts = []
    bad = 0
    for i in range(rounds):
        # fresh_id=False 时固定事务 ID，专门命中缓存路径
        txid = (0x1000 + i) if fresh_id else 0x2000
        t0 = time.perf_counter()
        try:
            s.sendto(q(name, t, txid), ("127.0.0.1", port))
            d, _ = s.recvfrom(4096)
            ts.append((time.perf_counter() - t0) * 1000)
        except Exception:
            bad += 1
    if not ts:
        print(f"  {label:<16} 全部失败 ({bad})")
        return
    ts.sort()
    print("  %-16s p50 %6.2f ms   p90 %6.2f ms   min %5.2f / max %6.2f ms   fail %d"
          % (label, ts[len(ts)//2], ts[int(len(ts)*0.9)], ts[0], ts[-1], bad))

import os
probe("bench-v6.test", 28, "AAAA 本地NODATA")
if os.environ.get("DNS_TUNNEL_TEST") == "1":
    probe("bench-a.test", 1, "A 首次(带隧道)")
    probe("bench-a.test", 1, "A 缓存命中", fresh_id=False)
else:
    print("  A 隧道/缓存     skip（无法占用 UDP 53；用 root 重跑可得完整数据）")
PY

# ---------------- 4. RSS ----------------
say "4/4 常驻内存 RSS（负载后即时采样）"
SP=$(cat "$WORK/server.pid"); CP=$(cat "$WORK/client.pid")
for pair in "cns-server:$SP" "cns-client:$CP"; do
    label=${pair%%:*}; pid=${pair##*:}
    if [ -d "/proc/$pid" ]; then
        rss=$(awk '/VmRSS/{print $2}' "/proc/$pid/status")
        thr=$(awk '/Threads/{print $2}' "/proc/$pid/status")
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
        printf "  %-11s RSS %6s KB   线程 %s   fd %s\n" "$label" "${rss:-?}" "${thr:-?}" "$fds"
    else
        printf "  %-11s 进程已退出\n" "$label"
    fi
done

echo
echo "注：以上为回环环境数字，用于同机跨版本对比；手机基带与跨国链路的真实体验"
echo "    请用 su -c /data/adb/modules/cns_rs/检测.sh 在设备上复测。"
