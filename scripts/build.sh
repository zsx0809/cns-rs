#!/usr/bin/env bash
# ============================================================================
# cns-rs 产物构建
#
#   cns-server-x86_64   x86_64-unknown-linux-musl   真静态  -> VPS 服务端
#   cns-server-aarch64  aarch64-unknown-linux-musl  真静态  -> ARM 服务器/OpenWrt
#   cns-client-aarch64  aarch64-linux-android       bionic  -> 手机（模块内）
#   （三个产物只写在仓库根目录一份，与 README / install.sh / Releases 的指向一致）
#
# 为什么服务端用 musl、客户端用 Android：
#   服务端要在各种发行版/内核上「拷过去就能跑」，glibc 版本墙会直接导致
#   CentOS 7 之类跑不起来；musl 静态无此问题。
#   客户端跑在 Android 上，linker 必须是 /system/bin/linker64，
#   用 bionic 目标产物最小且不需要任何额外 .so。
#
# 用法:
#   bash scripts/build.sh                  # 构建全部三个产物到仓库根目录
#   bash scripts/build.sh --host           # 只构建当前架构（调试用）
#   bash scripts/build.sh --server-only    # 只构建服务端
#   bash scripts/build.sh --clean          # 构建后清理 target/ 释放空间
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERVER_ARCHES=()
BUILD_CLIENT=1
BUILD_SERVER=1
CLEAN_AFTER=0
HOST_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --host)         HOST_ONLY=1 ;;
        --client-only)  BUILD_SERVER=0 ;;
        --server-only)  BUILD_CLIENT=0 ;;
        --arch)         shift; SERVER_ARCHES+=("$1") ;;
        --clean)        CLEAN_AFTER=1 ;;
        -h|--help)      sed -n '2,26p' "$0"; exit 0 ;;
        *)              echo "未知参数: $1"; exit 1 ;;
    esac
    shift
done

log()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m ✓\033[0m %s\n' "$*"; }
die()  { printf '\033[31m ✗\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 工具链探测
# 允许用独立 sysroot（不污染系统 rustup），也允许直接用系统 cargo
if [ -x /opt/rust199/bin/cargo ]; then
    export PATH="/opt/rust199/bin:$PATH"
    log "使用独立工具链: $(rustc -V)"
elif command -v cargo >/dev/null 2>&1; then
    log "使用系统 cargo: $(rustc -V)"
else
    die "找不到 cargo"
fi

command -v zig >/dev/null 2>&1 || python3 -c 'import ziglang' 2>/dev/null \
    || die "需要 zig（apt install zig 或 pip install ziglang）用于 musl 静态交叉链接"

HOST_TRIPLE="$(rustc -Vv | sed -n 's/^host: //p')"
# 本机能否直接执行目标产物（用于 --version 自检）
case "$HOST_TRIPLE" in
    aarch64-*) HOST_TRIPLE_ARCH_RE="aarch64|arm64" ;;
    x86_64-*)  HOST_TRIPLE_ARCH_RE="x86-64|x86_64" ;;
    *)         HOST_TRIPLE_ARCH_RE="$HOST_TRIPLE" ;;
esac
NEED_TOOLCHAIN_PKG=0
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    [ -d "$(rustc --print sysroot)/lib/rustlib/$t" ] || NEED_TOOLCHAIN_PKG=1
done

CARGO="${CARGO:-cargo}"
if [ "$NEED_TOOLCHAIN_PKG" = "1" ] && [ "${RUSTUP_TOOLCHAIN:-}" != "" ]; then
    log "缺少 musl std，尝试 rustup target add"
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl >/dev/null 2>&1 || true
fi
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    [ -d "$(rustc --print sysroot)/lib/rustlib/$t" ] \
        || die "目标 $t 的 std 不存在。请先安装：
   方式 A（有 rustup）: rustup target add $t
   方式 B（无 rustup，本项目脚本做法）:
     从镜像下载 rust-std-<ver>-$t.tar.xz，解压后把
     <sysroot>/lib/rustlib/$t 合并进当前 sysroot，
     并保证 host 的 rustc 版本与 std 版本一致"
done

# 产物只落在仓库根目录一份。
# 曾经这里还镜像到 bin/，但 README 与 install.sh 的下载链接都以根目录为准，
# 同一二进制存两份就会出现「装了过期那份」的故障面；v0.2.1 起彻底取消镜像。
publish() {
    local src="$1" name="$2"
    install -m 755 "$src" "$name"
}

# ---------------------------------------------------------------- 构建函数
# $1=rust target  $2=zig 目标三元组  $3=产物名  $4=package  $5=期望 file 特征
build_static() {
    local target="$1" zig="$2" out="$3" pkg="$4" want="$5"
    log "构建 $pkg -> $target"
    ZIG_MUSL_TARGET="$zig" CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}" \
        "$CARGO" build --release --target "$target" -p "$pkg"

    local src="target/$target/release/$pkg"
    [ -f "$src" ] || die "编译完成但找不到 $src"
    local desc; desc="$(file -b "$src")"
    echo "    $desc"
    # 断言静态：README 宣称「纯静态免依赖」，必须可验证
    if ! echo "$desc" | grep -qi "$want"; then
        die "$src 不是期望的「$want」产物，装到别的发行版上会跑不起来"
    fi
    # 真跑一次 --version，静态产物在任何环境都该立刻可执行
    if echo "$desc" | grep -qiE "$HOST_TRIPLE_ARCH_RE"; then
        "$src" --version >/dev/null 2>&1 || die "$src --version 执行失败"
        ok "  $out --version 自检通过"
    fi
    publish "$src" "$out"
    ok "./$out ($(du -h "$out" | cut -f1))"
}

# 在多个常见命名里挑一个真正存在的 Android 编译器
detect_android_cc() {
    local prefix="$1"
    local cands=(
        "${CC_aarch64_linux_android:-}"
        "$prefix/bin/aarch64-linux-android-clang"
        "$prefix/bin/aarch64-linux-android24-clang"
        "$prefix/bin/aarch64-linux-android21-clang"
        "$prefix/bin/aarch64-linux-android-gcc"
        "${ANDROID_NDK_ROOT:-}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang"
    )
    local c
    for c in "${cands[@]}"; do
        [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return 0; }
    done
    return 1
}

build_android() {
    local out="cns-client-aarch64"
    log "构建 cns-client -> aarch64-linux-android (bionic)"
    local prefix="${TERMUX_PREFIX:-/data/data/com.termux/files/usr}"
    local cc
    cc="$(detect_android_cc "$prefix")" || die "找不到 Android 交叉编译器（试过 aarch64-linux-android-clang / ...24-clang / android-gcc / \$ANDROID_NDK_ROOT）
   本项目默认使用 Termux 自带的 android 工具链：pkg install rust-bin 或 apt 里等价物"
    log "  使用编译器: $cc"
    # 自检：这个编译器真的产出 bionic 动态链接物
    local probe="${TMPDIR:-/tmp}/cns-android-probe-$$.c"
    echo 'int main(void){return 0;}' >"$probe"
    if "$cc" "$probe" -o "${probe}.out" 2>/dev/null; then
        file -b "${probe}.out" | grep -qi 'linker64' \
            || die "$cc 产出的不是 Android 二进制：$(file -b "${probe}.out")"
    else
        die "$cc 无法编译最小程序，工具链不完整"
    fi
    rm -f "$probe" "${probe}.out"

    # Termux 的 cargo 自带 android std；若用别的 cargo 则要求 sysroot 里有该目标
    local acargo="${ANDROID_CARGO:-$prefix/bin/cargo}"
    [ -x "$acargo" ] || acargo="$CARGO"
    if [ "$acargo" = "$CARGO" ]; then
        [ -d "$(rustc --print sysroot)/lib/rustlib/aarch64-linux-android" ] \
            || die "当前 cargo 的 sysroot 没有 aarch64-linux-android std
   请用 Termux 内的 cargo 编译客户端：ANDROID_CARGO=$prefix/bin/cargo bash scripts/build.sh"
    fi

    # 关键：cargo 通过 PATH 解析 rustc。若 PATH 里 /opt/rust199 在前，
    # 用的是没有 android std 的 rustc，会报 "can't find crate for std"。
    PATH="$prefix/bin:$PATH" \
    CC_aarch64_linux_android="$cc" \
    CXX_aarch64_linux_android="${CXX_aarch64_linux_android:-${cc}++}" \
    AR_aarch64_linux_android="${AR_aarch64_linux_android:-$prefix/bin/aarch64-linux-android-ar}" \
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$cc" \
    CARGO_TARGET_DIR="${ANDROID_TARGET_DIR:-target-android}" \
    CARGO_HOME="${ANDROID_CARGO_HOME:-$prefix/var/cargo}" \
        "$acargo" build --release --target aarch64-linux-android -p cns-client

    local src="target-android/aarch64-linux-android/release/cns-client"
    [ -f "$src" ] || src="target/aarch64-linux-android/release/cns-client"
    [ -f "$src" ] || die "编译完成但找不到 cns-client 产物"
    local desc; desc="$(file -b "$src")"
    echo "    $desc"
    echo "$desc" | grep -qi 'linker64' \
        || die "$src 不是 Android bionic 产物（缺 /system/bin/linker64）"
    # file 对 arm64 ELF 的输出措辞是 "ARM aarch64" 或 "arm64"，两者都要接受
    echo "$desc" | grep -qiE 'aarch64|arm64' || die "$src 不是 arm64: $desc"
    publish "$src" "$out"
    ok "./$out ($(du -h "$out" | cut -f1))"
}

# ---------------------------------------------------------------- 执行
if [ "$HOST_ONLY" = "1" ]; then
    if [ "$BUILD_SERVER" = "1" ]; then
        build_static "$HOST_TRIPLE" "" "cns-server-host" cns-server "static\|dynamically linked" || true
    fi
    exit 0
fi

if [ "$BUILD_SERVER" = "1" ]; then
    if [ ${#SERVER_ARCHES[@]} -eq 0 ]; then
        SERVER_ARCHES=(x86_64 aarch64)
    fi
    for a in "${SERVER_ARCHES[@]}"; do
        case "$a" in
            x86_64)  build_static x86_64-unknown-linux-musl  x86_64-linux-musl  cns-server-x86_64  cns-server "static" ;;
            aarch64) build_static aarch64-unknown-linux-musl aarch64-linux-musl cns-server-aarch64 cns-server "static" ;;
            *) die "不支持的服务端架构: $a（可选 x86_64 / aarch64）" ;;
        esac
    done
fi

if [ "$BUILD_CLIENT" = "1" ]; then
    build_android
fi

# ---------------------------------------------------------------- 校验清单
# install.sh 会按 sha256sums.txt 校验下载，缺失就等于没有防篡改能力。
log "生成 SHA-256 清单"
: > sha256sums.txt
for f in cns-server-x86_64 cns-server-aarch64 cns-client-aarch64; do
    [ -f "$f" ] && sha256sum "$f" | sed "s|  |  |" >> sha256sums.txt
done
# 每个产物旁边放同名 .sha256（install.sh 首选形态）
while read -r sum name; do
    [ -n "${name:-}" ] && printf '%s  %s\n' "$sum" "$name" > "$name.sha256"
done < sha256sums.txt
ok "sha256sums.txt ($(wc -l < sha256sums.txt) 条)"
cat sha256sums.txt

echo
log "根目录产物:"
ls -l cns-server-x86_64 cns-server-aarch64 cns-client-aarch64 2>/dev/null | awk '{printf "  %10s  %s\n", $5, $9}'
echo
log "版本一致性:"
V="$(sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
for f in cns-server-x86_64 cns-server-aarch64 cns-client-aarch64; do
    [ -f "$f" ] || continue
    # 跨架构产物无法在本机执行，用 --version 的可执行性判断，否则只报文件大小
    if out=$("./$f" --version 2>/dev/null); then
        case "$out" in
            *"$V"*) echo "  ✓ $f -> $out" ;;
            *) die "$f 版本 '$out' 与 Cargo.toml 的 $V 不一致" ;;
        esac
    else
        echo "  · $f 本机不可执行（跨架构），跳过运行时版本校验"
    fi
done

if [ "$CLEAN_AFTER" = "1" ]; then
    log "清理构建残留"
    rm -rf target target-android
    ok "已删除 target/ 与 target-android/"
fi
