#!/usr/bin/env python3
"""musl 静态交叉链接器：把 rustc 的链接请求转交给 `zig cc`。

zig 自带完整的 musl 与 libunwind，因此不需要额外的 musl sysroot 就能产出
真正 `statically linked` 的服务端二进制（可直接扔进 128MB 小鸡 / OpenWrt）。

用法（由 scripts/build.sh 设置）：
    ZIG_MUSL_TARGET=x86_64-linux-musl \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=$(pwd)/scripts/zig-musl-cc.py \
    cargo build --release --target x86_64-unknown-linux-musl

rustc 会传入若干 zig/clang 不认的参数（自带的 crt 名、aarch64 专用的
--fix-cortex-a53-843419 等），这里统一剥掉，让 zig 自己挑正确的启动文件。
"""
import sys, os, shutil, subprocess

if shutil.which("zig") is None and not os.path.exists("/data/data/com.termux/files/usr/lib/zig"):
    sys.exit("zig-musl-cc: 找不到 zig。请安装 zig（apt install zig / pip install ziglang）")

target = os.environ.get("ZIG_MUSL_TARGET", "aarch64-linux-musl")
CRT = {"crt1.o", "crti.o", "crtn.o", "rcrt1.o", "Scrt1.o", "soinit.o", "solfini.o",
       "crtbegin.o", "crtbeginS.o", "crtbeginT.o", "crtend.o", "crtendS.o", "crtfastmath.o"}
args = sys.argv[1:]
out, skip_next = [], False
for a in args:
    if skip_next:
        out.append(a); skip_next = False; continue
    if a == "-o":
        out.append(a); skip_next = True; continue
    if os.path.basename(a) in CRT:
        continue                                  # zig 自带正确 crt
    if a in ("-Wl,--fix-cortex-a53-843419", "-nodefaultlibs", "-nostartfiles"):
        continue                                  # 由 zig 决定启动文件
    out.append(a)
zig = shutil.which("zig")
if zig is None:
    # 退而使用 pip 版 ziglang
    if os.system("python3 -c 'import ziglang' >/dev/null 2>&1") == 0:
        cmd = ["python3", "-m", "ziglang", "cc"]
    else:
        sys.exit("zig-musl-cc: 未找到 zig 可执行文件，也未安装 python ziglang 模块")
else:
    cmd = [zig, "cc"]
cmd += ["-target", target, "-static"] + out
sys.exit(subprocess.call(cmd))
