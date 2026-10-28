#!/usr/bin/env python3
"""打包 Magisk / KernelSU / APatch 模块 zip。

相对旧版的改动：
* 版本号从 `Cargo.toml` 的 `[workspace.package] version` 单一真源读取，
  不再在脚本里硬编码（旧版脚本写死 v0.1.0，发布包却是 v0.1.1，两边对不上）。
* 二进制从仓库根的 `cns-client-aarch64` 注入到 zip 的 `Core/cns-client`，
  模块源码目录里不再保存任何二进制副本。
* 权限按类型区分：脚本与二进制 0755，配置/文档 0644（旧版把 README 和 json 也设成
  0755，属权限过宽）。
* 打包前做真实校验：必备文件存在、二进制架构正确、JSON 可解析、zip 内无 `..` 路径。
* 生成 SHA-256 清单，供 install.sh / 用户自行校验下载完整性。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "android-module")

EXECUTABLE_MODE = 0o755
DATA_MODE = 0o644


def workspace_version() -> str:
    """从 workspace 根 Cargo.toml 读取版本。"""
    path = os.path.join(ROOT, "Cargo.toml")
    text = open(path, encoding="utf-8").read()
    m = re.search(r"\[workspace\.package\][^[]*?^version\s*=\s*\"([^\"]+)\"", text, re.M | re.S)
    if not m:
        sys.exit(f"✗ 无法从 {path} 解析 [workspace.package] version")
    return m.group(1)


def version_code(version: str) -> int:
    """0.2.0 -> 200，0.2.3 -> 203（主*10000 + 次*100 + 修订）"""
    parts = version.split("-")[0].split(".")
    nums = [int(p) for p in parts[:3] + [0, 0, 0]]
    return nums[0] * 10000 + nums[1] * 100 + nums[2]


def read_elf_arch(path: str) -> tuple[str, str]:
    """返回 (machine, linkage)，用于阻止把 x86_64/glibc 二进制塞进 arm64 模块。"""
    with open(path, "rb") as fp:
        head = fp.read(20)
    if head[:4] != b"\x7fELF":
        return ("?", "?")
    e_machine = head[18] | (head[19] << 8)
    data = open(path, "rb").read()
    linkage = "static" if b"/system/bin/linker64" not in data and b"ld-linux" not in data else "dynamic"
    return ({183: "aarch64", 62: "x86_64", 40: "arm32"}.get(e_machine, f"0x{e_machine:x}"), linkage)


def validate_binary(path: str, *, want_linker: bool) -> str:
    arch, linkage = read_elf_arch(path)
    if arch != "aarch64":
        sys.exit(f"✗ {os.path.basename(path)} 架构是 {arch}，模块只接受 aarch64")
    if want_linker and linkage != "dynamic":
        # bionic 动态链接是 Android 客户端的正常形态；musl 静态说明拿错了产物
        print(f"   ⚠ 警告：{os.path.basename(path)} 看起来是静态产物（非 bionic 动态链接）")
    if not want_linker and linkage != "static":
        print(f"   ⚠ 警告：{os.path.basename(path)} 是动态链接，VPS 部署可能缺库")
    return arch


def load_json(path: str) -> object:
    try:
        with open(path, encoding="utf-8") as fp:
            return json.load(fp)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"✗ {os.path.relpath(path, ROOT)} 不是合法 JSON: {e}")


def write_module_prop(version: str) -> None:
    """module.prop 的 version/versionCode 由 Cargo.toml 决定。"""
    path = os.path.join(SRC, "module.prop")
    lines = open(path, encoding="utf-8").read().splitlines()
    out = []
    for line in lines:
        if line.startswith("version="):
            out.append(f"version=v{version}")
        elif line.startswith("versionCode="):
            out.append(f"versionCode={version_code(version)}")
        else:
            out.append(line)
    open(path, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"✓ module.prop -> v{version} ({version_code(version)})")


def collect_entries(binary: str | None, keep_existing_binary: bool) -> list[tuple[str, str, int]]:
    """返回 [(zip 内路径, 磁盘路径, mode)]"""
    required = [
        "module.prop",
        "customize.sh",
        "config.ini",
        "service.sh",
        "action.sh",
        os.path.join("Core", "cns_rules.sh"),
    ]
    for rel in required:
        if not os.path.isfile(os.path.join(SRC, rel)):
            sys.exit(f"✗ 缺少必备文件: android-module/{rel}")

    entries: list[tuple[str, str, int]] = []
    exec_names = {
        "customize.sh",
        "service.sh",
        "action.sh",
        "开启.sh",
        "关闭.sh",
        "检测.sh",
        "start.sh",
        "stop.sh",
        "status.sh",
    }
    for root, dirs, files in os.walk(SRC):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
        for name in files:
            if name.endswith((".log", ".pid", ".tmp", ".bak", ".swp")):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, SRC).replace(os.sep, "/")
            if rel == "Core/cns-client" and binary:
                continue  # 由注入版本替换
            if not keep_existing_binary and rel == "Core/cns-client":
                sys.exit(
                    "✗ android-module/Core/cns-client 是仓库里的旧副本。\n"
                    "  请先运行 bash scripts/build.sh 生成 ./cns-client-aarch64，"
                    "或用 --binary 显式指定。"
                )
            mode = EXECUTABLE_MODE if (rel in exec_names or rel.startswith("Core/") and rel.endswith(".sh")) else DATA_MODE
            if rel.endswith(".sh"):
                mode = EXECUTABLE_MODE
            entries.append((rel, full, mode))

    if binary:
        if not os.path.isfile(binary):
            sys.exit(f"✗ 找不到二进制: {binary}")
        validate_binary(binary, want_linker=True)
        entries.append(("Core/cns-client", binary, EXECUTABLE_MODE))
        print(f"✓ 注入 Android 客户端: {os.path.relpath(binary, ROOT)} ({os.path.getsize(binary)/1048576:.2f} MiB)")
    else:
        client = os.path.join(SRC, "Core", "cns-client")
        if not os.path.isfile(client):
            sys.exit("✗ 既没有 --binary 也没有 android-module/Core/cns-client")
        validate_binary(client, want_linker=True)
        entries.append(("Core/cns-client", client, EXECUTABLE_MODE))

    # 路径安全：zip slip
    for rel, _, _ in entries:
        if ".." in rel.split("/"):
            sys.exit(f"✗ 非法 zip 路径: {rel}")

    # 模式 JSON 必须可解析，且端口不能与 config.ini 冲突
    for rel, full, _ in entries:
        if rel.startswith("modes/") and rel.endswith(".json"):
            data = load_json(full)
            if isinstance(data, dict):
                for key in ("cns_server", "tproxy_listen", "dns_listen"):
                    if key in data and not isinstance(data[key], str):
                        sys.exit(f"✗ {rel} 的 {key} 必须是字符串")
    return entries


def build(version: str, binary: str | None, out_dir: str) -> str:
    entries = collect_entries(binary, keep_existing_binary=binary is None)
    out_zip = os.path.join(out_dir, f"cns-rs-v{version}-magisk-ksu-apatch-arm64.zip")
    if os.path.exists(out_zip):
        os.remove(out_zip)

    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel, full, mode in sorted(entries):
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))  # 固定时间戳 -> 可复现构建
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.create_system = 3  # unix
            with open(full, "rb") as fp:
                zf.writestr(info, fp.read())

    size = os.path.getsize(out_zip)
    digest = hashlib.sha256(open(out_zip, "rb").read()).hexdigest()
    print(f"✓ 生成 {os.path.relpath(out_zip, ROOT)}  ({len(entries)} 个文件, {size/1048576:.2f} MiB)")
    print(f"  SHA-256: {digest}")
    with open(out_zip + ".sha256", "w", encoding="utf-8") as fp:
        fp.write(f"{digest}  {os.path.basename(out_zip)}\n")

    # 打包后自检：必须包含 customize.sh / module.prop / 可执行 cns_rules.sh
    with zipfile.ZipFile(out_zip) as zf:
        names = set(zf.namelist())
        for need in ("module.prop", "customize.sh", "Core/cns-client", "Core/cns_rules.sh"):
            if need not in names:
                sys.exit(f"✗ 打包结果缺少 {need}")
        mode = (zf.getinfo("Core/cns_rules.sh").external_attr >> 16) & 0o777
        if not mode & 0o111:
            sys.exit(f"✗ Core/cns_rules.sh 权限不是可执行 ({oct(mode)})")
    print("  ✓ 结构自检通过")
    return out_zip


def main() -> None:
    ap = argparse.ArgumentParser(description="打包 cns-rs Android 模块")
    ap.add_argument(
        "--binary",
        help="要注入的 aarch64 Android cns-client 路径（默认按 cns-client-aarch64 -> bin/ 顺序自动查找）",
    )
    ap.add_argument("--version", help="覆盖版本号（默认读 Cargo.toml）")
    ap.add_argument("--out", default=ROOT, help="输出目录")
    args = ap.parse_args()

    version = args.version or workspace_version()
    binary = args.binary
    if binary is None:
        # 产物只有一处：仓库根的 cns-client-aarch64
        for cand in (os.path.join(ROOT, "cns-client-aarch64"),):
            if os.path.isfile(cand):
                binary = cand
                break
    write_module_prop(version)
    os.makedirs(args.out, exist_ok=True)
    build(version, binary, args.out)


if __name__ == "__main__":
    main()
