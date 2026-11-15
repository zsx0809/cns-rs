#!/usr/bin/env python3
"""
GitHub Actions CI 构建自动监控与构建产物同步脚本
- 监听当前 HEAD commit 的 CI 运行状态
- 成功后自动下载 artifact 并解压到 dist/ 目录
"""

import sys
import os
import time
import json
import urllib.request
import urllib.error
import zipfile
import io
import subprocess

REPO = "zsx0809/cns-rs"

def get_git_head_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception as e:
        print(f"[-] 获取本地 commit hash 失败: {e}")
        sys.exit(1)

def get_github_token():
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    # 从 git remote 提取
    try:
        remote_url = subprocess.check_output(["git", "remote", "get-url", "origin"], text=True).strip()
        if "ghp_" in remote_url:
            parts = remote_url.split("ghp_")
            token = "ghp_" + parts[1].split("@")[0]
            return token
    except Exception:
        pass
    # 从凭据文件提取
    cred_file = os.path.expanduser("/data/data/com.termux/files/home/projects/antigravity-test/服务器访问凭据（勿入库）.md")
    if os.path.exists(cred_file):
        try:
            with open(cred_file, "r") as f:
                for line in f:
                    if "ghp_" in line:
                        for word in line.split():
                            if word.startswith("ghp_"):
                                return word.strip("`'\" ,;")
        except Exception:
            pass
    return None

def api_request(url, token):
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "cns-rs-ci-watch")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()

def main():
    token = get_github_token()
    if not token:
        print("[-] 未找到有效的 GITHUB_TOKEN，请设置环境变量或检查凭据")
        sys.exit(1)

    commit_sha = get_git_head_commit()
    print(f"[*] 监控目标: {REPO} @ {commit_sha[:8]}")

    run_id = None
    # 轮询查找对应的 run
    for _ in range(30):
        url = f"https://api.github.com/repos/{REPO}/actions/runs?head_sha={commit_sha}"
        code, data = api_request(url, token)
        if code == 200:
            runs_info = json.loads(data)
            runs = runs_info.get("workflow_runs", [])
            if runs:
                run_id = runs[0]["id"]
                run_name = runs[0].get("name", "CI & Build")
                print(f"[+] 找到 Workflow Run: {run_name} (ID: {run_id})")
                break
        time.sleep(3)

    if not run_id:
        print("[-] 超时未检测到该 commit 的 workflow 启动，请确认已 push 到 GitHub")
        sys.exit(1)

    # 监控状态
    start_time = time.time()
    while True:
        url = f"https://api.github.com/repos/{REPO}/actions/runs/{run_id}"
        code, data = api_request(url, token)
        if code == 200:
            info = json.loads(data)
            status = info.get("status")
            conclusion = info.get("conclusion")
            elapsed = int(time.time() - start_time)
            print(f"[*] [{elapsed}s] 状态: {status} ... 结论: {conclusion or '进行中'}")

            if status == "completed":
                if conclusion == "success":
                    print("[+] CI 构建成功！开始拉取 Artifact...")
                    break
                else:
                    print(f"[-] CI 构建失败: {conclusion}")
                    sys.exit(2)
        time.sleep(8)

    # 获取 Artifact 并下载
    art_url = f"https://api.github.com/repos/{REPO}/actions/runs/{run_id}/artifacts"
    code, data = api_request(art_url, token)
    if code != 200:
        print(f"[-] 获取 artifacts 列表失败 (HTTP {code})")
        sys.exit(1)

    art_info = json.loads(data)
    artifacts = art_info.get("artifacts", [])
    target_art = None
    for a in artifacts:
        if a.get("name") == "cns-rs-dist":
            target_art = a
            break

    if not target_art:
        print("[-] 未在本次 run 中找到 cns-rs-dist 产物")
        sys.exit(1)

    download_url = target_art["archive_download_url"]
    print(f"[*] 正在下载产物: {target_art['name']} ({target_art.get('size_in_bytes', 0) // 1024} KB)...")

    code, zip_bytes = api_request(download_url, token)
    if code != 200:
        print(f"[-] 下载产物失败 (HTTP {code})")
        sys.exit(1)

    # 解压到 dist/
    os.makedirs("dist", exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        z.extractall("dist")

    # 赋予执行权限
    for root, _, files in os.walk("dist"):
        for file in files:
            p = os.path.join(root, file)
            if not p.endswith((".sha256", ".txt", ".zip")):
                try:
                    os.chmod(p, 0o755)
                except Exception:
                    pass

    print("[🎉] 产物已同步到 dist/ 目录！")
    for f in os.listdir("dist"):
        print(f"    - dist/{f}")

if __name__ == "__main__":
    main()
