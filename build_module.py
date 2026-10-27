#!/usr/bin/env python3
import os
import zipfile
import stat

def build_module():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    src_dir = os.path.join(base_dir, "android-module")
    out_zip = os.path.join(base_dir, "cns-rs-v0.1.0-magisk-ksu-arm64.zip")

    if os.path.exists(out_zip):
        os.remove(out_zip)

    print(f"[*] Packaging Magisk/KernelSU module from: {src_dir}")
    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src_dir):
            for f in files:
                if f.endswith((".log", ".pid", ".tmp", ".bak")):
                    continue
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, src_dir)
                
                zinfo = zipfile.ZipInfo.from_file(full_path, arcname=rel_path)
                zinfo.external_attr = (stat.S_IFREG | 0o755) << 16
                with open(full_path, "rb") as fp:
                    zf.writestr(zinfo, fp.read())
                count += 1

    size_mb = os.path.getsize(out_zip) / (1024 * 1024)
    print(f"[✓] Successfully generated: {out_zip} ({count} files, {size_mb:.2f} MB)")

if __name__ == "__main__":
    build_module()
