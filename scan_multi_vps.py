#!/usr/bin/env python3
"""
Multi-VPS Parallel 2026 CVE Scanner & Zero-Downtime Hot-Patcher v2.0 (Color + Summary)
--------------------------------------------------------------------------------------
Quét song song nhiều VPS cùng lúc qua SSH (chỉ mất ~3-5 giây cho hàng chục VPS) để kiểm tra:
  1. CVE-2026-98432 : Linux Kernel IPv4/TCP & MPTCP RCE (CVSS 9.8)
  2. CVE-2026-111497: Node.js ("Node2Shell") & libbrotli1 Out-of-Bounds Write RCE (CVSS 9.2)
  3. CVE-2026-109618/109619: PHP ("PHP2Shell") Unauthenticated RCE (CVSS 9.2 - CISA KEV)
  4. CVE-2026-42945 / 15176: Nginx rewrite/alias Heap Overflow
  5. CVE-2026-35414 / 6387 : OpenSSH Server RCE / CA Bypass
  6. CVE-2026-109518: Ubuntu APT HTTP MitM RCE

Cách dùng:
  python scan_multi_vps.py
  python scan_multi_vps.py --hosts 203.0.113.10,198.51.100.20
  python scan_multi_vps.py --fix
"""

import argparse
import ctypes
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import paramiko

sys.stdout.reconfigure(encoding="utf-8")

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vps_list.json")
DEFAULT_KEY = os.path.expanduser("~/.ssh/id_ed25519")
USE_COLOR = True


def enable_windows_ansi() -> None:
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def col(text: str, color_code: str) -> str:
    if not USE_COLOR:
        return str(text)
    return f"{color_code}{text}{C.RESET}"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def pad_col(s: str, width: int) -> str:
    pad = max(0, width - len(ANSI_RE.sub("", s)))
    return s + (" " * pad)


REMOTE_AUDIT_SCRIPT = r"""
export LC_ALL=C
OS_NAME=$(grep -s '^PRETTY_NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
KERNEL=$(uname -r)

MPTCP=$(sysctl -n net.mptcp.enabled 2>/dev/null || echo "0")
RAW_DROP=$(iptables -t raw -S PREROUTING 2>/dev/null | grep -i -c "u32" || true)
KERNEL_SAFE="VULN"
if echo "$KERNEL" | grep -Eq '5\.15\.0-(20[2-9]|2[1-9][0-9])|6\.8\.0-(8[5-9]|9[0-9])'; then
    KERNEL_SAFE="PATCHED_KERNEL"
elif [ "$MPTCP" = "0" ] && [ "$RAW_DROP" -gt 0 ]; then
    KERNEL_SAFE="MITIGATED_RAM"
fi

NODE_VER=$(node -v 2>/dev/null || echo "NONE")
NODE_STATUS="IMMUNE"
if [ "$NODE_VER" != "NONE" ]; then
    if echo "$NODE_VER" | grep -Eq '^v(22\.(23\.[4-9]|2[4-9]\.)|24\.(22\.[1-9]|2[3-9]\.)|26\.(12\.[1-9]|1[3-9]\.))'; then
        NODE_STATUS="SAFE($NODE_VER)"
    else
        NODE_STATUS="VULN($NODE_VER)"
    fi
fi

BROTLI_PKG=$(dpkg-query -W -f='${Version}' libbrotli1 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' brotli 2>/dev/null || echo "NONE")
BROTLI_RAM_DEL="0"
if [ -f /run/nginx.pid ]; then
    NPID=$(cat /run/nginx.pid 2>/dev/null)
    if [ -n "$NPID" ] && [ -r "/proc/$NPID/maps" ]; then
        BROTLI_RAM_DEL=$(grep "brotli" "/proc/$NPID/maps" 2>/dev/null | grep -c "(deleted)" || true)
    fi
fi
BROTLI_STATUS="SAFE"
if echo "$BROTLI_PKG" | grep -q "1.0.9-2build6"; then
    BROTLI_STATUS="VULN_DISK"
elif [ "$BROTLI_RAM_DEL" -gt 0 ]; then
    BROTLI_STATUS="VULN_RAM_DEL"
fi

PHP_VER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo "NONE")
PHP_STATUS="IMMUNE"
if [ "$PHP_VER" != "NONE" ]; then
    if echo "$PHP_VER" | grep -Eq '^(8\.5\.(1[2-9]|[2-9][0-9])|8\.4\.(2[7-9]|[3-9][0-9])|8\.3\.(3[6-9]|[4-9][0-9])|8\.2\.(3[5-9]|[4-9][0-9]))'; then
        PHP_STATUS="SAFE($PHP_VER)"
    else
        PHP_STATUS="VULN($PHP_VER)"
    fi
fi

NGINX_REWRITES=$(grep -rnE '^\s*(rewrite|alias)\s+' /etc/nginx/ 2>/dev/null | wc -l)
PENDING_SEC=$(apt-get -s upgrade 2>/dev/null | grep -i '^Inst' | grep -i 'security' | wc -l)

echo "RESULT|$OS_NAME|$KERNEL|$KERNEL_SAFE|$NODE_STATUS|$BROTLI_PKG|$BROTLI_STATUS|$PHP_STATUS|$NGINX_REWRITES|$PENDING_SEC"
"""

REMOTE_FIX_SAFE_SCRIPT = r"""
export DEBIAN_FRONTEND=noninteractive
sysctl -w net.mptcp.enabled=0 >/dev/null 2>&1 || true
sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null 2>&1 || true
cat << 'EOF' > /etc/sysctl.d/99-cve-2026-98432.conf
net.mptcp.enabled = 0
kernel.unprivileged_userns_clone = 0
EOF

if ! iptables -t raw -C PREROUTING -p tcp -m u32 --u32 "0>>24&0x0F=0x06:0x0F" -j DROP 2>/dev/null; then
    iptables -t raw -I PREROUTING 1 -p tcp -m u32 --u32 "0>>24&0x0F=0x06:0x0F" -j DROP 2>/dev/null || true
fi

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    NEEDRESTART_MODE=l apt-get install --only-upgrade -y libbrotli1 openssh-server apt >/dev/null 2>&1 || true
fi

if [ -f /run/nginx.pid ]; then
    OLD_PID=$(cat /run/nginx.pid 2>/dev/null)
    if [ -n "$OLD_PID" ] && grep "brotli" "/proc/$OLD_PID/maps" 2>/dev/null | grep -q "(deleted)"; then
        kill -USR2 "$OLD_PID" 2>/dev/null || true
        sleep 1.5
        if [ -f /run/nginx.pid.oldbin ]; then
            kill -WINCH "$OLD_PID" 2>/dev/null || true
            sleep 1
            kill -QUIT "$OLD_PID" 2>/dev/null || true
        fi
    fi
fi
"""


def check_single_vps(target: dict, apply_fix: bool = False) -> dict:
    name = target.get("name") or target["host"]
    host = target["host"]
    port = int(target.get("port", 22))
    user = target.get("user", "root")
    raw_key = target.get("key_file") or target.get("key_path") or ""
    key_file = os.path.expanduser(raw_key) if raw_key else ""
    password = target.get("password") or ""

    res = {
        "name": name,
        "host": host,
        "reachable": False,
        "error": "",
        "os": "-",
        "kernel": "-",
        "cve_98432_kernel": "-",
        "cve_111497_node": "-",
        "cve_111497_brotli": "-",
        "cve_109618_php": "-",
        "nginx_rewrites": "0",
        "pending_sec": "0",
        "overall": "ERROR",
    }

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs = {"hostname": host, "port": port, "username": user, "timeout": 12}
        if key_file and os.path.exists(key_file):
            connect_kwargs["key_filename"] = key_file
        if password:
            connect_kwargs["password"] = password

        ssh.connect(**connect_kwargs)
        res["reachable"] = True

        if apply_fix:
            _, out_fix, _ = ssh.exec_command(REMOTE_FIX_SAFE_SCRIPT, timeout=60)
            out_fix.read()

        _, stdout, stderr = ssh.exec_command(REMOTE_AUDIT_SCRIPT, timeout=30)
        output = stdout.read().decode("utf-8", errors="replace").strip()
        for line in output.splitlines():
            if line.startswith("RESULT|"):
                parts = line.split("|")
                if len(parts) >= 10:
                    res["os"] = parts[1]
                    res["kernel"] = parts[2]
                    res["cve_98432_kernel"] = parts[3]
                    res["cve_111497_node"] = parts[4]
                    res["cve_111497_brotli"] = f"{parts[6]} ({parts[5]})"
                    res["cve_109618_php"] = parts[7]
                    res["nginx_rewrites"] = parts[8].strip()
                    res["pending_sec"] = parts[9].strip()

                    has_vuln = any(
                        "VULN" in x
                        for x in (
                            res["cve_98432_kernel"],
                            res["cve_111497_node"],
                            res["cve_111497_brotli"],
                            res["cve_109618_php"],
                        )
                    )
                    if has_vuln:
                        res["overall"] = "VULN"
                    elif int(res["pending_sec"] or "0") > 0:
                        res["overall"] = "WARN"
                    else:
                        res["overall"] = "SAFE"
                break
        else:
            err_txt = stderr.read().decode("utf-8", errors="replace").strip()
            res["error"] = f"Unexpected output: {err_txt or output[:80]}"
    except Exception as e:
        res["error"] = str(e)
    finally:
        ssh.close()

    return res


def color_field(val: str) -> str:
    if "VULN" in val:
        return col(val, C.RED + C.BOLD)
    if "SAFE" in val or "IMMUNE" in val or "PATCHED" in val or "MITIGATED" in val:
        return col(val, C.GREEN)
    return col(val, C.YELLOW)


def main() -> None:
    global USE_COLOR
    enable_windows_ansi()

    parser = argparse.ArgumentParser(description="Multi-VPS Parallel 2026 CVE Scanner v2.0")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to vps_list.json")
    parser.add_argument("--hosts", default="", help="Comma-separated list of VPS IPs (overrides config)")
    parser.add_argument("--user", default="root", help="SSH username when using --hosts")
    parser.add_argument("--key", default=DEFAULT_KEY, help="SSH private key path when using --hosts")
    parser.add_argument("--password", default="", help="SSH password when using --hosts")
    parser.add_argument("--fix", "--fix-safe", dest="fix_safe", action="store_true", help="Apply 0ms Zero-Downtime hotfixes")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    targets = []
    if args.hosts.strip():
        for idx, h in enumerate([x.strip() for x in args.hosts.split(",") if x.strip()], start=1):
            targets.append(
                {
                    "name": f"VPS-{idx}",
                    "host": h,
                    "port": 22,
                    "user": args.user,
                    "key_file": args.key,
                    "password": args.password,
                }
            )
    else:
        if not os.path.exists(args.config):
            print(
                col(
                    f"\n[!] Chưa tìm thấy file cấu hình SSH: {args.config}\n"
                    f"👉 Hãy đổi tên hoặc copy file `vps_list.example.json` thành `vps_list.json` và điền IP/SSH của bạn vào đó.\n",
                    C.YELLOW + C.BOLD,
                )
            )
            sys.exit(1)
        with open(args.config, "r", encoding="utf-8") as f:
            targets = json.load(f)

    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(targets)))) as pool:
        futs = {pool.submit(check_single_vps, t, args.fix_safe): t for t in targets}
        for fut in as_completed(futs):
            results.append(fut.result())

    elapsed = time.time() - t0
    order_map = {"VULN": 0, "ERROR": 1, "WARN": 2, "SAFE": 3}
    results.sort(key=lambda x: (order_map.get(x["overall"], 9), x["name"]))

    line_sep = col("=" * 136, C.CYAN)
    print(line_sep)
    mode_str = "AUTO-HOTFIX (0ms Downtime)" if args.fix_safe else "READ-ONLY SSH AUDIT"
    print(
        col(
            f" MULTI-VPS 2026 CRITICAL CVE SCANNER v2.0 | Targets: {len(targets)} | Mode: {mode_str} | Time: {elapsed:.2f}s | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            C.BOLD + C.WHITE,
        )
    )
    print(line_sep)

    hdr = (
        f"{pad_col('STATUS', 11)} | "
        f"{pad_col('NAME / IP', 26)} | "
        f"{pad_col('KERNEL (CVE-98432)', 20)} | "
        f"{pad_col('NODE (CVE-111497)', 17)} | "
        f"{pad_col('BROTLI (CVE-111497)', 24)} | "
        f"{pad_col('PHP (CVE-109618)', 16)} | "
        f"SEC_UPD"
    )
    print(col(hdr, C.BOLD))
    print(col("-" * 136, C.DIM))

    cnt_safe = sum(1 for r in results if r["overall"] == "SAFE")
    cnt_warn = sum(1 for r in results if r["overall"] == "WARN")
    cnt_vuln = sum(1 for r in results if r["overall"] == "VULN")
    cnt_err = sum(1 for r in results if r["overall"] == "ERROR")

    for r in results:
        label = f"{r['name']} ({r['host']})"
        if not r["reachable"]:
            b = col("✖ SSH ERR  ", C.RED + C.BOLD)
            print(f"{pad_col(b, 11)} | {pad_col(label, 26)} | {col('[SSH ERROR] ' + r['error'], C.RED)}")
            continue

        if r["overall"] == "SAFE":
            b = col("● SAFE     ", C.GREEN + C.BOLD)
        elif r["overall"] == "WARN":
            b = col("▲ WARN     ", C.YELLOW + C.BOLD)
        else:
            b = col("✖ VULN     ", C.RED + C.BOLD)

        sec_col = col(r["pending_sec"], C.GREEN if r["pending_sec"] == "0" else C.YELLOW + C.BOLD)
        print(
            f"{pad_col(b, 11)} | "
            f"{pad_col(col(label[:26], C.WHITE), 26)} | "
            f"{pad_col(color_field(r['cve_98432_kernel']), 20)} | "
            f"{pad_col(color_field(r['cve_111497_node']), 17)} | "
            f"{pad_col(color_field(r['cve_111497_brotli']), 24)} | "
            f"{pad_col(color_field(r['cve_109618_php']), 16)} | "
            f"{sec_col}"
        )

    print(col("-" * 136, C.DIM))
    print(
        f" 📊 TỔNG KẾT (TOTAL SUMMARY):  "
        f"{col(f'🟢 SAFE: {cnt_safe}', C.GREEN + C.BOLD)}   |   "
        f"{col(f'🟡 PENDING UPDATES: {cnt_warn}', C.YELLOW + C.BOLD)}   |   "
        f"{col(f'🔴 VULNERABLE: {cnt_vuln}', C.RED + C.BOLD)}   |   "
        f"{col(f'⚪ SSH UNREACHABLE: {cnt_err}', C.DIM)}"
    )
    print(line_sep)


if __name__ == "__main__":
    main()
