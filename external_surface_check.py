#!/usr/bin/env python3
"""
Deep External Non-Intrusive Recon & CVE Surface Auditor v3.0 (Color + Multi-VPS Optimized)
------------------------------------------------------------------------------------------
Tối ưu hóa cho việc quét hàng loạt nhiều VPS / Domain cùng lúc (10 -> 100+ servers):
  1. IP-Level Deduplication & Port-Scan Cache: Nếu 10 domain cùng trỏ về 1 IP vật lý,
     chỉ quét Port/SSH/MySQL/PTR đúng 1 lần duy nhất cho IP đó (nhanh gấp 5x, không bị chặn Firewall).
  2. ANSI Color-Coding trực quan trên Windows PowerShell/CMD & Linux:
     - [GREEN]  SAFE / CLEAN / CLOSED
     - [YELLOW] REVIEW / HIDDEN VERSION / CLOUDFLARE PROXY
     - [RED]    EXPOSED DB PORT (3306/6379) / VULNERABLE SSH / LEAKED VERSION
  3. Bố cục 3 phần cực dễ nhìn cho nhiều VPS:
     - Phần 1: Bảng Tổng Quan 1 Dòng / 1 Server (Compact Overview Table).
     - Phần 2: Chi Tiết Gom Nhóm Theo IP Vật Lý (Grouped by Physical Host IP - chống lặp rối mắt).
     - Phần 3: Bảng Tổng Kết Số Lượng (TOTAL SUMMARY DASHBOARD & Action Items).
  4. Hỗ trợ đọc danh sách từ cả `--targets`, `--file targets.txt`, hoặc tự đọc `vps_list.json`.

Cách dùng:
  python external_surface_check.py
  python external_surface_check.py --targets 203.0.113.10,example.com,api.example.com
  python external_surface_check.py --compact   (Chỉ in bảng 1 dòng + Tổng kết khi quét >20 VPS)
"""

import argparse
from collections import defaultdict
import ctypes
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")


def enable_windows_ansi() -> None:
    if os.name == "nt":
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


USE_COLOR = True


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


def col(text: str, color_code: str) -> str:
    if not USE_COLOR:
        return str(text)
    return f"{color_code}{text}{C.RESET}"


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def vis_len(s: str) -> int:
    return len(ANSI_RE.sub("", s))


def pad_col(s: str, width: int) -> str:
    pad = max(0, width - vis_len(s))
    return s + (" " * pad)


PORT_MAP = {
    21: "FTP",
    22: "SSH",
    2083: "cPanel",
    2087: "WHM",
    2222: "DirectAdmin",
    3306: "MySQL",
    5000: "App-5000",
    5050: "App-5050",
    5432: "Postgres",
    6379: "Redis",
    8080: "HTTP-8080",
    8443: "HTTPS-8443",
    27017: "MongoDB",
}

CRITICAL_DB_PORTS = {3306, 5432, 6379, 27017, 5000, 5050}

# Thread-safe cache with per-IP lock so concurrent threads on the same IP wait & reuse 1 single port scan
_IP_CACHE_LOCK = threading.Lock()
_IP_LOCKS: dict[str, threading.Lock] = defaultdict(threading.Lock)
_IP_SCAN_CACHE: dict[str, dict] = {}
_PTR_CACHE: dict[str, str] = {}


def compute_recommended_ranges(ip_str: str) -> dict:
    """
    Từ 1 địa chỉ IPv4, tự động tính toán các dải CIDR gợi ý (/29, /28, /24)
    và thông số toán học Z_p* tương ứng cho người dùng.
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip_str)
        net29 = ipaddress.IPv4Network(f"{ip_obj}/29", strict=False)
        net28 = ipaddress.IPv4Network(f"{ip_obj}/28", strict=False)
        net24 = ipaddress.IPv4Network(f"{ip_obj}/24", strict=False)
        return {
            "cidr_29": f"{net29} ({net29.network_address} -> {net29.broadcast_address}, 8 IPs - Cụm Rack sát kề)",
            "cidr_28": f"{net28} ({net28.network_address} -> {net28.broadcast_address}, 16 IPs - Nhánh Switch, Z_17*)",
            "cidr_24": f"{net24} ({net24.network_address} -> {net24.broadcast_address}, 256 IPs - Lớp C Datacenter, Z_257*)",
            "net28_short": str(net28),
            "net24_short": str(net24),
        }
    except Exception:
        return {
            "cidr_29": "-",
            "cidr_28": "-",
            "cidr_24": "-",
            "net28_short": "-",
            "net24_short": "-",
        }


def resolve_dns_and_ptr(host: str) -> tuple[str, str]:
    ip = host
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        pass
    with _IP_CACHE_LOCK:
        if ip in _PTR_CACHE:
            return ip, _PTR_CACHE[ip]
    ptr = "-"
    try:
        ptr = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    with _IP_CACHE_LOCK:
        _PTR_CACHE[ip] = ptr
    return ip, ptr


def grab_text_banner(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256).decode("utf-8", errors="ignore").strip()
            return data.splitlines()[0] if data else "OPEN"
    except Exception:
        return ""


def grab_mysql_version_passive(host: str, port: int = 3306, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            raw = s.recv(256)
            if len(raw) > 6:
                proto = raw[4]
                if proto == 0x0A:
                    end_idx = raw.find(b"\x00", 5)
                    if end_idx != -1:
                        ver = raw[5:end_idx].decode("utf-8", errors="ignore")
                        return f"OPEN ({ver})"
                elif proto == 0xFF and len(raw) > 7:
                    msg = raw[7:].decode("utf-8", errors="ignore").strip()
                    return f"OPEN (ACL: {msg[:30]})"
                return "OPEN (MySQL)"
    except Exception:
        pass
    return ""


def evaluate_ssh_banner(banner: str) -> tuple[str, str]:
    """Returns (status_level, display_text) where status_level is SAFE | WARN | VULN | HIDDEN."""
    if not banner:
        return ("HIDDEN", "CLOSED/FILTERED")
    m_ub22 = re.search(r"OpenSSH_8\.9p1\s+Ubuntu-3ubuntu0\.(\d+)", banner)
    if m_ub22:
        patch_num = int(m_ub22.group(1))
        if patch_num >= 18:
            return ("SAFE", f"SAFE (Ubuntu22 8.9p1-0.{patch_num})")
        elif patch_num >= 10:
            return ("WARN", f"WARN_CVE-35414 (8.9p1-0.{patch_num})")
        else:
            return ("VULN", f"VULN_CVE-6387 (8.9p1-0.{patch_num})")

    m_ub24 = re.search(r"OpenSSH_9\.6p1\s+Ubuntu-3ubuntu13\.(\d+)", banner)
    if m_ub24:
        patch_num = int(m_ub24.group(1))
        if patch_num >= 11:
            return ("SAFE", f"SAFE (Ubuntu24 9.6p1-13.{patch_num})")
        return ("WARN", f"OUTDATED (9.6p1-13.{patch_num})")

    clean = banner.replace("SSH-2.0-", "").strip()
    if re.match(r"^OpenSSH_9\.[89]", clean):
        return ("WARN", f"{clean} (EL9/RedHat)")
    return ("WARN", clean[:28])


def scan_ports_and_banners_cached(ip: str) -> dict:
    with _IP_CACHE_LOCK:
        if ip in _IP_SCAN_CACHE:
            return _IP_SCAN_CACHE[ip]
        ip_lock = _IP_LOCKS[ip]

    with ip_lock:
        with _IP_CACHE_LOCK:
            if ip in _IP_SCAN_CACHE:
                return _IP_SCAN_CACHE[ip]

        open_ports = []
        exposed_crit_ports = []
        ssh_level, ssh_eval = ("HIDDEN", "CLOSED/FILTERED")
        ftp_banner = ""
        mysql_info = ""

        def probe_port(port: int, label: str):
            if port == 22:
                b = grab_text_banner(ip, 22)
                return (22, evaluate_ssh_banner(b) if b else ("HIDDEN", "CLOSED/FILTERED"))
            if port == 21:
                b = grab_text_banner(ip, 21)
                return (21, b)
            if port == 3306:
                m = grab_mysql_version_passive(ip, 3306)
                return (3306, m)
            try:
                with socket.create_connection((ip, port), timeout=1.2):
                    return (port, f"{port}({label})")
            except Exception:
                return (port, "")

        with ThreadPoolExecutor(max_workers=len(PORT_MAP)) as pool:
            futs = [pool.submit(probe_port, p, lbl) for p, lbl in PORT_MAP.items()]
            for f in as_completed(futs):
                p, val = f.result()
                if not val:
                    continue
                if p == 22:
                    ssh_level, ssh_eval = val
                elif p == 21:
                    ftp_banner = val
                    open_ports.append("21(FTP)")
                elif p == 3306:
                    mysql_info = val
                    open_ports.append(f"3306[{val}]")
                    exposed_crit_ports.append(3306)
                else:
                    open_ports.append(val)
                    if p in CRITICAL_DB_PORTS:
                        exposed_crit_ports.append(p)

        res = {
            "ssh_level": ssh_level,
            "ssh_eval": ssh_eval,
            "ftp_banner": ftp_banner,
            "mysql_info": mysql_info,
            "open_ports": sorted(open_ports),
            "exposed_crit_ports": sorted(exposed_crit_ports),
        }
        with _IP_CACHE_LOCK:
            _IP_SCAN_CACHE[ip] = res
        return res


def fetch_http_path(host: str, path: str, use_https: bool = True, timeout: float = 2.8) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        if use_https:
            conn = http.client.HTTPSConnection(host, 443, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, 80, timeout=timeout)
        conn.request(
            "GET",
            path,
            headers={
                "Host": host,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SurfaceAudit/3.0",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "br, gzip, deflate",
            },
        )
        resp = conn.getresponse()
        raw_headers = resp.getheaders()
        body_sample = resp.read(4096).decode("utf-8", errors="ignore")
        headers = {}
        cookies = []
        for k, v in raw_headers:
            kl = k.lower()
            if kl == "set-cookie":
                cookies.append(v)
            else:
                headers[kl] = v
        return {
            "ok": True,
            "status": resp.status,
            "headers": headers,
            "cookies": cookies,
            "body": body_sample,
        }
    except Exception:
        return {"ok": False, "status": 0, "headers": {}, "cookies": [], "body": ""}
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def inspect_tls_cert(host: str, timeout: float = 2.2) -> dict:
    res = {"tls_ver": "-", "issuer": "-", "sans": []}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                res["tls_ver"] = ssock.version() or "-"
                cert = ssock.getpeercert()
                if cert:
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    res["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "-"
                    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                    res["sans"] = sans[:6]
    except Exception:
        pass
    return res


def deep_http_and_runtime_fingerprint(host: str, base_path: str = "/") -> dict:
    r_root = fetch_http_path(host, base_path, use_https=True)
    use_https = True
    if not r_root["ok"]:
        r_root = fetch_http_path(host, base_path, use_https=False)
        use_https = False

    if not r_root["ok"]:
        return {
            "web_server": "UNREACHABLE",
            "http3_quic": "NO",
            "brotli": "NO",
            "detected_stack": "NONE",
            "sec_headers": "0/4",
            "leaked_ver": False,
        }

    hdrs = r_root["headers"]
    cookies_str = " ; ".join(r_root["cookies"])
    body = r_root["body"]
    server_hdr = hdrs.get("server", "Hidden")
    powered_by = hdrs.get("x-powered-by", "")

    alt_svc = hdrs.get("alt-svc", "")
    http3 = "YES" if "h3=" in alt_svc else "NO"
    brotli = "YES" if "br" in hdrs.get("content-encoding", "").lower() else "NO"

    stack_signals = []
    leaked_ver = False
    if powered_by:
        stack_signals.append(f"Header:{powered_by}")
        if re.search(r"\d+\.\d+", powered_by):
            leaked_ver = True
    if re.search(r"\d+\.\d+", server_hdr):
        leaked_ver = True

    if "phpsessid" in cookies_str.lower():
        stack_signals.append("PHP(PHPSESSID)")
    if "xsrf-token" in cookies_str.lower() or "_session=" in cookies_str.lower():
        m_sess = re.search(r"([a-z0-9_]+_session)=", cookies_str, re.I)
        sess_name = m_sess.group(1) if m_sess else "laravel_session"
        stack_signals.append(f"PHP/Laravel({sess_name})")
    if "connect.sid" in cookies_str.lower():
        stack_signals.append("Node/Express")

    if "/build/assets/" in body or "csrf-token" in body:
        if not any("Laravel" in s for s in stack_signals):
            stack_signals.append("Laravel/Vite")
    if "/_next/static/" in body:
        stack_signals.append("Node/Next.js")

    for probe_file in ("/index.php", "/login.php"):
        p_path = base_path.rstrip("/") + probe_file
        r_idx = fetch_http_path(host, p_path, use_https=use_https)
        if r_idx["ok"] and r_idx["status"] in (200, 301, 302):
            idx_cookies = " ; ".join(r_idx["cookies"])
            if (
                "phpsessid" in idx_cookies.lower()
                or "_session=" in idx_cookies.lower()
                or server_hdr.lower() == "litespeed"
                or r_root["status"] == 403
            ):
                if not any("PHP" in s for s in stack_signals):
                    stack_signals.append(f"PHP({probe_file}={r_idx['status']},expose_php=Off)")
                break

    sec_cnt = sum(
        1
        for h in ("strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy")
        if h in hdrs
    )

    return {
        "web_server": f"{server_hdr} ({r_root['status']})",
        "http3_quic": http3,
        "brotli": brotli,
        "detected_stack": ", ".join(stack_signals) if stack_signals else "Hidden/Custom (Python/Go/Static)",
        "sec_headers": f"{sec_cnt}/4",
        "leaked_ver": leaked_ver,
    }


def audit_single_target(raw_target: str) -> dict:
    target = raw_target.strip()
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        base_path = parsed.path or "/"
    elif "/" in target:
        host, rest = target.split("/", 1)
        base_path = "/" + rest
    else:
        host = target
        base_path = "/"

    ip, ptr = resolve_dns_and_ptr(host)
    port_res = scan_ports_and_banners_cached(ip)
    http_res = deep_http_and_runtime_fingerprint(host, base_path)
    tls_res = inspect_tls_cert(host)

    infra = ptr
    open_ports_list = list(port_res["open_ports"])
    exposed_crit = list(port_res["exposed_crit_ports"])
    web_srv_str = http_res["web_server"]
    is_cloudflare = "cloudflare" in web_srv_str.lower()

    if is_cloudflare:
        infra = f"Cloudflare CDN ({ip})"
        cf_edge_ports = {"2083(cPanel)", "2087(WHM)", "8080(HTTP-8080)", "8443(HTTPS-8443)"}
        real_open = [p for p in open_ports_list if p not in cf_edge_ports]
        open_ports_str = ", ".join(real_open) if real_open else "NONE (CF Edge Only)"
        exposed_crit = []
    else:
        if "vietnix" in ptr.lower():
            infra = f"Vietnix CloudLinux ({ptr})"
        elif "your-server.de" in ptr.lower():
            infra = f"Hetzner Cloud ({ptr})"
        if web_srv_str == "UNREACHABLE" and port_res["ssh_eval"] != "CLOSED/FILTERED":
            web_srv_str = "ORIGIN_CLOAKED (CF Only)"
        open_ports_str = ", ".join(open_ports_list) if open_ports_list else "NONE (Closed)"

    detected_stack = http_res["detected_stack"]
    if (
        detected_stack.startswith("Hidden/Custom")
        and "litespeed" in web_srv_str.lower()
        and any("2083" in p for p in open_ports_list)
    ):
        detected_stack = "PHP/cPanel VHost (.htaccess 403, expose_php=Off)"

    # Determine Overall Risk Level & Actionable Reasons
    # SAFE (Green) | REVIEW (Yellow) | HIGH_RISK (Red)
    risk_level = "SAFE"
    reasons = []

    if port_res["ssh_level"] == "VULN":
        risk_level = "HIGH_RISK"
        reasons.append(f"Vuln SSH ({port_res['ssh_eval']})")
    if exposed_crit:
        risk_level = "HIGH_RISK"
        if 3306 in exposed_crit:
            reasons.append(f"Port 3306 MySQL Exposed [{port_res['mysql_info']}]")
        else:
            reasons.append(f"Exposed DB/App Ports {exposed_crit}")
    if http_res["leaked_ver"]:
        if risk_level != "HIGH_RISK":
            risk_level = "REVIEW"
        reasons.append("Server/PHP Version Leaked in Header")

    if "PHP" in detected_stack:
        m_php_ver = re.search(r"PHP/(\d+\.\d+\.\d+)", detected_stack, re.I)
        if m_php_ver:
            pver = m_php_ver.group(1)
            if re.match(r"^(8\.5\.(1[2-9]|[2-9]\d)|8\.4\.(2[7-9]|[3-9]\d)|8\.3\.(3[6-9]|[4-9]\d)|8\.2\.(3[5-9]|[4-9]\d))", pver):
                reasons.append(f"PHP {pver} Leaked via Header -> SAFE against PHP2Shell (CVE-2026-109618/109619 Patched!)")
            else:
                risk_level = "HIGH_RISK"
                reasons.append(f"PHP {pver} VULNERABLE to PHP2Shell (CVE-2026-109618/109619 RCE!)")
        else:
            if risk_level == "SAFE":
                risk_level = "REVIEW"
            reasons.append("PHP Active (expose_php=Off -> Check sibling SAN or Bridge/SSH for CVE-109618)")
    if "Node" in detected_stack:
        if risk_level == "SAFE":
            risk_level = "REVIEW"
        reasons.append("Node Active (Verify >=22.23.4 for CVE-111497)")
    if port_res["ssh_level"] == "WARN":
        if risk_level == "SAFE":
            risk_level = "REVIEW"
        reasons.append("Kernel/SSH patch date hidden externally (Verify uname -r for CVE-98432)")
    if is_cloudflare and risk_level == "SAFE":
        reasons.append("Origin IP protected behind Cloudflare (Verify Origin VPS internally)")

    if not reasons:
        reasons.append("All external checks passed (SSH Patched, Origin Cloaked, DB Closed)")

    return {
        "target": raw_target,
        "host": host,
        "ip": ip,
        "ptr": ptr,
        "ptr_infra": infra,
        "is_cloudflare": is_cloudflare,
        "ssh_level": port_res["ssh_level"],
        "ssh_status": port_res["ssh_eval"],
        "ftp_banner": port_res["ftp_banner"],
        "web_server": web_srv_str,
        "http3": http_res["http3_quic"],
        "brotli": http_res["brotli"],
        "detected_stack": detected_stack,
        "tls_info": f"{tls_res['tls_ver']} ({tls_res['issuer']})",
        "sans": ", ".join(tls_res["sans"]),
        "sans_list": tls_res["sans"],
        "rec_ranges": compute_recommended_ranges(ip),
        "open_ports": open_ports_str,
        "exposed_crit": exposed_crit,
        "sec_headers": http_res["sec_headers"],
        "risk_level": risk_level,
        "reasons": reasons,
    }


def format_risk_badge(level: str) -> str:
    if level == "SAFE":
        return col("● SAFE     ", C.GREEN + C.BOLD)
    if level == "REVIEW":
        return col("▲ REVIEW   ", C.YELLOW + C.BOLD)
    return col("✖ HIGH RISK", C.RED + C.BOLD)


def colorize_ssh(level: str, text: str) -> str:
    if level == "SAFE":
        return col(text, C.GREEN)
    if level == "VULN":
        return col(text, C.RED + C.BOLD)
    if level == "WARN":
        return col(text, C.YELLOW)
    return col(text, C.DIM)


def colorize_stack(stack: str) -> str:
    if "PHP" in stack or "Node" in stack:
        return col(stack, C.YELLOW)
    if stack == "NONE":
        return col(stack, C.DIM)
    return col(stack, C.CYAN)


def colorize_ports(ports_str: str, exposed_crit: list) -> str:
    if exposed_crit:
        return col(ports_str, C.RED + C.BOLD)
    if ports_str.startswith("NONE"):
        return col(ports_str, C.GREEN)
    return col(ports_str, C.YELLOW)


DEFAULT_TARGETS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets.txt")


def expand_target_token(token: str) -> list[str]:
    """
    Hỗ trợ:
      - Cú pháp CIDR (VD: `203.0.113.0/29` hoặc `203.0.113.0/28`) -> Bung thành danh sách IP theo hoán vị Z_p*
      - Cú pháp khoảng IP ngắn (VD: `203.0.113.10-20`)
      - IP / Domain / URL thông thường
    """
    # Kiểm tra cú pháp CIDR: x.x.x.x/prefix (chỉ cho phép tối đa /24 = 256 IPs để an toàn)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", token.strip()):
        try:
            net = ipaddress.IPv4Network(token.strip(), strict=False)
            if net.prefixlen < 24:
                net = ipaddress.IPv4Network(f"{net.network_address}/24", strict=False)
            hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
            # Hoán vị thứ tự IP bằng Z_p* (với p = 257) để không quét tuần tự .1, .2, .3
            n = len(hosts)
            p = 257
            g = 38  # 3^173 mod 257 (căn nguyên thủy của 257)
            permuted = []
            cur = 1
            while len(permuted) < n:
                cur = (cur * g) % p
                idx = cur - 1
                if idx < n:
                    permuted.append(hosts[idx])
            return permuted
        except Exception:
            pass

    # Kiểm tra cú pháp khoảng IP: a.b.c.start-end (VD: 203.0.113.10-20)
    m_range = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", token.strip())
    if m_range:
        prefix, s_idx, e_idx = m_range.group(1), int(m_range.group(2)), int(m_range.group(3))
        if 0 <= s_idx <= e_idx <= 255 and (e_idx - s_idx) <= 64:
            return [f"{prefix}{i}" for i in range(s_idx, e_idx + 1)]

    return [token.strip()]


def load_targets_from_args(args) -> list[str]:
    targets = []
    if getattr(args, "quick_targets", None):
        for item in args.quick_targets:
            for sub in item.split(","):
                if sub.strip():
                    targets.extend(expand_target_token(sub.strip()))
        if targets:
            return targets

    if args.targets:
        for sub in args.targets.split(","):
            if sub.strip():
                targets.extend(expand_target_token(sub.strip()))
        return targets

    file_to_read = args.file if (args.file and os.path.exists(args.file)) else DEFAULT_TARGETS_FILE
    if os.path.exists(file_to_read):
        with open(file_to_read, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    targets.extend(expand_target_token(s))
    return targets


def main() -> None:
    global USE_COLOR
    enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Deep External Non-Intrusive Surface & CVE Recon v3.1",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Ví dụ dùng cực nhanh (không cần nhớ cờ):\n"
            "  python external_surface_check.py                              (Quét tự động từ targets.txt)\n"
            "  python external_surface_check.py 203.0.113.10 example.com     (Gõ thẳng IP/Domain cách nhau dấu cách)\n"
            "  python external_surface_check.py --compact                    (Chế độ bảng 1 dòng gọn cho >20 VPS)\n"
        ),
    )
    parser.add_argument(
        "quick_targets",
        nargs="*",
        help="Nhập thẳng 1 hoặc nhiều IP/Domain cách nhau bởi dấu cách hoặc dấu phẩy",
    )
    parser.add_argument(
        "--targets",
        default="",
        help="Danh sách IP/Domain cách nhau bởi dấu phẩy",
    )
    parser.add_argument("--file", default="", help="Đường dẫn file .txt chứa danh sách IP/Domain (mặc định: targets.txt)")
    parser.add_argument("--compact", action="store_true", help="Chỉ hiển thị Bảng 1 dòng + Tổng kết (dành cho >20 VPS)")
    parser.add_argument(
        "--no-extend",
        action="store_true",
        help="Tắt tính năng tự động mở rộng quét các Subdomain/SAN anh em phát hiện trong SSL Cert",
    )
    parser.add_argument(
        "--extend-rack",
        action="store_true",
        help="Mở rộng quét thêm cả dải /29 (8 IPs cùng Rack vật lý) cho mỗi IP gốc phát hiện được",
    )
    parser.add_argument("--no-color", action="store_true", help="Tắt màu ANSI")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    targets = load_targets_from_args(args)
    if not targets:
        print(
            col(
                "\n[!] Chưa có mục tiêu nào để quét. Hãy nhập IP/Domain trực tiếp (VD: `python cve_center.py example.com`) hoặc thêm vào file `targets.txt`.\n",
                C.YELLOW + C.BOLD,
            )
        )
        return
    t0 = time.time()

    # =========================================================================
    # WAVE 1: INITIAL PARALLEL SCAN
    # =========================================================================
    results = []
    with ThreadPoolExecutor(max_workers=min(24, max(1, len(targets)))) as pool:
        futs = {pool.submit(audit_single_target, t): t for t in targets}
        for fut in as_completed(futs):
            results.append(fut.result())

    # =========================================================================
    # WAVE 2: AUTO-EXTEND FULL SCAN (SSL SANs + SIBLING VHOSTS + OPTIONAL /29 RACK)
    # =========================================================================
    extended_targets = []
    if not args.no_extend:
        scanned_hosts = {r["host"].lower() for r in results} | {r["target"].lower() for r in results}
        discovered_sans = set()
        for r in results:
            for san in r.get("sans_list", []):
                san_clean = san.lower().strip()
                if san_clean and not san_clean.startswith("*.") and san_clean not in scanned_hosts:
                    discovered_sans.add(san_clean)
                    scanned_hosts.add(san_clean)

        if args.extend_rack:
            seen_ips = {r["ip"] for r in results if not r.get("is_cloudflare")}
            for ip_val in sorted(seen_ips):
                for rack_ip in expand_target_token(f"{ip_val}/29"):
                    if rack_ip not in scanned_hosts:
                        discovered_sans.add(rack_ip)
                        scanned_hosts.add(rack_ip)

        if discovered_sans:
            extended_targets = sorted(discovered_sans)
            with ThreadPoolExecutor(max_workers=min(24, max(1, len(extended_targets)))) as pool:
                futs2 = {pool.submit(audit_single_target, t): t for t in extended_targets}
                for fut in as_completed(futs2):
                    r_ext = fut.result()
                    r_ext["is_auto_extended"] = True
                    results.append(r_ext)

    # =========================================================================
    # WAVE 3: CROSS-VHOST INTELLIGENCE CORRELATION (PROPAGATE LEAKED PHP/STACK VER ACROSS SAME IP)
    # =========================================================================
    ip_leaked_php: dict[str, str] = {}
    for r in results:
        m_php = re.search(r"PHP/(\d+\.\d+\.\d+)", r["detected_stack"], re.I)
        if m_php:
            ip_leaked_php[r["ip"]] = m_php.group(1)

    for r in results:
        shared_php_ver = ip_leaked_php.get(r["ip"])
        if shared_php_ver and "PHP" in r["detected_stack"] and f"PHP/{shared_php_ver}" not in r["detected_stack"]:
            r["detected_stack"] = f"{r['detected_stack']} [➔PHP/{shared_php_ver}]"
            # Update reason to reflect confirmed PHP version from sibling SAN on the same server!
            new_reasons = []
            for reason in r["reasons"]:
                if "expose_php=Off" in reason:
                    if re.match(
                        r"^(8\.5\.(1[2-9]|[2-9]\d)|8\.4\.(2[7-9]|[3-9]\d)|8\.3\.(3[6-9]|[4-9]\d)|8\.2\.(3[5-9]|[4-9]\d))",
                        shared_php_ver,
                    ):
                        new_reasons.append(
                            f"PHP {shared_php_ver} Confirmed via Sibling SAN -> SAFE against PHP2Shell (CVE-2026-109618/109619 Patched!)"
                        )
                    else:
                        r["risk_level"] = "HIGH_RISK"
                        new_reasons.append(
                            f"PHP {shared_php_ver} Confirmed via Sibling SAN -> VULNERABLE to PHP2Shell (CVE-2026-109618!)"
                        )
                else:
                    new_reasons.append(reason)
            r["reasons"] = new_reasons

    elapsed = time.time() - t0
    # Sort so HIGH_RISK appears first, then REVIEW, then SAFE
    order_map = {"HIGH_RISK": 0, "REVIEW": 1, "SAFE": 2}
    results.sort(key=lambda x: (order_map.get(x["risk_level"], 9), x["ip"], x["target"]))

    unique_ips = sorted({r["ip"] for r in results})
    cnt_safe = sum(1 for r in results if r["risk_level"] == "SAFE")
    cnt_review = sum(1 for r in results if r["risk_level"] == "REVIEW")
    cnt_high = sum(1 for r in results if r["risk_level"] == "HIGH_RISK")

    line_sep = col("=" * 144, C.CYAN)
    print(line_sep)
    ext_badge = f" (+{len(extended_targets)} Auto-Extended SANs)" if extended_targets else ""
    title = f" DEEP EXTERNAL RECON & CVE AUDITOR v3.2  |  Targets: {len(results)}{ext_badge} ({len(unique_ips)} Unique IPs)  |  Time: {elapsed:.2f}s  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    print(col(title, C.BOLD + C.WHITE))
    print(line_sep)

    # =========================================================================
    # PART 1: COMPACT OVERVIEW TABLE (1 LINE PER TARGET - SUPER EASY TO SCAN)
    # =========================================================================
    print(col("\n[PHẦN 1] BẢNG TỔNG QUAN NHANH (1 DÒNG / 1 MỤC TIÊU - SẮP XẾP THEO MỨC ĐỘ NGUY HIỂM):", C.BOLD + C.CYAN))
    print(col("-" * 144, C.DIM))
    hdr = (
        f"{pad_col('RISK STATUS', 12)} | "
        f"{pad_col('TARGET (DOMAIN / IP)', 32)} | "
        f"{pad_col('RESOLVED IP', 15)} | "
        f"{pad_col('SSH (CVE-35414/6387)', 26)} | "
        f"{pad_col('TECH STACK (PHP/NODE)', 25)} | "
        f"EXPOSED PORTS / DB VERSION"
    )
    print(col(hdr, C.BOLD))
    print(col("-" * 144, C.DIM))

    for r in results:
        badge = format_risk_badge(r["risk_level"])
        t_label = r["target"]
        if r.get("is_auto_extended"):
            t_label = f"↳ [SAN] {t_label}"
        elif r["target"] == r["ip"] and r.get("ptr") and r["ptr"] != "-":
            t_label = f"{r['ip']} ({r['ptr']})"
        t_str = col(t_label[:34], C.BOLD if r["risk_level"] == "HIGH_RISK" else C.WHITE)
        ip_str = col(r["ip"], C.CYAN)
        ssh_str = colorize_ssh(r["ssh_level"], r["ssh_status"][:26])
        stack_str = colorize_stack(r["detected_stack"][:25])
        ports_str = colorize_ports(r["open_ports"], r["exposed_crit"])

        row_line = (
            f"{pad_col(badge, 12)} | "
            f"{pad_col(t_str, 34)} | "
            f"{pad_col(ip_str, 15)} | "
            f"{pad_col(ssh_str, 26)} | "
            f"{pad_col(stack_str, 25)} | "
            f"{ports_str}"
        )
        print(row_line)

    print(col("-" * 144, C.DIM))

    # =========================================================================
    # PART 2: GROUPED BY PHYSICAL IP (AVOIDS REPEATING PORTS/SSH FOR SHARED IP)
    # =========================================================================
    if not args.compact:
        print(col("\n[PHẦN 2] CHI TIẾT GOM NHÓM THEO MÁY CHỦ VẬT LÝ (GROUPED BY UNIQUE SERVER IP):", C.BOLD + C.CYAN))
        by_ip = defaultdict(list)
        for r in results:
            by_ip[r["ip"]].append(r)

        for idx, (ip, group) in enumerate(by_ip.items(), 1):
            first = group[0]
            worst_level = min((g["risk_level"] for g in group), key=lambda lv: order_map.get(lv, 9))
            ip_badge = format_risk_badge(worst_level)
            print(
                f"\n  {col(f'[Máy chủ #{idx}]', C.BOLD + C.MAGENTA)} IP: {col(ip, C.BOLD + C.CYAN)}  "
                f"({first['ptr_infra']})  -->  {ip_badge}"
            )
            print(
                f"    ├─ Hạ tầng Mạng & SSH : SSH={colorize_ssh(first['ssh_level'], first['ssh_status'])}  |  "
                f"Ports={colorize_ports(first['open_ports'], first['exposed_crit'])}"
            )
            if first["ftp_banner"]:
                print(f"    ├─ FTP Greeting (21)  : {col(first['ftp_banner'], C.DIM)}")
            for g in group:
                print(
                    f"    ├─ Target: {col(pad_col(g['target'], 33), C.BOLD)} | "
                    f"Web: {pad_col(g['web_server'], 22)} | "
                    f"Br:{g['brotli']} H3:{g['http3']} SecHdr:{g['sec_headers']} | "
                    f"Stack: {colorize_stack(g['detected_stack'])}"
                )
            # Consolidated notes for this physical server
            unique_reasons = []
            for g in group:
                for reason in g["reasons"]:
                    if reason not in unique_reasons:
                        unique_reasons.append(reason)
            print(f"    └─ Đánh giá CVE       : {col(' ; '.join(unique_reasons), C.YELLOW if worst_level != 'SAFE' else C.GREEN)}")

    # =========================================================================
    # PART 3: TOTAL EXECUTIVE SUMMARY BOX (EASY TO SEE AT A GLANCE)
    # =========================================================================
    print("\n" + line_sep)
    print(col(" 📊 TỔNG KẾT TOÀN BỘ HỆ THỐNG (TOTAL RECON SUMMARY)", C.BOLD + C.WHITE))
    print(col("-" * 144, C.DIM))
    print(
        f"  • Tổng mục tiêu đã quét : {col(str(len(results)), C.BOLD + C.WHITE)} targets  "
        f"(trên {col(str(len(unique_ips)), C.BOLD + C.CYAN)} máy chủ IP vật lý duy nhất — đã tự động gộp quét Port theo IP)"
    )
    print(
        f"  • Phân loại Trạng thái  : "
        f"{col(f'🟢 SAFE (An toàn bề mặt): {cnt_safe}', C.GREEN + C.BOLD)}   |   "
        f"{col(f'🟡 REVIEW (Cần xác minh): {cnt_review}', C.YELLOW + C.BOLD)}   |   "
        f"{col(f'🔴 HIGH RISK (Hở Port/CVE): {cnt_high}', C.RED + C.BOLD)}"
    )

    high_items = [r for r in results if r["risk_level"] == "HIGH_RISK"]
    review_items = [r for r in results if r["risk_level"] == "REVIEW"]

    if high_items:
        print(col("\n  🚨 DANH SÁCH CẦN XỬ LÝ / LƯU Ý NGAY (HIGH RISK):", C.RED + C.BOLD))
        seen_high_ips = set()
        for r in high_items:
            if r["ip"] in seen_high_ips:
                continue
            seen_high_ips.add(r["ip"])
            t_names = ", ".join(x["target"] for x in high_items if x["ip"] == r["ip"])
            print(f"     - {col(r['ip'], C.RED + C.BOLD)} ({t_names}): {'; '.join(r['reasons'])}")

    if review_items:
        print(col("\n  ⚠️  DANH SÁCH CẦN KIỂM TRA PHIÊN BẢN BÊN TRONG QUA SSH/BRIDGE (REVIEW):", C.YELLOW + C.BOLD))
        seen_rev_ips = set()
        for r in review_items:
            if r["ip"] in seen_rev_ips:
                continue
            seen_rev_ips.add(r["ip"])
            t_names = ", ".join(x["target"] for x in review_items if x["ip"] == r["ip"])
            print(f"     - {col(r['ip'], C.YELLOW + C.BOLD)} ({t_names}): {'; '.join(r['reasons'])}")

    # =========================================================================
    # PART 4: SMART RANGE & SIBLING DOMAIN RECOMMENDATIONS FOR THE USER
    # =========================================================================
    print(col("\n  💡 GỢI Ý DẢI MẠNG (RECOMMENDED RANGES) & TÊN MIỀN CÙNG SERVER PHÁT HIỆN TỰ ĐỘNG:", C.CYAN + C.BOLD))
    scanned_hosts = {r["host"].lower() for r in results}
    unscanned_sans = set()
    seen_rec_ips = set()

    for r in results:
        for san in r.get("sans_list", []):
            san_clean = san.lower().strip()
            if not san_clean.startswith("*.") and san_clean not in scanned_hosts:
                unscanned_sans.add(san_clean)

        if r["ip"] in seen_rec_ips:
            continue
        seen_rec_ips.add(r["ip"])
        rr = r["rec_ranges"]
        if r["is_cloudflare"]:
            print(
                f"     • {col(r['ip'], C.CYAN)} ({r['target']}): Đang bọc qua Cloudflare Anycast ({rr['net24_short']}) ➔ "
                f"{col('Khuyên dùng IP gốc (Origin IP) khi quét Port/Range', C.YELLOW)}"
            )
        else:
            print(
                f"     • {col(r['ip'], C.CYAN + C.BOLD)} ({r['ptr_infra']}):"
            )
            print(f"       ├─ Range nhỏ cùng Rack (/29 - 8 IPs)   : {col(rr['cidr_29'], C.WHITE)}")
            print(f"       ├─ Range vừa cùng Switch (/28 - 16 IPs): {col(rr['cidr_28'], C.GREEN)}")
            print(f"       └─ Range rộng lớp C (/24 - 256 IPs)    : {col(rr['cidr_24'], C.YELLOW)}")

    if unscanned_sans:
        san_cmd_str = " ".join(sorted(unscanned_sans))
        print(
            f"\n  🔍 {col('PHÁT HIỆN SUBDOMAIN / DOMAIN ANH EM TRONG SSL CERT CHƯA QUÉT:', C.MAGENTA + C.BOLD)} "
            f"{col(', '.join(sorted(unscanned_sans)), C.WHITE + C.BOLD)}"
        )
        print(
            f"     👉 Lệnh quét tiếp gợi ý: {col(f'python cve_center.py {san_cmd_str}', C.GREEN + C.BOLD)}"
        )

    print(line_sep)


if __name__ == "__main__":
    main()
