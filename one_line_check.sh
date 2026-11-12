#!/bin/bash
# One-Liner Bash Script để paste trực tiếp vào bất kỳ Terminal VPS nào cần kiểm tra nhanh:

echo "=== QUICK 2026 CVE AUDIT ON $(hostname) ($(hostname -I | awk '{print $1}')) ==="
echo "1. [CVE-2026-98432 Kernel TCP RCE] Kernel: $(uname -r) | MPTCP: $(sysctl -n net.mptcp.enabled 2>/dev/null) | Raw Drop Rule: $(iptables -t raw -S PREROUTING 2>/dev/null | grep -c u32)"
echo "2. [CVE-2026-111497 Node2Shell]    Node: $(node -v 2>/dev/null || echo 'NONE (Immune)') | libbrotli1: $(dpkg-query -W -f='${Version}' libbrotli1 2>/dev/null || echo 'N/A') | Nginx Deleted .so in RAM: $(grep brotli /proc/$(cat /run/nginx.pid 2>/dev/null)/maps 2>/dev/null | grep -c '(deleted)')"
echo "3. [CVE-2026-109618 PHP2Shell]     PHP: $(php -v 2>/dev/null | head -n 1 || echo 'NONE (Immune)')"
echo "4. [CVE-2026-42945 Nginx Rewrite]  Nginx rewrite/alias count: $(grep -rnE '^\s*(rewrite|alias)\s+' /etc/nginx/ 2>/dev/null | wc -l)"
echo "5. [Pending Security Upgrades]     $(apt-get -s upgrade 2>/dev/null | grep -i '^Inst' | grep -i security | wc -l) packages"
