#!/usr/bin/env python3
"""
====================================================================================
  CVE 2026 SECURITY COMMAND CENTER (ALL-IN-ONE UNIFIED LAUNCHER)
====================================================================================
Cách dùng siêu gọn:
  1. Bấm đúp vào file `CHAY_KIEM_TRA_CVE.bat` (hoặc chạy `python cve_center.py`)
     -> Hiện Menu số [1] -> [6] trực quan.
  2. Hoặc gõ thẳng từ dòng lệnh:
     - Quét nhanh bất kỳ IP/Domain/CIDR nào:
         python cve_center.py 203.0.113.10 example.com
     - Quét toàn bộ danh sách trong `targets.txt`:
         python cve_center.py --all
     - Quét sâu qua SSH (nếu có quyền SSH trong `vps_list.json`):
         python cve_center.py --ssh
     - Tự động Vá Nóng 0ms Downtime qua SSH:
         python cve_center.py --fix
====================================================================================
"""

import ctypes
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECON_SCRIPT = os.path.join(BASE_DIR, "external_surface_check.py")
SSH_SCRIPT = os.path.join(BASE_DIR, "scan_multi_vps.py")
ANATOMY_SCRIPT = os.path.join(BASE_DIR, "cve_anatomy_explainer.py")
ALGO_SCRIPT = os.path.join(BASE_DIR, "algorithm_deepdive_simulator.py")
TARGETS_FILE = os.path.join(BASE_DIR, "targets.txt")
VPS_JSON_FILE = os.path.join(BASE_DIR, "vps_list.json")


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
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"


def run_py(script_path: str, extra_args: list[str] | None = None) -> None:
    cmd = [sys.executable, script_path] + (extra_args or [])
    subprocess.run(cmd)


def interactive_menu() -> None:
    enable_windows_ansi()
    while True:
        print(f"\n{C.CYAN}{'=' * 96}{C.RESET}")
        print(f"{C.BOLD}{C.WHITE} 🛡️  TRUNG TÂM KIỂM TRA & RÀ SOÁT LỖ HỔNG CVE 2026 (SECURITY COMMAND CENTER){C.RESET}")
        print(f"{C.CYAN}{'=' * 96}{C.RESET}")
        print(
            f"  {C.GREEN}{C.BOLD}[1]{C.RESET} 🌐 Quét nhanh 1 hoặc nhiều {C.BOLD}IP / Domain / Dải mạng CIDR{C.RESET} bất kỳ (Hỗ trợ /29, /28, /24)"
        )
        print(
            f"  {C.CYAN}{C.BOLD}[2]{C.RESET} 📋 Quét toàn bộ danh sách mục tiêu trong file {C.BOLD}targets.txt{C.RESET}"
        )
        print(
            f"  {C.MAGENTA}{C.BOLD}[3]{C.RESET} 🔐 Kiểm tra sâu bên trong các VPS qua {C.BOLD}SSH (Read-Only){C.RESET} (Đọc từ {C.DIM}vps_list.json{C.RESET})"
        )
        print(
            f"  {C.RED}{C.BOLD}[4]{C.RESET} ⚡ Tự động {C.BOLD}Vá Nóng 0ms Downtime{C.RESET} qua SSH cho các VPS trong {C.DIM}vps_list.json{C.RESET}"
        )
        print(
            f"  {C.YELLOW}{C.BOLD}[5]{C.RESET} 🧬 Mô phỏng Giải phẫu Cơ chế 4 Siêu CVE 2026 ({C.DIM}cve_anatomy_explainer.py - 100% Offline{C.RESET})"
        )
        print(
            f"  {C.GREEN}{C.BOLD}[6]{C.RESET} 📐 Mô phỏng Toán học Hoán vị {C.BOLD}Z_p* & Inverse SYN-Cookie{C.RESET} ({C.DIM}algorithm_deepdive_simulator.py{C.RESET})"
        )
        print(f"  {C.DIM}[0] Thoát{C.RESET}")
        print(f"{C.CYAN}{'-' * 96}{C.RESET}")

        choice = input(
            f"{C.BOLD}👉 Nhập lựa chọn [1-6] (hoặc gõ thẳng IP / Domain / CIDR để quét ngay): {C.RESET}"
        ).strip()
        if not choice or choice == "0":
            print(f"{C.GREEN}Đã thoát chương trình.{C.RESET}")
            break

        if choice == "1":
            print(f"\n  {C.CYAN}💡 Gợi ý cú pháp nhập mục tiêu:{C.RESET}")
            print(f"     • Quét đơn lẻ : {C.WHITE}example.com{C.RESET} hoặc {C.WHITE}203.0.113.10{C.RESET}")
            print(
                f"     • Quét dải CIDR: {C.GREEN}203.0.113.0/29{C.RESET} (8 IPs), {C.GREEN}203.0.113.0/28{C.RESET} (16 IPs), {C.YELLOW}203.0.113.0/24{C.RESET} (256 IPs)"
            )
            print(f"     • Quét đoạn IP : {C.WHITE}203.0.113.10-20{C.RESET}")
            raw_targets = input(
                f"  {C.YELLOW}Nhập IP / Domain / CIDR (cách nhau bởi dấu cách hoặc dấu phẩy): {C.RESET}"
            ).strip()
            if raw_targets:
                tokens = [t.strip() for t in raw_targets.replace(",", " ").split() if t.strip()]
                run_py(RECON_SCRIPT, tokens)
        elif choice == "2":
            run_py(RECON_SCRIPT, ["--file", TARGETS_FILE])
        elif choice == "3":
            run_py(SSH_SCRIPT, ["--config", VPS_JSON_FILE])
        elif choice == "4":
            confirm = input(
                f"  {C.RED}Xác nhận chạy Vá Nóng 0ms Downtime (--fix) cho danh sách VPS trong vps_list.json? (y/n): {C.RESET}"
            ).strip().lower()
            if confirm == "y":
                run_py(SSH_SCRIPT, ["--config", VPS_JSON_FILE, "--fix"])
        elif choice == "5":
            run_py(ANATOMY_SCRIPT)
        elif choice == "6":
            run_py(ALGO_SCRIPT)
        else:
            # Người dùng gõ thẳng IP hoặc Domain vào ô chọn Menu -> Tự động quét luôn!
            tokens = [t.strip() for t in choice.replace(",", " ").split() if t.strip()]
            run_py(RECON_SCRIPT, tokens)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        interactive_menu()
        return

    first = args[0].lower()
    if first == "--all":
        run_py(RECON_SCRIPT, ["--file", TARGETS_FILE] + args[1:])
    elif first == "--ssh":
        run_py(SSH_SCRIPT, ["--config", VPS_JSON_FILE] + args[1:])
    elif first == "--fix":
        run_py(SSH_SCRIPT, ["--config", VPS_JSON_FILE, "--fix"] + args[1:])
    elif first == "--anatomy":
        run_py(ANATOMY_SCRIPT)
    elif first == "--algo":
        run_py(ALGO_SCRIPT)
    else:
        run_py(RECON_SCRIPT, args)


if __name__ == "__main__":
    main()
