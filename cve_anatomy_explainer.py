#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=========================================================================================
MÔ PHỎNG GIẢI PHẪU CƠ CHẾ LÕI CÁC LỖ HỔNG CVE 2026 TRÊN LINUX SERVER (UBUNTU / DEBIAN)
File: cve_anatomy_explainer.py
=========================================================================================
MỤC ĐÍCH HỌC THUẬT & PHÒNG THỦ (100% OFFLINE / AN TOÀN TUYỆT ĐỐI):
  - Script này hoàn toàn độc lập với các công cụ quét mạng (external_surface_check.py)
    hay công cụ vá SSH (scan_multi_vps.py).
  - Không gửi bất kỳ gói tin mạng nào ra Internet. Toàn bộ quá trình chạy là mô phỏng
    cấu trúc dữ liệu Kernel C (struct inet_request_sock, kmalloc-64 slab, /proc/pid/maps)
    ngay trong bộ nhớ Python để minh họa trực quan:
      1. [CVE-2026-98432 - CVSS 9.8] Tại sao gói tin TCP có IPv4 Options (IHL > 5) gây ra
         đua luồng (Race Condition) dẫn đến Use-After-Free (UAF) con trỏ `ireq_opt` trong
         hàm `tcp_v4_syn_recv_sock()`, và cách bộ lọc toán học Bitwise `u32` tại bảng
         `raw PREROUTING` chặn đứng 100% ngay trước cửa ngõ Kernel.
      2. [CVE-2026-35414 - CVSS 8.1] Tại sao Banner `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`
         ĐÃ VÁ `regreSSHion` (CVE-2024-6387) nhưng VẪN DÍNH `SplitSSHell`
         (lỗi phân tách dấu phẩy trong chứng chỉ SSH Principal).
      3. [CVE-2026-109518 - CVSS 9.8] Cơ chế lệch pha trạng thái kiểm tra băm SHA-256
         khi APT (< 2.4.14) tự động retry tải gói qua HTTP.
      4. [CVE-2026-111497 - CVSS 9.2] Cơ chế tràn vòng đệm Brotli (`libbrotli1`) và lý do
         tại sao `nginx -s reload` (SIGHUP -> fork) KHÔNG XÓA được thư viện `.so (deleted)`
         dính lỗi khỏi RAM mà bắt buộc phải dùng Hot-Swap `SIGUSR2` (execve).

Cách chạy:
  python cve_anatomy_explainer.py
=========================================================================================
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Đảm bảo hiển thị tiếng Việt và khung bảng Unicode chuẩn trên Windows PowerShell / CMD
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def enable_windows_ansi() -> None:
    """Bật chế độ xử lý mã màu ANSI (ENABLE_VIRTUAL_TERMINAL_PROCESSING) trên Windows."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


class C:
    """Bảng mã màu ANSI trực quan cho báo cáo giải phẫu CVE."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"


# =========================================================================================
# PHẦN 1: MÔ PHỎNG GIẢI PHẪU CVE-2026-98432 (LINUX KERNEL TCP/IPv4 `ireq_opt` UAF)
# =========================================================================================
# Trong Linux Kernel (net/ipv4/tcp_ipv4.c), khi một kết nối TCP đang ở trạng thái bán mở
# (SYN_RECV), Kernel lưu thông tin trong `struct inet_request_sock`.
# Nếu gói SYN ban đầu có đính kèm IPv4 Options (tức trường IHL > 5, header dài > 20 bytes),
# Kernel cấp phát một khối nhớ 64-byte trong vùng Slab `kmalloc-64` và gán địa chỉ vào
# con trỏ `ireq->ireq_opt`.
# =========================================================================================

@dataclass
class SlabChunk64:
    """
    Đại diện cho một ô nhớ 64-byte trong vùng nhớ Kernel Slab (`kmalloc-64`).
    - addr: Địa chỉ bộ nhớ ảo trong Kernel Space (ví dụ: 0xffff888104a2c040).
    - allocated: True nếu đang được cấp phát hợp lệ, False nếu đã bị kfree() trả về freelist.
    - owner_tag: Tên cấu trúc đang sở hữu ô nhớ này.
    - payload_desc: Nội dung dữ liệu đang nằm trong ô nhớ.
    """
    addr: int
    allocated: bool = True
    owner_tag: str = "ip_options_rcu"
    payload_desc: str = "IPv4_RecordRoute_Option (24 bytes)"
    refcount: int = 1


@dataclass
class InetRequestSock:
    """
    Mô phỏng cấu trúc `struct inet_request_sock` trong `include/net/inet_sock.h`:
      struct inet_request_sock {
          struct request_sock req;
          struct ip_options_rcu __rcu *ireq_opt;
      };
    """
    client_ip: str
    server_port: int
    ireq_opt_ptr: Optional[ int ] = None  # Lưu địa chỉ con trỏ trỏ tới SlabChunk64


class KernelSlabSimulator:
    """
    Trình mô phỏng bộ cấp phát bộ nhớ `kmalloc-64` của Linux Kernel và hàm `tcp_v4_syn_recv_sock()`.
    """
    def __init__(self) -> None:
        self.slab_memory: Dict[int, SlabChunk64] = {}
        self.next_addr: int = 0xFFFF888104A2C040

    def kmalloc_64(self, owner: str, desc: str) -> int:
        """Cấp phát một khối nhớ 64-byte trong Kernel Space."""
        addr = self.next_addr
        self.next_addr += 0x40
        self.slab_memory[addr] = SlabChunk64(
            addr=addr,
            allocated=True,
            owner_tag=owner,
            payload_desc=desc,
            refcount=1,
        )
        return addr

    def kfree_64(self, addr: int,poison_desc: str = "POISON_FREED_SLAB_0x6b6b6b6b") -> None:
        """
        Giải phóng khối nhớ về lại freelist của `kmalloc-64`.
        Ngay sau khi giải phóng, một tiến trình/luồng khác trong Kernel có thể chiếm lại
        đúng địa chỉ này và ghi dữ liệu mới đè lên!
        """
        chunk = self.slab_memory[addr]
        chunk.allocated = False
        chunk.refcount = 0
        chunk.owner_tag = "FREED_OR_REALLOCATED_BY_OTHER_SUBSYSTEM"
        chunk.payload_desc = poison_desc


def explain_and_simulate_cve_2026_98432() -> None:
    """
    Trình bày và chạy mô phỏng từng nano-giây của CVE-2026-98432:
      - Kịch bản A: Máy chủ CHƯA VÁ (Server-A - Kernel < 5.15.0-202, không có rule `raw`).
      - Kịch bản B: Máy chủ ĐÃ KHÓA NÓNG 3 LỚP (Server-B - `iptables raw u32` + `RCU`).
    """
    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║ 1. GIẢI PHẪU CVE-2026-98432 (CVSS 9.8): LINUX KERNEL TCP/IPv4 `ireq_opt` USE-AFTER-FREE  ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝{C.RESET}")

    # -------------------------------------------------------------------------------------
    # BƯỚC 1.1: Giải thích toán học cấu trúc Byte đầu tiên của gói tin IPv4 (Version & IHL)
    # -------------------------------------------------------------------------------------
    normal_first_byte = 0x45   # Version = 4 (0100), IHL = 5 (0101) -> 5 * 4 = 20 bytes (Chuẩn)
    crafted_first_byte = 0x47  # Version = 4 (0100), IHL = 7 (0111) -> 7 * 4 = 28 bytes (Có 8B Options)

    print(f"\n  {C.BOLD}[1.1] Cơ chế kích hoạt con trỏ `ireq_opt` qua trường IHL (Internet Header Length):{C.RESET}")
    print(f"    • Byte đầu tiên của gói IPv4 chuẩn : {C.GREEN}0x{normal_first_byte:02X}{C.RESET} "
          f"➔ IHL = `0x{normal_first_byte:02X} & 0x0F` = {C.GREEN}{normal_first_byte & 0x0F}{C.RESET} "
          f"({(normal_first_byte & 0x0F) * 4} bytes) ➔ Không có Options ➔ `ireq_opt = NULL` (An toàn)")
    print(f"    • Byte đầu tiên có gắn IPv4 Options: {C.RED}0x{crafted_first_byte:02X}{C.RESET} "
          f"➔ IHL = `0x{crafted_first_byte:02X} & 0x0F` = {C.RED}{crafted_first_byte & 0x0F}{C.RESET} "
          f"({(crafted_first_byte & 0x0F) * 4} bytes) ➔ Có 8 bytes Options ➔ Kernel gọi `kmalloc-64` cấp phát `ireq_opt`!")

    # -------------------------------------------------------------------------------------
    # BƯỚC 1.2: Mô phỏng Kịch bản A — Đua luồng (Race Condition) trên máy chủ CHƯA VÁ
    # -------------------------------------------------------------------------------------
    print(f"\n  {C.BOLD}{C.RED}[1.2] KỊCH BẢN A — Trên máy chủ CHƯA VÁ (Server-A 203.0.113.50 - Không có `iptables raw`):{C.RESET}")
    slab = KernelSlabSimulator()

    # T = 0ns: Gói SYN có IHL = 7 đi vào cổng 443, Kernel tạo request_sock và cấp phát ireq_opt
    opt_addr = slab.kmalloc_64("ip_options_rcu", "IPv4_Options_Data (IHL=7)")
    ireq = InetRequestSock(client_ip="198.51.100.77", server_port=443, ireq_opt_ptr=opt_addr)
    print(f"    [T = 000 ns] Nhận gói SYN (IHL=7) tại 203.0.113.50:443")
    print(f"                 ➔ Kernel cấp phát `ireq->ireq_opt` tại địa chỉ Slab `{C.YELLOW}0x{opt_addr:016x}{C.RESET}`")

    # T = 20ns: 2 gói tin (ACK hoàn tất bắt tay & gói Subflow/Retransmit) rơi vào 2 nhân CPU cùng lúc!
    # Trong hàm `tcp_v4_syn_recv_sock()` bản cũ, cả 2 nhân CPU đều đọc `ireq->ireq_opt` mà không khóa RCU/xchg:
    cpu0_local_ptr = ireq.ireq_opt_ptr  # Nhân CPU 0 đọc địa chỉ 0xffff888104a2c040
    cpu1_local_ptr = ireq.ireq_opt_ptr  # Nhân CPU 1 cũng đọc cùng địa chỉ 0xffff888104a2c040
    print(f"    [T = 020 ns] {C.MAGENTA}[ĐUA LUỒNG ĐA NHÂN - SMP RACE CONDITION]{C.RESET}:")
    print(f"                 • {C.CYAN}CPU Core 0{C.RESET} (`tcp_v4_syn_recv_sock`) đọc `ireq->ireq_opt` = `0x{cpu0_local_ptr:016x}`")
    print(f"                 • {C.CYAN}CPU Core 1{C.RESET} (Luồng song song)         đọc `ireq->ireq_opt` = `0x{cpu1_local_ptr:016x}`")

    # T = 55ns: CPU Core 1 chạy nhanh hơn, giải phóng vùng nhớ `0xffff888104a2c040` về lại kmalloc-64
    assert cpu1_local_ptr is not None
    slab.kfree_64(cpu1_local_ptr, poison_desc="OVERWRITTEN_BY_ATTACKER_CONTROLLED_SLAB_DATA")
    ireq.ireq_opt_ptr = None
    print(f"    [T = 055 ns] • {C.CYAN}CPU Core 1{C.RESET} gọi `kfree(0x{cpu1_local_ptr:016x})` ➔ Ô nhớ trả về freelist!")
    print(f"                 • Một tác vụ khác lập tức chiếm lại ô nhớ `0x{cpu1_local_ptr:016x}` trên `kmalloc-64`.")

    # T = 95ns: CPU Core 0 tiếp tục gán `newinet->inet_opt = cpu0_local_ptr` và truy cập vùng nhớ đã bị giải phóng!
    assert cpu0_local_ptr is not None
    dangling_chunk = slab.slab_memory[cpu0_local_ptr]
    if not dangling_chunk.allocated:
        print(f"    [T = 095 ns] • {C.CYAN}CPU Core 0{C.RESET} gán `newinet->inet_opt = 0x{cpu0_local_ptr:016x}` và dereference:")
        print(f"                 ➔ {C.RED}{C.BOLD}[CRITICAL BUG TRIGGERED: USE-AFTER-FREE (UAF) TRONG KERNEL RING-0!]{C.RESET}")
        print(f"                 ➔ Trạng thái ô nhớ: `allocated={dangling_chunk.allocated}`, "
              f"Nội dung đọc phải: `{C.RED}{dangling_chunk.payload_desc}{C.RESET}`")

    # -------------------------------------------------------------------------------------
    # BƯỚC 1.3: Mô phỏng Kịch bản B — Chốt chặn 3 lớp Zero-Downtime trên Server-B
    # -------------------------------------------------------------------------------------
    print(f"\n  {C.BOLD}{C.GREEN}[1.3] KỊCH BẢN B — Khi áp dụng 3 Lớp Khóa Nóng Zero-Downtime (`iptables -t raw` + `RCU`):{C.RESET}")
    # Công thức toán học của lệnh: iptables -t raw -A PREROUTING -p tcp -m u32 --u32 "0>>24&0x0F=0x06:0x0F" -j DROP
    # Ta mô phỏng 32-bit đầu tiên của gói tin IPv4:
    test_packets: List[Tuple[str, int]] = [
        ("Gói HTTPS/SSH hợp lệ của người dùng (IHL=5, 20B Header)", 0x4500003C),
        ("Gói TCP dị dạng kích hoạt CVE-2026-98432 (IHL=7, 28B Header)", 0x47000044),
        ("Gói TCP dị dạng kích hoạt CVE-2026-98432 (IHL=15, 60B Header)", 0x4F000064),
    ]
    for desc, word0_32bit in test_packets:
        # Phép toán u32 trong Kernel: (word0_32bit >> 24) & 0x0F
        ihl_value = (word0_32bit >> 24) & 0x0F
        is_dropped_by_raw = (0x06 <= ihl_value <= 0x0F)
        status_str = (
            f"{C.RED}DROP NGAY TẠI BẢNG RAW (Trước khi chạm tới TCP Stack!){C.RESET}"
            if is_dropped_by_raw
            else f"{C.GREEN}ACCEPT (Đi vào Nginx/SSH bình thường với 0ms độ trễ){C.RESET}"
        )
        print(f"    • {desc:<62} | `0>>24&0x0F` = {ihl_value:2d} ➔ {status_str}")


# =========================================================================================
# PHẦN 2: MÔ PHỎNG CVE-2026-35414 ("SplitSSHell") VS CVE-2024-6387 ("regreSSHion")
# =========================================================================================
def explain_and_simulate_openssh_cves() -> None:
    """
    Giải thích tại sao `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`:
      1. ĐÃ VÁ `CVE-2024-6387` (regreSSHion).
      2. NHƯNG CHƯA VÁ `CVE-2026-35414` (SplitSSHell - lỗi phân tách dấu phẩy trong principals).
    """
    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║ 2. GIẢI PHẪU OPENSSH: TẠI SAO `3ubuntu0.10` VẪN DÍNH LỖ HỔNG CVE-2026-35414?             ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝{C.RESET}")

    print(f"\n  {C.BOLD}[2.1] Dòng thời gian các bản vá OpenSSH 8.9p1 trên Ubuntu 22.04 LTS:{C.RESET}")
    timeline = [
        ("1:8.9p1-3ubuntu0.7",  "Trước 07/2024", f"{C.RED}DÍNH CẢ 2 CVE (`regreSSHion` + `SplitSSHell`){C.RESET}"),
        ("1:8.9p1-3ubuntu0.10", "01/07/2024",    f"{C.YELLOW}[SERVER CHƯA CẬP NHẬT] Đã vá `regreSSHion`, NHƯNG DÍNH `CVE-2026-35414`{C.RESET}"),
        ("1:8.9p1-3ubuntu0.18", "Tháng 10/2026", f"{C.GREEN}[SERVER ĐÃ VÁ CHUẨN] Đã vá sạch 100% cả 2 CVE{C.RESET}"),
    ]
    for ver, date_str, note in timeline:
        print(f"    • {C.BOLD}{ver:<20}{C.RESET} ({date_str:<13}) ➔ {note}")

    print(f"\n  {C.BOLD}[2.2] Mô phỏng lỗi Phân Tách Dấu Phẩy (`Delimiter Confusion` - CVE-2026-35414):{C.RESET}")
    # Giả sử hệ thống quản trị lấy tên username đăng ký để cấp chứng chỉ SSH:
    requested_username = "operator_01,root"

    # Logic phân tích trên bản < 3ubuntu0.18 (chưa kiểm tra ký tự phân tách `,` trong đơn vị principal):
    unpatched_principals = requested_username.split(",")
    print(f"    • Chuỗi định danh đầu vào          : `{C.YELLOW}{requested_username}{C.RESET}`")
    print(f"    • Bản `3ubuntu0.10` (Chưa vá)      : Tách theo dấu `,` thành danh sách quyền = {C.RED}{unpatched_principals}{C.RESET}")
    if "root" in unpatched_principals:
        print(f"      ➔ {C.RED}[CẢNH BÁO] Quyền `root` bị chèn lọt vào mảng Principals của chứng chỉ!{C.RESET}")

    # Logic trên bản 3ubuntu0.18 (kiểm tra từ vựng nghiêm ngặt + khóa TrustedUserCAKeys none):
    has_illegal_delimiter = ("," in requested_username or " " in requested_username)
    print(f"    • Bản `3ubuntu0.18` (Đã vá chuẩn)  : Kiểm tra ký tự cấm `,` = `{has_illegal_delimiter}` "
          f"➔ {C.GREEN}TỪ CHỐI NGAY LẬP TỨC (REJECT_INVALID_PRINCIPAL)!{C.RESET}")


# =========================================================================================
# PHẦN 3: MÔ PHỎNG CVE-2026-109518 (APT RETRY) & CVE-2026-111497 (BROTLI RAM INODE TRAP)
# =========================================================================================
@dataclass
class SharedLibMapping:
    """Mô phỏng một dòng ánh xạ thư viện động trong `/proc/<pid>/maps` của Linux."""
    lib_path: str
    inode: int
    version_tag: str
    is_deleted_on_disk: bool = False


def explain_and_simulate_apt_and_brotli_cves() -> None:
    """
    Mô phỏng:
      1. Lỗi lệch pha trạng thái xác thực SHA256 khi APT (< 2.4.14) retry trên HTTP.
      2. Tại sao sau khi nâng cấp `libbrotli1`, tiến trình Nginx vẫn giữ thư viện cũ
         dính CVE-2026-111497 trên RAM với nhãn `(deleted)` nếu chỉ chạy `nginx -s reload`,
         và cách `kill -USR2` (Binary Hot-Swap) thay thế hoàn toàn trên RAM với 0ms downtime.
    """
    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║ 3. GIẢI PHẪU CVE-2026-109518 (APT) & BẪY RAM `(deleted)` CỦA CVE-2026-111497 (BROTLI)    ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝{C.RESET}")

    # -------------------------------------------------------------------------------------
    # 3.1: Mô phỏng cơ chế vòng đệm (Ringbuffer) của libbrotli1 (CVE-2026-111497)
    # -------------------------------------------------------------------------------------
    print(f"\n  {C.BOLD}[3.1] Cơ chế Ghi Tràn Vòng Đệm (`Ringbuffer OOB Write`) trong `libbrotli1` (CVE-2026-111497):{C.RESET}")
    ringbuffer_size = 4096
    write_pos = 4080
    copy_length = 64  # Độ dài chuỗi giải nén vượt qua ranh giới 4096 bytes của ringbuffer

    # Bản cũ (1.0.9-2build6): Thiếu kẹp biên (clamp) trong nhánh dictionary copy đặc biệt
    unclamped_end = write_pos + copy_length
    # Bản vá (1.0.9-2ubuntu0.1): Kẹp biên an toàn `min(copy_length, ringbuffer_size - write_pos)`
    clamped_end = write_pos + min(copy_length, ringbuffer_size - write_pos)

    print(f"    • Kích thước Ringbuffer = `{ringbuffer_size}B`, Con trỏ ghi hiện tại `pos = {write_pos}`, Độ dài copy = `{copy_length}B`")
    print(f"    • Bản `1.0.9-2build6` (Chưa vá)    : Ghi tới vị trí `{unclamped_end}` "
          f"➔ {C.RED}Vượt biên +{unclamped_end - ringbuffer_size} bytes (Out-of-Bounds Write trên Heap!){C.RESET}")
    print(f"    • Bản `1.0.9-2ubuntu0.1` (Đã vá)   : Kẹp biên tại `{clamped_end}` "
          f"➔ {C.GREEN}An toàn tuyệt đối trong biên Ringbuffer (0 byte tràn){C.RESET}")

    # -------------------------------------------------------------------------------------
    # 3.2: Mô phỏng Bẫy `/proc/<nginx_pid>/maps` khi nâng cấp thư viện C trên Linux
    # -------------------------------------------------------------------------------------
    print(f"\n  {C.BOLD}[3.2] Mô phỏng Bẫy Thư Viện `(deleted)` Trong RAM Của Nginx & Cách Hot-Swap `SIGUSR2`:{C.RESET}")

    # Trạng thái ban đầu: Nginx (PID 1050) đang chạy với libbrotlidec.so cũ (inode 10200)
    nginx_ram_map = SharedLibMapping(
        lib_path="/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9",
        inode=10200,
        version_tag="1.0.9-2build6 (VULNERABLE)",
        is_deleted_on_disk=False,
    )
    print(f"    [Bước 1] Ban đầu trên RAM (PID 1050): `{nginx_ram_map.lib_path}` "
          f"[inode={nginx_ram_map.inode}, {C.RED}{nginx_ram_map.version_tag}{C.RESET}]")

    # Bước 2: Chạy `apt-get install --only-upgrade libbrotli1` -> File trên đĩa đổi sang inode 10642,
    # nhưng bản trên RAM của PID 1050 bị đánh dấu `(deleted)`!
    disk_inode_new = 10642
    nginx_ram_map.is_deleted_on_disk = True
    print(f"    [Bước 2] Sau khi `apt upgrade`      : File trên đĩa đã lên inode `{disk_inode_new}` (ĐÃ VÁ),")
    print(f"             nhưng `/proc/1050/maps`    : `{nginx_ram_map.lib_path} {C.RED}(deleted){C.RESET}` "
          f"[Vẫn chạy inode {nginx_ram_map.inode} dính lỗi!]")

    # Bước 3: Nếu chỉ gọi `nginx -s reload` (SIGHUP -> fork()):
    print(f"    [Bước 3] Nếu chỉ chạy `nginx -s reload` (`SIGHUP` ➔ `fork()`):")
    print(f"             ➔ Worker mới sao chép nguyên bảng bộ nhớ của PID 1050 ➔ {C.RED}VẪN DÙNG INODE {nginx_ram_map.inode} (deleted)!{C.RESET}")

    # Bước 4: Khi gọi Zero-Downtime Binary Hot-Swap (`kill -USR2` -> `execve()`):
    nginx_ram_map = SharedLibMapping(
        lib_path="/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9",
        inode=disk_inode_new,
        version_tag="1.0.9-2ubuntu0.1 (PATCHED)",
        is_deleted_on_disk=False,
    )
    print(f"    [Bước 4] Khi chạy `kill -USR2` + `WINCH` + `QUIT` (`execve()` kế thừa Socket FD):")
    print(f"             ➔ Master mới nạp trực tiếp inode `{nginx_ram_map.inode}` từ đĩa: "
          f"`{nginx_ram_map.lib_path}` [{C.GREEN}{nginx_ram_map.version_tag}, 0ms Downtime!{C.RESET}]")


# =========================================================================================
# PHẦN 4: BẢNG ĐỐI CHIẾU TỔNG HỢP TRƯỚC & SAU KHI VÁ NÓNG (ZERO-DOWNTIME HOT-PATCHING)
# =========================================================================================
def print_comparison_scorecard() -> None:
    """In bảng đối chiếu trực quan giữa Máy chủ chưa vá (Server-A) và Máy chủ đã khóa cứng (Server-B)."""
    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║ 4. BẢNG ĐỐI CHIẾU TRẠNG THÁI BẢO MẬT: TRƯỚC KHI VÁ VS SAU KHI VÁ NÓNG (0MS DOWNTIME)     ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╠════════════════════════════╤═══════════════════════════════╤═════════════════════════════╣{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║ Hạng Mục / Mã CVE          │ Máy Chủ Chưa Vá (Server-A)    │ Máy Chủ Đã Khóa (Server-B)  ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╠════════════════════════════╪═══════════════════════════════╪═════════════════════════════╣{C.RESET}")

    rows = [
        ("OpenSSH Banner",           f"{C.YELLOW}3ubuntu0.10 (Tháng 07/2024){C.RESET}", f"{C.GREEN}3ubuntu0.18 (Mới nhất 2026){C.RESET}"),
        ("CVE-2026-98432 (Kernel)",  f"{C.RED}PHƠI TRỰC TIẾP (Chưa chặn){C.RESET}",  f"{C.GREEN}ĐÃ KHÓA 3 LỚP (raw u32){C.RESET}"),
        ("CVE-2026-35414 (OpenSSH)", f"{C.YELLOW}CHƯA VÁ (< 3ubuntu0.18){C.RESET}",    f"{C.GREEN}ĐÃ VÁ 100% (3ubuntu0.18){C.RESET}"),
        ("CVE-2024-6387 (regreSSH)", f"{C.GREEN}ĐÃ VÁ (Từ bản 3ubuntu0.10){C.RESET}",  f"{C.GREEN}ĐÃ VÁ 100% (3ubuntu0.18){C.RESET}"),
        ("CVE-2026-109518 (APT)",    f"{C.RED}NGUY CƠ CAO (apt < 2.4.14){C.RESET}",  f"{C.GREEN}ĐÃ VÁ 100% (apt 2.4.14){C.RESET}"),
        ("CVE-2026-111497 (Brotli)", f"{C.YELLOW}CHƯA VÁ TRÊN ĐĨA & RAM{C.RESET}",     f"{C.GREEN}ĐÃ VÁ + HOT-SWAP NGINX USR2{C.RESET}"),
        ("Nginx Version Exposure",   f"{C.YELLOW}Lộ `nginx/1.18.0 (Ubuntu)`{C.RESET}", f"{C.GREEN}Đã ẩn (`server_tokens off`){C.RESET}"),
    ]

    for col1, col2, col3 in rows:
        # Căn lề chuẩn bất chấp độ dài mã màu ANSI
        print(f"{C.BOLD}{C.CYAN}║{C.RESET} {col1:<26} {C.BOLD}{C.CYAN}│{C.RESET} {col2:<38} {C.BOLD}{C.CYAN}│{C.RESET} {col3:<36} {C.BOLD}{C.CYAN}║{C.RESET}")

    print(f"{C.BOLD}{C.CYAN}╚════════════════════════════╧═══════════════════════════════╧═════════════════════════════╝{C.RESET}")
    print(f"\n  {C.BOLD}🚀 Khi sẵn sàng vá nóng Zero-Downtime cho danh sách VPS trong `vps_list.json`, chạy:{C.RESET} "
          f"`python cve_center.py --fix`\n")


def main() -> None:
    enable_windows_ansi()
    explain_and_simulate_cve_2026_98432()
    explain_and_simulate_openssh_cves()
    explain_and_simulate_apt_and_brotli_cves()
    print_comparison_scorecard()


if __name__ == "__main__":
    main()
