# 🛡️ CVE 2026 Security Command Center — Bộ Công Cụ Rà Soát & Vá Nóng Lỗ Hổng CVE Cho Máy Chủ Linux / VPS

Bộ công cụ tất-cả-trong-một (**All-in-One**) giúp kiểm tra bề mặt tấn công từ bên ngoài (**External Recon — Không cần đăng nhập**), kiểm toán sâu bên trong hàng loạt VPS qua **SSH**, và tự động **Vá Nóng Không Gián Đoạn (`0ms Downtime Hot-Patching`)** đối với 6 cụm siêu lỗ hổng CVE nguy hiểm nhất (2025–2026).

---

## 📌 1. Danh Mục 6 Cụm Siêu Lỗ Hổng CVE Được Kiểm Tra & Bảo Vệ

| # | Mã CVE | Điểm CVSS | Thành Phần Bị Ảnh Hưởng | Cơ Chế Kiểm Tra & Vá Nóng (`0ms Downtime`) |
| :-: | :--- | :-: | :--- | :--- |
| **1** | **`CVE-2026-98432`** | **9.8** *(Critical)* | **Linux Kernel** (`net/ipv4/tcp_ipv4.c` & `MPTCP`) | Kiểm tra Kernel (`>= 5.15.0-202` / `6.8.0-85`) hoặc khóa nóng 3 lớp trên RAM: chặn gói TCP có `IPv4 Options (IHL > 5)` tại bảng `iptables -t raw PREROUTING` (`u32 "0>>24&0x0F=0x06:0x0F"`) + tắt `net.mptcp.enabled=0` + khóa `unprivileged_userns_clone=0`. |
| **2** | **`CVE-2026-111497`**<br>*("Node2Shell" / Brotli)* | **9.2** *(Critical)* | **Node.js** (`22.x`, `24.x`, `26.x`) & Thư viện C **`libbrotli1`** (`Nginx`) | Kiểm tra phiên bản Node.js (`>= 22.23.4`) và kiểm tra cả gói `libbrotli1` trên đĩa lẫn **vùng nhớ `/proc/<nginx_pid>/maps` trên RAM**. Nếu phát hiện Nginx vẫn giữ `libbrotlidec.so (deleted)` cũ trong RAM, tự động **Hot-Swap nhị phân Nginx (`kill -USR2` + `WINCH` + `QUIT`)** với `0ms` rớt mạng. |
| **3** | **`CVE-2026-109618`**<br>**`CVE-2026-109619`**<br>*("PHP2Shell" — CISA KEV)* | **9.2** *(Critical)* | **PHP Engine** (`8.2.x` ➔ `8.5.x`) | Phát hiện phiên bản PHP qua Header, Cookie (`PHPSESSID` / `laravel_session`), tương quan chéo giữa các Subdomain cùng IP (**Cross-VHost SAN Correlation**), hoặc kiểm tra trực tiếp `PHP_VERSION` qua SSH (`>= 8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`). |
| **4** | **`CVE-2026-35414`** *("SplitSSHell")*<br>**`CVE-2024-6387`** *("regreSSHion")* | **8.1 – 9.8** | **OpenSSH Server** (`sshd`) | Phân tích trực tiếp SSH Banner từ cổng `22` (`Ubuntu 22.04 >= 3ubuntu0.18`, `Ubuntu 24.04 >= 3ubuntu13.11`) và tự động nâng cấp `openssh-server` qua APT mà không làm đứt phiên SSH đang mở. |
| **5** | **`CVE-2026-109518`** | **9.8** *(Critical)* | **Ubuntu APT Package Manager** | Kiểm tra và nâng cấp `apt` (`>= 2.4.14`) chống tấn công Man-in-the-Middle chèn gói `.deb` khi retry HTTP. |
| **6** | **`CVE-2026-42945`** *("Rift Chain")*<br>**`CVE-2026-15176`** | **8.8 – 9.8** | **Nginx** (`rewrite` / `alias` + Cổng DB nhạy cảm) | Quét các cổng nhạy cảm bị lộ ra Internet (`3306 MySQL`, `5432 Postgres`, `6379 Redis`, `27017 MongoDB`, `5000/5050 App`) và rà soát chỉ thị `rewrite`/`alias` trong `/etc/nginx/`. |

---

## 📂 2. Cấu Trúc Thư Mục Bộ Công Cụ

```text
Cve_check/
├── CHAY_KIEM_TRA_CVE.bat          # [Khuyên dùng trên Windows] Click đúp để mở Menu điều khiển tiếng Việt
├── cve_center.py                  # Trung tâm điều khiển hợp nhất (Menu tương tác + CLI đa năng)
├── external_surface_check.py      # Công cụ quét Recon bề mặt từ bên ngoài (Không cần SSH, đa luồng, tự mở rộng SSL SAN)
├── scan_multi_vps.py              # Công cụ kiểm toán sâu & Vá Nóng 0ms Downtime hàng loạt VPS qua SSH
├── one_line_check.sh              # Script Bash 1 dòng chạy trực tiếp bên trong từng máy chủ Linux
├── targets.txt                    # Danh sách IP / Domain / Dải mạng CIDR cần quét Recon bên ngoài
├── vps_list.example.json          # File mẫu cấu hình danh sách VPS (đổi tên thành vps_list.json khi dùng SSH)
├── cve_anatomy_explainer.py       # [Học thuật - 100% Offline] Mô phỏng giải phẫu cơ chế bộ nhớ của 4 siêu CVE
└── algorithm_deepdive_simulator.py# [Học thuật - 100% Offline] Mô phỏng toán học hoán vị Z_p* & Inverse SYN-Cookie
```

---

## ⚙️ 3. Cài Đặt Môi Trường (Chỉ Cần Làm 1 Lần)

1. **Yêu cầu**: Máy tính đã cài **Python 3.10 trở lên**.
2. **Thư viện**:
   - Chế độ **Quét Recon từ bên ngoài** (`external_surface_check.py`): **Không cần cài thêm bất kỳ thư viện nào** (sử dụng 100% thư viện chuẩn của Python).
   - Chế độ **Kiểm tra & Vá nóng qua SSH** (`scan_multi_vps.py`): Cần cài thư viện `paramiko`:
     ```bash
     pip install paramiko
     ```

---

## 🚀 4. Hướng Dẫn Sử Dụng Chi Tiết (Từ Cơ Bản Đến Nâng Cao)

### Cách 1: Dùng Menu Tương Tác (Nhanh & Dễ Nhất)
- **Trên Windows**: Bấm đúp chuột vào file **`CHAY_KIEM_TRA_CVE.bat`**.
- **Trên Terminal / PowerShell / macOS / Linux**:
  ```bash
  python cve_center.py
  ```
- Bảng Menu sẽ hiện ra 6 chế độ:
  - Gõ **`1`** (hoặc gõ thẳng IP / Tên miền ngay tại dấu nhắc) để quét nhanh bất kỳ mục tiêu nào.
  - Gõ **`2`** để quét toàn bộ danh sách mục tiêu bạn đã lưu trong `targets.txt`.
  - Gõ **`3`** để kiểm tra sâu bên trong các VPS qua SSH (**Read-Only — Chỉ đọc, tuyệt đối không chỉnh sửa gì trên server**).
  - Gõ **`4`** để tự động **Vá Nóng `0ms Downtime`** cho toàn bộ các VPS trong `vps_list.json`.
  - Gõ **`5`** hoặc **`6`** để xem mô phỏng trực quan cơ chế lỗ hổng và thuật toán (chạy 100% Offline trong RAM).

---

### Cách 2: Quét Recon Bề Mặt Từ Bên Ngoài (Không Cần Mật Khẩu / SSH)
Dùng khi bạn muốn kiểm tra nhanh 1 hoặc hàng chục Website / IP / Dải mạng xem có bị lộ cổng Database (`3306`, `6379`), chạy SSH bản cũ, lộ phiên bản PHP/Nginx hay thiếu Security Headers không:

```bash
# 1. Quét nhanh 1 hoặc nhiều IP / Domain bất kỳ:
python cve_center.py 203.0.113.10 example.com api.example.com

# 2. Quét cả một dải mạng CIDR (/29 = 8 IPs, /28 = 16 IPs, /24 = 256 IPs) theo thuật toán hoán vị Z_p*:
python cve_center.py 203.0.113.0/28

# 3. Quét khoảng IP liên tiếp:
python cve_center.py 203.0.113.10-25

# 4. Quét theo danh sách lưu sẵn trong file targets.txt:
python cve_center.py --all

# 5. Chế độ rút gọn 1 dòng/1 server (dành cho lúc quét > 20 VPS cùng lúc):
python external_surface_check.py --file targets.txt --compact
```

**✨ Tính năng thông minh của `external_surface_check.py`**:
- **Gộp quét Port theo IP vật lý (`IP-Level Deduplication`)**: Nếu 10 domain cùng trỏ về 1 IP, công cụ chỉ quét Port/SSH/MySQL đúng 1 lần duy nhất cho IP đó (nhanh gấp 5 lần và tránh bị Firewall chặn).
- **Tự động phát hiện Subdomain anh em (`SSL SAN Auto-Extension`)**: Tự động đọc chứng chỉ TLS/SSL để tìm các tên miền phụ cùng server và đối chiếu chéo phiên bản PHP nếu 1 tên miền phụ bị lộ header `X-Powered-By`.

---

### Cách 3: Kiểm Toán Sâu Bên Trong & Vá Nóng `0ms Downtime` Qua SSH (`vps_list.json`)

Vì việc quét từ bên ngoài không thể nhìn thấy ngày build của Kernel (`uname -r`) hay các thư viện `.so (deleted)` đang nằm trong RAM của Nginx, bạn nên dùng chế độ SSH đối với các VPS thuộc quyền quản lý của mình:

#### Bước 1: Tạo file `vps_list.json`
Sao chép file mẫu `vps_list.example.json` thành `vps_list.json` và điền thông tin VPS của bạn (hỗ trợ cả SSH Private Key hoặc Password):
```json
[
  {
    "name": "Web-Server-01",
    "host": "203.0.113.10",
    "port": 22,
    "user": "root",
    "key_path": "~/.ssh/id_ed25519",
    "password": ""
  },
  {
    "name": "API-Server-02",
    "host": "198.51.100.20",
    "port": 22,
    "user": "root",
    "key_path": "",
    "password": "Mat_Khau_SSH_Cua_Ban"
  }
]
```

#### Bước 2: Chạy kiểm tra Read-Only (An toàn 100%, chỉ đọc thông số)
```bash
python cve_center.py --ssh
# Hoặc truyền thẳng IP không cần tạo file json:
python scan_multi_vps.py --hosts 203.0.113.10,198.51.100.20 --user root --password "Mat_Khau_SSH"
```

#### Bước 3: Tự động Vá Nóng `0ms Downtime` (Không cần Reboot máy chủ)
```bash
python cve_center.py --fix
```
Khi chạy `--fix`, công cụ sẽ tự động thực hiện trên từng VPS:
1. Khóa nóng `CVE-2026-98432` trên RAM (`sysctl net.mptcp.enabled=0`, `kernel.unprivileged_userns_clone=0`, lưu vào `/etc/sysctl.d/99-cve-2026-98432.conf`, và chèn rule `iptables -t raw PREROUTING` chặn gói TCP có `IHL > 5`).
2. Nâng cấp tự động các gói bảo mật `libbrotli1`, `openssh-server`, `apt` ở chế độ không làm gián đoạn dịch vụ (`NEEDRESTART_MODE=l`).
3. Kiểm tra `/proc/$(cat /run/nginx.pid)/maps` — nếu tiến trình Nginx còn giữ thư viện `libbrotli` cũ bị đánh dấu `(deleted)` trên RAM, tự động kích hoạt **Binary Hot-Swap (`kill -USR2` + `WINCH` + `QUIT`)** để nạp thư viện mới lên RAM với **`0ms` downtime**.

---

### Cách 4: Chạy Trực Tiếp Trên Terminal Của Máy Chủ Linux (`one_line_check.sh`)
Nếu bạn đang đăng nhập sẵn bên trong terminal của một VPS Linux và muốn kiểm tra nhanh tại chỗ mà không cần cài Python trên PC, hãy chạy:
```bash
bash one_line_check.sh
```
Script sẽ in ra báo cáo 6 phần ngay lập tức (Kernel & MPTCP, Node.js & Brotli RAM maps, PHP Version & `upload_progress`, Nginx Rewrites, APT/OpenSSH và số lượng bản cập nhật bảo mật đang chờ).
