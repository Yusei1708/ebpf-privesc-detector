# eBPF & Machine Learning Linux Privilege Escalation Detector (Project 3)

Hệ thống giám sát và phát hiện tấn công leo thang đặc quyền (Privilege Escalation) theo thời gian thực trên Linux Kernel sử dụng công nghệ **eBPF (Extended Berkeley Packet Filter)** kết hợp mô hình học máy **Machine Learning (Isolation Forest & Random Forest)**.

---

## 1. Kiến Trúc Hệ Thống (Architecture)

```
+-----------------------------------------------------------------------------------------+
|                                    LINUX KERNEL SPACE                                   |
|                                                                                         |
|  [tracepoint:sys_enter_execve]  [kprobe:commit_creds]  [kprobe:cap_capable]  [tracepoint:sys_enter_openat] |
|               |                           |                    |                         |       |
|               +---------------------------+--------------------+-------------------------+       |
|                                           |                                                     |
|                                 [BPF Perf Ring Buffer]                                          |
+-------------------------------------------|---------------------------------------------+
                                            |
                                            v (Zero-copy Telemetry)
+-----------------------------------------------------------------------------------------+
|                                    USER SPACE AGENT                                     |
|                                                                                         |
|  [agent/collector.py] ---> [Process Lineage Tree]                                       |
|                                    |                                                    |
|                                    v                                                    |
|  [agent/features.py]  ---> [Sliding Window 3.0s] ---> Trích xuất Vector 8 Đặc Trưng     |
|                                                                    |                    |
|                                    +-------------------------------+                    |
|                                    |                                                    |
|                                    v                               v                    |
|                       [TẦNG 1: Fast Path Rule-Based]   [TẦNG 2: Machine Learning]      |
|                       - commit_creds nhảy euid=0       - Random Forest (P_Attack)       |
|                       - SUID binary bất thường         - Isolation Forest (Anomaly)     |
|                       - Drop exploit /tmp, /dev/shm    - StandardScaler                 |
|                       - Đọc trộm /etc/shadow           - Composite Threat Score         |
|                                    |                               |                    |
|                                    +---------------+---------------+                    |
|                                                    |                                    |
|                                                    v                                    |
|                                    [Rich Terminal SOC Alert Dashboard]                  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. 8 Đặc Trưng Hành Vi (Behavioral Features)

Trong mỗi cửa sổ trượt 3 giây (`Sliding Window 3.0s`), hệ thống trích xuất 8 đặc trưng:
1. `exec_count`: Số lần gọi `execve` trong cửa sổ.
2. `uid_change_flag`: Cờ chuyển đổi từ `UID != 0` sang `EUID == 0`.
3. `is_whitelisted_bin`: 0 nếu nhị phân là SUID hợp lệ (`sudo`, `su`, `passwd`, `pkexec`), 1 nếu là nhị phân bất thường (ví dụ: `find`, `python`, `sh`, `vim`).
4. `suspicious_path_flag`: Thực thi nhị phân từ thư mục tạm nguy hiểm (`/tmp`, `/dev/shm`, `/var/tmp`).
5. `service_parent_flag`: Tiến trình cha là web/network daemon (`nginx`, `apache2`, `python`, `node`, `php-fpm`).
6. `sensitive_file_access`: Số lần truy cập file cấu hình nhạy cảm (`/etc/shadow`, `/etc/sudoers`, `/etc/passwd`).
7. `cap_check_count`: Số lần kiểm tra Linux Capabilities nhạy cảm (`CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`).
8. `priv_syscall_rate`: Tần suất gọi các syscall nhạy cảm trên một giây.

---

## 3. Quy Tắc An Toàn Tuyệt Đối (Zero-Footprint Safety Rules)

Dự án được thiết kế đặc biệt cho máy chủ phát triển **Arch Linux**:
1. **Không can thiệp Host:** Không bao giờ gán SUID hay sửa đổi `/etc/shadow`, `/etc/passwd` trên máy thật.
2. **Container & Namespace Isolation:** Mọi kịch bản giả lập tấn công được thực thi bên trong Docker Container với cờ `--rm` hoặc Linux User Namespace (`unshare -r -m -p -f --mount-proc`).
3. **Cơ chế Rollback & Auto-Cleanup:** Tích hợp `trap cleanup EXIT INT TERM` (Bash) và `atexit` (Python) để tự động tháo gỡ eBPF hooks và dọn dẹp môi trường khi dừng chương trình.

---

## 4. Hướng Dẫn Cài Đặt & Sử Dụng

### Bước 1: Kích hoạt môi trường ảo Python
```bash
cd /home/yusei1708/code/project3/ebpf-privesc-detector
source .venv/bin/activate
```

### Bước 2: Huấn luyện lại mô hình ML (nếu cần)
```bash
python ml/train.py
```
*Kết quả mô hình sẽ được lưu tại `ml/models/` (Random Forest, Isolation Forest, Scaler).*

### Bước 3: Kiểm thử giao diện cảnh báo (Không cần quyền root)
```bash
python main.py --test-alert
```

### Bước 4: Chạy kiểm thử tấn công an toàn trong môi trường cô lập
```bash
./tests/safe_attack_simulator.sh
```

### Bước 5: Khởi chạy Agent eBPF giám sát Kernel thời gian thực
*(Yêu cầu cài đặt gói `bcc` và `python-bcc` trên Arch Linux: `sudo pacman -S bcc python-bcc docker`)*
```bash
sudo .venv/bin/python main.py
```
