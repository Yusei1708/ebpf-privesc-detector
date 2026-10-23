# eBPF & Machine Learning Linux Privilege Escalation Detector

[![GitHub Repository](https://img.shields.io/badge/GitHub-Yusei1708%2Febpf--privesc--detector-blue?logo=github)](https://github.com/Yusei1708/ebpf-privesc-detector)
[![Kernel LTS](https://img.shields.io/badge/Linux-6.x%20LTS-orange?logo=linux)](https://kernel.org)
[![Python](https://img.shields.io/badge/Python-3.14-green?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)](LICENSE)

Hệ thống giám sát và phát hiện tấn công leo thang đặc quyền (**Privilege Escalation**) theo thời gian thực trên Linux Kernel, kết hợp kỹ thuật thu thập telemetry nhân qua **eBPF (Extended Berkeley Packet Filter)** và phân tích hai tầng: **Rule-based Fast Path** và **Machine Learning (Isolation Forest & Random Forest)**.

Repository: [https://github.com/Yusei1708/ebpf-privesc-detector](https://github.com/Yusei1708/ebpf-privesc-detector)

---

## 1. Kiến Trúc Hệ Thống (Architecture & Data Flow)

```text
+-------------------------------------------------------------------------------------------------+
|                                        LINUX KERNEL SPACE                                       |
|                                                                                                 |
|   [tracepoint:sys_enter_execve]      [kprobe:commit_creds]       [kprobe:cap_capable]            |
|       (Quan sát thực thi)         (Quan sát đổi quyền task)     (Quan sát kiểm tra Cap)         |
|               |                              |                            |                     |
|               +------------------------------+----------------------------+                     |
|                                              |                                                  |
|                                [tracepoint:sys_enter_openat]                                    |
|                                (Quan sát ý định mở file /etc)                                   |
|                                              |                                                  |
|                                              v                                                  |
|                                   [BPF Perf Ring Buffer]                                        |
|                       (event_t: 200 bytes, 8-byte aligned, BPF Ring Buffer)                     |
+----------------------------------------------|--------------------------------------------------+
                                               |
                                               v (Poll asynchronously)
+-------------------------------------------------------------------------------------------------+
|                                        USER SPACE AGENT                                         |
|                                                                                                 |
|   [agent/collector.py]  ---> BPFCollector (BCC Runtime, Auto-Cleanup via atexit/signal)         |
|                                      |                                                          |
|                                      v                                                          |
|   [agent/features.py]   ---> FeatureExtractor (Sliding Window 3.0s, Lineage, PID Reuse)         |
|                                      |                                                          |
|                                      +------------------------------------+                     |
|                                      |                                    |                     |
|                                      v                                    v                     |
|                      [TẦNG 1: Rule-Based Fast Path]           [TẦNG 2: Machine Learning]        |
|                      - PRIVESC-001 (commit_creds jump)        - Random Forest (P_Attack)        |
|                      - PRIVESC-002 (GTFOBins SUID abuse)      - Isolation Forest (Anomaly)      |
|                      - PRIVESC-003 (Suspicious path exec)     - StandardScaler                  |
|                      - PRIVESC-004 (Service-spawned root)     - Composite Threat Score          |
|                      - PRIVESC-005 (Sensitive file access)                |                     |
|                      - PRIVESC-006 (Priv capability probe)                |                     |
|                                      |                                    |                     |
|                                      +------------------+-----------------+                     |
|                                                         |                                       |
|                                      +------------------+-----------------+                     |
|                                      |                                    |                     |
|                                      v                                    v                     |
|                         [Rich SOC Dashboard UI]             [Structured JSONL Logging]          |
|                         (Cảnh báo Terminal trực quan)       (alerts.jsonl chuẩn SIEM)           |
+-------------------------------------------------------------------------------------------------+
```

---

## 2. Giới Hạn Quan Sát Của eBPF Probes (Observability Boundaries)

Hệ thống minh bạch về ranh giới dữ liệu được thu thập:
1. **`tracepoint/syscalls/sys_enter_execve`**: Quan sát **lời gọi** thực thi nhị phân, tham số và danh tính caller tại thời điểm bắt đầu. Điểm đo này không kết luận tiến trình có exec thành công hay thất bại (ví dụ: file hỏng, thiếu quyền thực thi).
2. **`kprobe/commit_creds`**: Quan sát thời điểm kernel chuẩn bị áp dụng cấu trúc `struct cred` mới cho task. Cho phép bắt khoảnh khắc EUID hoặc UID thay đổi sang 0.
3. **`kprobe/cap_capable`**: Quan sát kernel đang kiểm tra quyền đối với capability nhạy cảm (`CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`). Không thể kết luận từ entry rằng quyền này được cấp thuận hay bị từ chối.
4. **`tracepoint/syscalls/sys_enter_openat`**: Quan sát **ý định (entry)** muốn mở file nhạy cảm (`/etc/shadow`, `/etc/sudoers`, `/etc/passwd`). **Tuyệt đối không khẳng định file đã được đọc thành công**, vì kernel VFS có thể trả về lỗi `-EACCES` (Permission Denied) sau đó.

---

## 3. Danh Sách 8 Đặc Trưng Hành Vi (Behavioral Features)

Trong mỗi cửa sổ trượt 3.0 giây (`Sliding Window 3.0s`), hệ thống trích xuất vector 8 đặc trưng:
1. `exec_count`: Số lần gọi `execve` trong cửa sổ thời gian.
2. `uid_change_flag`: Cờ chuyển đổi đặc quyền (1 nếu `UID != 0` chuyển sang `EUID == 0`).
3. `is_whitelisted_bin`: `1` nếu nhị phân thuộc danh sách SUID hợp lệ (`sudo`, `su`, `passwd`, `pkexec`), `0` nếu là nhị phân ngoài whitelist (ví dụ: `find`, `python`, `sh`, `vim`).
4. `suspicious_path_flag`: `1` nếu nhị phân được thực thi từ thư mục tạm nguy hiểm (kiểm tra ranh giới thư mục chuẩn xác: `/tmp/`, `/dev/shm/`, `/var/tmp/`, không nhầm lẫn tiền tố như `/tmpfoo`).
5. `service_parent_flag`: `1` nếu tiến trình cha hoặc tổ tiên thuộc danh sách daemon dịch vụ mạng (`nginx`, `apache2`, `node`, `python`, `php-fpm`).
6. `sensitive_file_access`: Số lần phát sinh syscall yêu cầu mở file cấu hình nhạy cảm.
7. `cap_check_count`: Số lần kernel kiểm tra các capability đặc quyền.
8. `priv_syscall_rate`: Tần suất gọi syscall nhạy cảm trên một giây (tính theo khoảng thời gian thực tế của các sự kiện trong window).

---

## 4. Danh Sách Các Luật Phát Hiện (Tier 1 Rules)

| Mã Luật | Tên Luật | Mức Độ | Kỹ Thuật MITRE | Điều Kiện Kích Hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **PRIVESC-001** | `RULE_COMMIT_CREDS_EUID_JUMP` | CRITICAL | T1548.001 | `commit_creds` chuyển sang `EUID=0` từ caller không đặc quyền và binary không thuộc whitelist. |
| **PRIVESC-002** | `RULE_GTFOBINS_SUID_ABUSE` | CRITICAL | T1548.001 | `uid_change_flag == 1` và `is_whitelisted_bin == 0` và `EUID == 0`. |
| **PRIVESC-003** | `RULE_SUSPICIOUS_PATH_PRIV_EXEC`| HIGH | T1059 | Thực thi mã từ `/tmp` hoặc `/dev/shm` với `EUID == 0` ngoài whitelist. |
| **PRIVESC-004** | `RULE_SERVICE_SPAWNED_ROOT_SHELL`| CRITICAL | T1068 | Tiến trình con của web/network daemon nâng quyền lên root (dấu hiệu Web Shell RCE). |
| **PRIVESC-005** | `RULE_SENSITIVE_FILE_ACCESS_ATTEMPT`| HIGH | T1003.008 | Yêu cầu mở `/etc/shadow` trong bối cảnh nghi vấn (`/tmp`, con của service, hoặc unwhitelisted root). |
| **PRIVESC-006** | `RULE_PRIVILEGED_CAPABILITY_PROBE`| MEDIUM | T1548 | Tiến trình không đặc quyền yêu cầu kernel kiểm tra `CAP_SETUID`/`CAP_SYS_ADMIN` kèm tín hiệu rủi ro ngữ cảnh (đường dẫn `/tmp`, con của service, hoặc tần suất cao). |

---

## 5. Yêu Cầu Hệ Thống & Cài Đặt

### 5.1. Yêu Cầu Môi Trường
- **Hệ điều hành**: Linux Kernel 5.8+ (khuyên dùng Kernel 6.x LTS).
- **Quyền hạn**: Quyền `root` (`sudo`) hoặc các capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`.
- **Gói phụ thuộc hệ thống (Arch Linux)**:
  ```bash
  sudo pacman -S bcc python-bcc linux-lts-headers
  ```

### 5.2. Khởi Tạo Môi Trường Ảo Python
```bash
# Tạo virtualenv kế thừa python-bcc từ hệ thống
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 6. Hướng Dẫn Sử Dụng & Kiểm Thử

### 6.1. Chạy Toàn Bộ Test Suite Tự Động (Không cần Root)
Bộ kiểm thử tự động kiểm tra trích xuất đặc trưng, sliding window, PID reuse, rule engine, alert logger JSONL và pipeline ML:
```bash
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```

### 6.2. Kiểm Thử Giao Diện Cảnh Báo Với Assertion Chặt Chẽ
```bash
.venv/bin/python main.py --test-alert
```

### 6.3. Huấn Luyện Lại Mô Hình Machine Learning
```bash
# Huấn luyện với tập dữ liệu mô phỏng theo phiên (Grouped Sessions chống rò rỉ dữ liệu)
.venv/bin/python ml/train.py

# Hoặc nạp tập dữ liệu telemetry thực tế có gán nhãn:
.venv/bin/python ml/train.py --telemetry-file path/to/telemetry.jsonl
```

### 6.4. Chạy Giả Lập Tấn Công An Toàn (Zero-Footprint)
Kịch bản giả lập tấn công được đóng gói bên trong Docker container (`--rm`) hoặc Linux User Namespace (`unshare -r -m -p -f --mount-proc`) kèm cơ chế dọn dẹp và healthcheck toàn vẹn file host:
```bash
./tests/safe_attack_simulator.sh
```

### 6.5. Khởi Chạy Giám Sát Nhân Thời Gian Thực (Cần Quyền Root)
```bash
sudo .venv/bin/python main.py --alert-log alerts.jsonl
```

---

## 7. Đo Kiểm Đối Chuẩn Hiệu Năng (Benchmark vs Auditd)

Dự án cung cấp bộ công cụ đo lường định lượng và hướng dẫn tái hiện bài đo so sánh với Linux `auditd`:
- Công cụ đo kiểm: [`benchmarks/benchmark_agent_vs_auditd.py`](benchmarks/benchmark_agent_vs_auditd.py)
- Hướng dẫn thực nghiệm & Biểu mẫu ghi kết quả: [`benchmarks/BENCHMARK_GUIDE.md`](benchmarks/BENCHMARK_GUIDE.md)

Lệnh thực hiện:
```bash
# Đo Agent eBPF trong 30 giây
python benchmarks/benchmark_agent_vs_auditd.py --pid $(pgrep -f "agent/detector.py") --label "eBPF-Agent" --duration 30

# Đo daemon auditd trong 30 giây
python benchmarks/benchmark_agent_vs_auditd.py --pid $(pgrep -x auditd) --label "Auditd" --duration 30
```

---

## 8. Giới Hạn Kỹ Thuật (Known Limitations)

1. **Ranh giới Syscall Entry vs Exit**: Hiện tại probe gắn tại `sys_enter_*` nhằm phát hiện sớm ý định trước khi tiến trình kịp thực thi mã độc. Do đó, probe không nhận biết được mã trả về (return value) của syscall nếu lệnh thất bại sau đó.
2. **Kỹ thuật Tấn công DKOM (Direct Kernel Object Manipulation)**: Nếu kẻ tấn công khai thác lỗ hổng kernel cấp zero-day để ghi trực tiếp vào vùng nhớ `struct cred` trong RAM mà không thông qua hàm `commit_creds()`, kprobe tại `commit_creds` sẽ không được kích hoạt.
3. **Thời gian khởi động ban đầu của BCC**: BCC thực hiện biên dịch mã nguồn C eBPF sang bytecode Clang/LLVM JIT tại runtime, mất từ 1-3 giây khi khởi động Agent trước khi gắn probe vào Kernel.
4. **Giới hạn quan sát của kprobe/cap_capable**: Điểm hook `cap_capable` chỉ quan sát thời điểm kernel thực hiện kiểm tra quyền (capability audit check entry). Sự kiện này không đồng nghĩa với việc capability đã được cấp hay bị từ chối. Vì vậy hệ thống chỉ dùng tín hiệu này làm ngữ cảnh tương quan hoặc cảnh báo mức MEDIUM khi có dấu hiệu rủi ro đi kèm, tránh tạo cảnh báo sai độc lập.
