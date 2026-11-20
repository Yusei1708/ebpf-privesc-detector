# Hướng Dẫn Thực Nghiệm & Đo Kiểm Hiệu Năng Đối Chuẩn: eBPF Agent vs Linux Auditd

Tài liệu này cung cấp quy trình thực nghiệm có thể tái hiện để đo lường định lượng và so sánh mức tiêu hao tài nguyên (CPU %, RAM RSS) và thời gian hoàn tất workload (wall-clock latency) giữa **eBPF PrivEsc Detector** và **Linux Audit Daemon (`auditd`)**, đồng thời hướng dẫn quan sát tỷ lệ rớt sự kiện từ kernel ring buffer.

> [!IMPORTANT]
> **Nguyên tắc Khoa học & Trung thực**: Không ngụy tạo số liệu hoặc đưa ra các tuyên bố thiếu căn cứ như "tiêu hao dưới 1% CPU", "zero-copy", hay "hoàn toàn không độ trễ". Script `benchmark_agent_vs_auditd.py` tập trung đo lường chính xác CPU (%), RAM RSS (MB), số core (`cpu_count`) và thời gian thực tế (`actual_elapsed_sec`) từ `/proc`. Mọi số liệu trong báo cáo phải được lấy từ các bài đo thực tế trên phần cứng xác định.

---

## 1. Thiết Lập Môi Trường Đo Kiểm

### 1.1. Cấu hình Luật Giám sát cho Auditd
Để đảm bảo tính công bằng, cấu hình `auditd` theo dõi nhóm syscall tương ứng với **9 eBPF hooks** của hệ thống (`sys_enter_execve`, `sys_exit_execve`, `sys_enter_execveat`, `sys_exit_execveat`, `commit_creds`, `cap_capable`, `sys_enter_openat`, `sched_process_fork`, `sched_process_exit`):
```bash
# 1. Xóa các luật cũ
sudo auditctl -D

# 2. Theo dõi thực thi tiến trình (tương đương tracepoint execve & execveat)
sudo auditctl -a always,exit -F arch=b64 -S execve,execveat -k benchmark_exec

# 3. Theo dõi chuyển đổi đặc quyền UID/EUID (tương đương nhóm hook commit_creds trên userspace)
sudo auditctl -a always,exit -F arch=b64 -S setuid,setresuid,setreuid -k benchmark_cred

# 4. Theo dõi mở file cấu hình nhạy cảm trong /etc (tương đương tracepoint openat)
sudo auditctl -a always,exit -F arch=b64 -S openat -F dir=/etc -k benchmark_open

# 5. Kiểm tra danh sách luật đang hoạt động
sudo auditctl -l
```

*(Sau khi kết thúc bài đo `auditd`, nhớ chạy `sudo auditctl -D` để dọn luật đo kiểm).*

### 1.2. Khởi động eBPF Agent
Khởi động Agent với output cảnh báo ghi ra file (có giới hạn xoay vòng `--max-log-mb`, có thể thêm `--quiet` khi đo hiệu năng thuần không render bảng terminal):
```bash
cd ebpf-privesc-detector
sudo .venv/bin/python main.py --alert-log /tmp/ebpf_bench_alerts.jsonl --ringbuf-pages 256 --cooldown 2.0
```
Khi khởi động thành công, Agent sẽ in trực tiếp dòng:
```text
[✓] Agent PID: <PID>
```

---

## 2. Kịch Bản Sinh Tải (Workload Generation) & Wall-Clock Latency

Để đo mức chịu tải và ảnh hưởng độ trễ hệ thống của hai cơ chế (inline eBPF hook trong nhân vs netlink/disk I/O của `auditd`), hãy đo cả **thời gian chạy thực tế (wall-clock time)** của từng kịch bản bằng `time` khi chạy ở 3 trạng thái: **Baseline (tắt cả hai)**, **Bật eBPF Agent**, và **Bật Auditd**.

### Kịch bản A: Tải Thực thi Tiến trình Dày đặc (Heavy Process Fork/Exec)
Sử dụng công cụ `stress-ng` để tạo hàng nghìn lời gọi syscall `execve`:
```bash
time stress-ng --exec 4 --exec-ops 20000 --timeout 30s
```
*(Nếu không có `stress-ng`, sử dụng vòng lặp Bash: `time bash -c 'for i in $(seq 1 10000); do /bin/true; done'`)*

### Kịch bản B: Tải Mở File Dày đặc trong `/etc` (High-frequency openat)
Mô phỏng quét và mở file cấu hình liên tục:
```bash
time bash -c 'for i in $(seq 1 5000); do cat /etc/passwd >/dev/null 2>&1; cat /etc/shadow >/dev/null 2>&1; done'
```

---

## 3. Lệnh Thực Thi Đo Kiểm Định Lượng

Sử dụng script đo kiểm [`benchmarks/benchmark_agent_vs_auditd.py`](benchmark_agent_vs_auditd.py):

### Bước 1: Đo eBPF Agent
> [!WARNING]
> **Tránh bẫy đo nhầm PID của `sudo`**: Không dùng `pgrep -f "main.py" | head -n 1` vì tiến trình cha `sudo .venv/bin/python main.py ...` cũng chứa `"main.py"` trong command line và có PID nhỏ hơn tiến trình Python thật! Hãy dùng trực tiếp giá trị `[✓] Agent PID: <PID>` do Agent in ra, hoặc dùng `pgrep -nf "python.*main\.py"` (lấy tiến trình mới nhất).

```bash
# Cách 1 (khuyên dùng): gán trực tiếp PID từ dòng "[✓] Agent PID: <PID>"
# AGENT_PID=<PID_IN_RA_KHI_KHOI_DONG>

# Cách 2: lấy PID tiến trình Python mới nhất (bỏ qua tiến trình cha sudo)
AGENT_PID=$(pgrep -nf "python.*main\.py")

# Chạy benchmark trong 30 giây lấy mẫu mỗi 0.5s (dùng --include-children nếu cần gộp tiến trình con)
.venv/bin/python benchmarks/benchmark_agent_vs_auditd.py \
    --pid "${AGENT_PID}" \
    --label "eBPF-PrivEsc-Agent" \
    --duration 30 \
    --interval 0.5 \
    --output ebpf_benchmark_result.json
```

### Bước 2: Đo Linux Auditd
```bash
# Lấy PID của daemon auditd
AUDITD_PID=$(pgrep -x auditd)

# Chạy benchmark trong 30 giây trong khi đang chạy cùng kịch bản sinh tải
.venv/bin/python benchmarks/benchmark_agent_vs_auditd.py \
    --pid "${AUDITD_PID}" \
    --label "Linux-Auditd" \
    --duration 30 \
    --interval 0.5 \
    --include-children \
    --output auditd_benchmark_result.json
```
*(Ghi chú: Thread nhân `kauditd` xử lý đẩy sự kiện netlink chạy trong kernel space nên không hiện trực tiếp trong `VmRSS` của `auditd`; việc so sánh wall-clock time ở Mục 2 giúp phản ánh thêm phần chi phí nhân này.)*

---

## 4. Biểu Mẫu Ghi Nhận Kết Quả Thực Nghiệm (Template)

Sau khi hoàn thành các bài đo trên máy của bạn, điền kết quả vào bảng dưới đây:

| Tiêu Chí Đo Lường | Baseline (Không Agent) | Linux `auditd` | eBPF PrivEsc Detector | Phương Pháp Đo Đạc & Ghi Chú |
| :--- | :--- | :--- | :--- | :--- |
| **CPU Trung bình / P95 / Đỉnh (%)** | — | *[Điền kết quả]* | *[Điền kết quả]* | Tự động đo bằng `time.monotonic()` & parse `/proc/<pid>/stat` (kèm kiểm tra `starttime` chống PID reuse) qua `benchmark_agent_vs_auditd.py` |
| **RAM RSS Trung bình / P95 / Đỉnh (MB)** | — | *[Điền kết quả]* | *[Điền kết quả]* | Tự động đo `VmRSS` qua `/proc/<pid>/status` trong `benchmark_agent_vs_auditd.py` |
| **Thời gian chạy Workload (Wall-Clock s)** | *[Điền kết quả]* | *[Điền kết quả]* | *[Điền kết quả]* | Đo bằng `time` ở Mục 2 để phản ánh chi phí inline kernel + netlink/I/O |
| **Số sự kiện xử lý (Events/s)** | — | *[Điền kết quả]* | *[Điền kết quả]* | Đếm số dòng log / `processed` in ra khi `BPFCollector.cleanup()` |
| **Tỷ lệ rớt sự kiện (Drop Rate %)** | — | *[Điền kết quả]* | *[Điền kết quả]* | `auditctl -s` (`lost`) vs `dropped_events` (`BPF_PERCPU_ARRAY` + `BPF_RINGBUF_OUTPUT`, mặc định `256` pages) in lúc cleanup |
| **Tác động đến I/O máy chủ** | — | Ghi log đĩa liên tục | Xử lý in-memory, chỉ log khi có alert (xoay vòng `--max-log-mb`) | Quan sát qua `iotop` hoặc `vmstat` |

---

## 5. Phân Tích Cơ Chế Kỹ Thuật

1. **Linux Auditd**:
   - Sử dụng cơ chế socket netlink để đẩy toàn bộ sự kiện từ nhân ra userspace daemon `auditd` (và ghi tuần tự xuống `/var/log/audit/audit.log`).
   - Với lượng syscall lớn, việc ghi liên tục xuống đĩa có thể gây thắt cổ chai I/O (Disk I/O Bottleneck) và làm chậm tiến trình người dùng nếu cấu hình cờ `-f 2` (panic/halt khi tràn buffer).

2. **eBPF PrivEsc Detector**:
   - Lọc sớm trực tiếp trong Kernel Space trên **9 hooks** (`execve`/`execveat` entry+exit, `commit_creds`, `cap_capable`, `openat`, `sched_process_fork`, `sched_process_exit`):
     - `sys_enter_openat` chuẩn hóa nhiều dấu `/` ở đầu và kiểm tra ranh giới đường dẫn chính xác: luôn thu nhận `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/*` (đọc + ghi), và **chỉ** thu nhận `/etc/passwd`, `/etc/ld.so.preload` khi có cờ ghi (`O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND`) — loại bỏ nhiễu đọc `/etc/passwd` thông thường ngay từ kernel.
   - Sử dụng **`BPF_RINGBUF_OUTPUT`** (chia sẻ liên tục giữa các CPU, mặc định `256` pages qua `--ringbuf-pages`) kết hợp bộ đếm nguyên tử `BPF_PERCPU_ARRAY` `dropped_events` để theo dõi chính xác lượng sự kiện bị tràn mà không mất thứ tự thời gian giữa các core.
   - Nhược điểm: Cần bộ nhớ RAM để tải các mô hình ML (Random Forest, Isolation Forest, StandardScaler) trong Python User Space và thời gian biên dịch JIT bytecode BCC (~1-3s) lúc khởi động.
