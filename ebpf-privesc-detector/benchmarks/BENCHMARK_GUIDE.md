# Hướng Dẫn Thực Nghiệm & Đo Kiểm Hiệu Năng Đối Chuẩn: eBPF Agent vs Linux Auditd

Tài liệu này cung cấp quy trình thực nghiệm có thể tái hiện để đo lường định lượng và so sánh mức tiêu hao tài nguyên (CPU %, RAM RSS) giữa **eBPF PrivEsc Detector** và **Linux Audit Daemon (`auditd`)**, đồng thời hướng dẫn phương pháp quan sát tỷ lệ rớt sự kiện và độ trễ.

> [!IMPORTANT]
> **Nguyên tắc Khoa học & Trung thực**: Không ngụy tạo số liệu hoặc đưa ra các tuyên bố thiếu căn cứ như "tiêu hao dưới 1% CPU", "zero-copy", hay "hoàn toàn không độ trễ". Script `benchmark_agent_vs_auditd.py` tập trung đo lường chính xác CPU (%) và RAM RSS (MB) từ `/proc`. Mọi số liệu trong báo cáo phải được lấy từ các bài đo thực tế trên phần cứng xác định.

---

## 1. Thiết Lập Môi Trường Đo Kiểm

### 1.1. Cấu hình Luật Giám sát cho Auditd
Để đảm bảo tính công bằng, cấu hình `auditd` theo dõi các syscall tương đương với 4 probes của eBPF:
```bash
# 1. Xóa các luật cũ
sudo auditctl -D

# 2. Theo dõi thực thi tiến trình (tương đương tracepoint execve)
sudo auditctl -a always,exit -F arch=b64 -S execve -k benchmark_exec

# 3. Theo dõi mở file cấu hình nhạy cảm trong /etc (tương đương tracepoint openat)
sudo auditctl -a always,exit -F arch=b64 -S openat -F dir=/etc -k benchmark_open

# 4. Kiểm tra danh sách luật đang hoạt động
sudo auditctl -l
```

### 1.2. Khởi động eBPF Agent
Khởi động Agent với output cảnh báo ghi ra file:
```bash
sudo .venv/bin/python main.py --alert-log /tmp/ebpf_bench_alerts.jsonl
```

---

## 2. Kịch Bản Sinh Tải (Workload Generation)

Để đo mức chịu tải của hai hệ thống, sử dụng các kịch bản sinh tải chuẩn:

### Kịch bản A: Tải Thực thi Tiến trình Dày đặc (Heavy Process Fork/Exec)
Sử dụng công cụ `stress-ng` để tạo hàng nghìn lời gọi syscall `execve`:
```bash
stress-ng --exec 4 --exec-ops 20000 --timeout 30s
```
*(Nếu không có `stress-ng`, sử dụng vòng lặp Bash: `for i in $(seq 1 10000); do /bin/true; done`)*

### Kịch bản B: Tải Mở File Dày đặc trong `/etc` (High-frequency openat)
Mô phỏng quét và đọc file liên tục:
```bash
for i in $(seq 1 5000); do
    cat /etc/passwd >/dev/null 2>&1
    cat /etc/shadow >/dev/null 2>&1
done
```

---

## 3. Lệnh Thực Thi Đo Kiểm Định Lượng

Sử dụng script đo kiểm [`benchmarks/benchmark_agent_vs_auditd.py`](benchmark_agent_vs_auditd.py):

### Bước 1: Đo eBPF Agent
```bash
# Lấy PID của tiến trình python detector
AGENT_PID=$(pgrep -f "agent/detector.py" | head -n 1)

# Chạy benchmark trong 30 giây lấy mẫu mỗi 0.5s
python benchmarks/benchmark_agent_vs_auditd.py \
    --pid ${AGENT_PID} \
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
python benchmarks/benchmark_agent_vs_auditd.py \
    --pid ${AUDITD_PID} \
    --label "Linux-Auditd" \
    --duration 30 \
    --interval 0.5 \
    --output auditd_benchmark_result.json
```

---

## 4. Biểu Mẫu Ghi Nhận Kết Quả Thực Nghiệm (Template)

Sau khi hoàn thành các bài đo trên máy của bạn, điền kết quả vào bảng dưới đây:

| Tiêu Chí Đo Lường | Linux `auditd` | eBPF PrivEsc Detector | Phương Pháp Đo Đạc & Ghi Chú |
| :--- | :--- | :--- | :--- |
| **CPU Trung bình (%)** | *[Điền kết quả]* | *[Điền kết quả]* | Tự động đo qua `benchmark_agent_vs_auditd.py` |
| **CPU Đỉnh (%)** | *[Điền kết quả]* | *[Điền kết quả]* | Tự động đo qua `benchmark_agent_vs_auditd.py` |
| **RAM (RSS MB)** | *[Điền kết quả]* | *[Điền kết quả]* | Tự động đo qua `benchmark_agent_vs_auditd.py` |
| **Số sự kiện xử lý (Events/s)**| *[Điền kết quả]* | *[Điền kết quả]* | Đếm số dòng log sinh ra / thời gian đo |
| **Tỷ lệ rớt sự kiện (Drop Rate %)**| *[Điền kết quả]* | *[Điền kết quả]* | `auditctl -s` (lost) vs BPF perf buffer drops |
| **Độ trễ phát hiện (Latency)**| *[Điền kết quả]* | *[Điền kết quả]* | Chênh lệch giữa timestamp syscall và timestamp alert |
| **Tác động đến I/O máy chủ** | Ghi log đĩa liên tục | Xử lý in-memory, chỉ log khi có alert | Quan sát qua `iotop` hoặc `vmstat` |

---

## 5. Phân Tích Cơ Chế Kỹ Thuật

1. **Linux Auditd**:
   - Sử dụng cơ chế socket netlink để đẩy toàn bộ sự kiện từ nhân ra userspace daemon `auditd`.
   - Với lượng syscall lớn, việc ghi liên tục vào `/var/log/audit/audit.log` có thể gây thắt cổ chai I/O đĩa cứng (Disk I/O Bottleneck) và làm chậm tiến trình người dùng nếu cấu hình cờ `-f 2` (panic/halt khi tràn buffer).

2. **eBPF PrivEsc Detector**:
   - Lọc và tiền xử lý trực tiếp trong Kernel Space (ví dụ: chỉ gửi sự kiện mở file khi đường dẫn bắt đầu bằng `/etc/s` hoặc `/etc/p`).
   - Sử dụng cơ chế BPF Perf Ring Buffer không đồng bộ (Asynchronous ring buffer) giảm thiểu context switch.
   - Nhược điểm: Cần bộ nhớ RAM để tải các mô hình ML (Random Forest, Isolation Forest) trong Python User Space.
