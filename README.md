# eBPF & Machine Learning Linux Privilege Escalation Detector

[![GitHub Repository](https://img.shields.io/badge/GitHub-Yusei1708%2Febpf--privesc--detector-blue?logo=github)](https://github.com/Yusei1708/ebpf-privesc-detector)
[![Kernel LTS](https://img.shields.io/badge/Linux-5.8%E2%80%936.x%20LTS-orange?logo=linux)](https://kernel.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgrey)](LICENSE)

Hệ thống giám sát và phát hiện tấn công leo thang đặc quyền (**Privilege Escalation**) theo thời gian thực trên Linux Kernel, kết hợp thu thập telemetry nhân qua **eBPF (Extended Berkeley Packet Filter / BPF Ring Buffer)** và phân tích hai tầng: **Rule-based Fast Path (8 luật PRIVESC-001..008)** và **Machine Learning (Isolation Forest & Random Forest)**.

Repository: [https://github.com/Yusei1708/ebpf-privesc-detector](https://github.com/Yusei1708/ebpf-privesc-detector)

---

## 1. Kiến Trúc Hệ Thống (Architecture & Data Flow)

```text
+---------------------------------------------------------------------------------------------------+
|                                        LINUX KERNEL SPACE (9 eBPF Hooks)                          |
|                                                                                                   |
|   [tp:sys_enter/exit_execve & execveat]    [kprobe:commit_creds]         [kprobe:cap_capable]     |
|   (Thực thi / memfd & revert FLAG_EXEC_FAILED) (UID/EUID/CAP gain)      (Audited caps & userns)   |
|               |                                     |                            |                |
|               +-------------------------------------+----------------------------+                |
|                                                     |                                             |
|        [tp:sys_enter_openat]                        +--- [tp:sched_process_fork & exit]           |
|   (/etc/shadow,gshadow,sudoers*; write: passwd/preload)  (Kế thừa fork & live.counter==0)         |
|                                                     |                                             |
|                                                     v                                             |
|                      [BPF_LRU_HASH tracked_tgids + BPF_PERCPU_ARRAY dropped_events]               |
|                      [BPF_RINGBUF_OUTPUT (event_t: 200B, 8B-aligned, 256 pages)]                  |
+-----------------------------------------------------|---------------------------------------------+
                                                      |
                                                      v (ring_buffer_poll + dropped_events sync)
+---------------------------------------------------------------------------------------------------+
|                                           USER SPACE AGENT                                        |
|                                                                                                   |
|   [agent/collector.py]  ---> BPFCollector (BCC Runtime, CapEff check, /proc snapshot & fallback)  |
|                                      |                                                            |
|                                      v                                                            |
|   [agent/features.py]   ---> FeatureExtractor (3s Event Window, Fork Lineage, Sticky /tmp, TTL)   |
|                                      |                                                            |
|                                      +--------------------------------------+                     |
|                                      |                                      |                     |
|                                      v                                      v                     |
|                      [TẦNG 1: Rule-Based Fast Path]           [TẦNG 2: Machine Learning]          |
|                      - PRIVESC-001 (commit_creds)             - Random Forest (P_Attack)          |
|                      - PRIVESC-008 (fileless exec)            - Isolation Forest (Anomaly)        |
|                      - PRIVESC-005 (sensitive openat)         - StandardScaler + SHA-256 verify   |
|                      - PRIVESC-007 (container escape)         - classify_ml_tier2 & LRU Cooldown  |
|                      - PRIVESC-006 (cap probe)                                                    |
|                      - PRIVESC-004 (service root shell)                                           |
|                      - PRIVESC-003 (suspicious path exec)                                         |
|                      - PRIVESC-002 (GTFOBins SUID)                                                |
|                                      |                                      |                     |
|                                      +-------------------+------------------+                     |
|                                                          |                                        |
|                                      +-------------------+------------------+                     |
|                                      |                                      |                     |
|                                      v                                      v                     |
|                         [Rich SOC Dashboard UI]             [Structured JSONL Logging]            |
|                         (Escape markup/ANSI injection)      (0600, O_NOFOLLOW, Size Rotation)     |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Ranh Giới Quan Sát Của 9 eBPF Hooks (Observability Boundaries)

Hệ thống minh bạch về phạm vi telemetry thu thập từ Linux Kernel (tương thích Kernel 5.8 – 6.14):
1. **`tracepoint/syscalls/sys_enter_execve`, `sys_exit_execve`, `sys_enter_execveat`, `sys_exit_execveat`**:
   - Quan sát lời gọi thực thi nhị phân tại syscall entry (bao gồm fileless `(execveat:fd)` / `memfd_create`) để có `exe_path` trước khi `commit_creds` kích hoạt.
   - Nếu `sys_exit_execve`/`sys_exit_execveat` trả về `args->ret < 0`, kernel phát sự kiện gắn cờ `FLAG_EXEC_FAILED` để `FeatureExtractor` hoàn tác `exe_path` đầu cơ.
2. **`kprobe/commit_creds`**: Quan sát thời điểm kernel áp dụng `struct cred` mới cho task, phát hiện chuyển đổi UID/EUID/FSUID/EGID (`FLAG_CRED_UID_GAIN`) hoặc tăng bit `cap_effective` (`FLAG_CRED_CAP_GAIN`).
3. **`kprobe/cap_capable`**: Quan sát kiểm tra capability có audit (bỏ qua `CAP_OPT_NOAUDIT` và cred override tạm của OverlayFS; gắn cờ `FLAG_CAP_USERNS` nếu kiểm tra trong user namespace con `level > 0`). Không kết luận từ entry rằng capability đã được cấp hay bị từ chối.
4. **`tracepoint/syscalls/sys_enter_openat`**: Quan sát **ý định (entry)** mở tệp nhạy cảm (kể cả khi VFS trả về `-EACCES`). Chuẩn hóa tối đa 4 dấu `/` ở đầu và kiểm tra ranh giới chính xác: thu nhận cả đọc lẫn ghi với `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/*`; **chỉ** thu nhận `/etc/passwd` và `/etc/ld.so.preload` khi có cờ ghi (`O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND`, gắn `FLAG_OPEN_WRITE`).
5. **`tracepoint/sched/sched_process_fork` & `sched_process_exit`**: Theo dõi `fork()` từ tiến trình đã giám sát (`EVENT_PROCESS_FORK=6`) để kế thừa `exe_path`/lineage, và phát `EVENT_PROCESS_EXIT=5` khi cả thread-group thoát (`signal->live.counter == 0`, fallback `pid == tgid`) nhằm xử lý chính xác PID reuse.

---

## 3. Danh Sách 8 Đặc Trưng Hành Vi (Behavioral Features)

Trong cửa sổ trượt 3.0 giây (`Sliding Window 3.0s`), `FeatureExtractor` trích xuất 8 đặc trưng nhất quán giữa chế độ live và replay:
1. `exec_count`: Số lần gọi `execve`/`execveat` thành công (không tính lệnh có `FLAG_EXEC_FAILED`).
2. `uid_change_flag`: `1` nếu tiến trình chuyển từ `UID != 0` sang `EUID == 0` hoặc có `commit_creds` gain (`FLAG_CRED_UID_GAIN` / `FLAG_CRED_CAP_GAIN`).
3. `is_whitelisted_bin`: `1` chỉ khi có `exe_path` đã xác thực (fail-closed khi rỗng, từ chối hậu tố `" (deleted)"`) thuộc danh sách SUID hợp lệ tại `TRUSTED_BIN_DIRS` (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) và không thuộc đường dẫn nghi vấn.
4. `suspicious_path_flag`: `1` nếu thực thi từ `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/run/shm`, `/dev/mqueue`, `/memfd:`, `(execveat:fd)`, `/proc/*/fd/*` (giữ bền vững qua `ever_suspicious_path` suốt vòng đời và qua `fork()`).
5. `service_parent_flag`: `1` nếu cha hoặc tổ tiên tối đa 5 cấp (kể cả sau reparent sang PID 1 nhờ `original_ppid`) thuộc daemon mạng/ứng dụng (`nginx`, `apache2`, `httpd`, `nodejs`, `python3.*`, `php-fpm*`, `php8.*`, ...).
6. `sensitive_file_access`: Số lần mở mục tiêu nhạy cảm khớp `is_sensitive_open_target()` (bao gồm write-only cho `/etc/passwd` và `/etc/ld.so.preload`).
7. `cap_check_count`: Số lần kiểm tra capability được ghi nhận trong cửa sổ.
8. `priv_syscall_rate`: `round(priv_events_count / window_size, 4)` (đồng nhất giữa `raw_features` và vector ML).

---

## 4. Danh Sách 8 Luật Phát Hiện (Tier 1 Rules)

Đánh giá theo thứ tự độ đặc hiệu giảm dần (`evaluate_all_rules`); `highest_severity` lấy mức nghiêm trọng cao nhất trong tất cả các luật khớp:

| Mã Luật | Tên Luật | Mức Độ | MITRE | Điều Kiện Kích Hoạt |
| :--- | :--- | :--- | :--- | :--- |
| **PRIVESC-001** | `RULE_COMMIT_CREDS_EUID_JUMP` | CRITICAL | T1548.001 | `commit_creds` nâng `UID/EUID=0` hoặc `FLAG_CRED_UID_GAIN`/`FLAG_CRED_CAP_GAIN` ngoài whitelist. |
| **PRIVESC-008** | `RULE_FILELESS_EXEC_ATTEMPT` | HIGH | T1620 | Thực thi fileless qua `(execveat:fd)`, `/memfd:*` hoặc `/proc/*/fd/*` ngoài whitelist. |
| **PRIVESC-005** | `RULE_SENSITIVE_FILE_ACCESS_ATTEMPT` | HIGH | T1003.008 / T1574.006 | Mở `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*` hoặc ghi `/etc/ld.so.preload`, `/etc/passwd` (miễn trừ auth daemon root đọc chuẩn). |
| **PRIVESC-007** | `RULE_CONTAINER_ESCAPE_CAP_PROBE` | HIGH | T1611 | Trong Container (khác `pidns_id` hoặc `mntns_id`, ở `init_user_ns`): kiểm tra `CAP_SYS_MODULE`, hoặc `CAP_SYS_ADMIN`/`CAP_SYS_PTRACE` kèm ngữ cảnh rủi ro. |
| **PRIVESC-006** | `RULE_PRIVILEGED_CAPABILITY_PROBE` | MEDIUM | T1548 | Tiến trình `uid != 0` ngoài whitelist ở `init_user_ns` kiểm tra `HIGH_RISK_CAPS` hoặc `CAP_DAC_OVERRIDE` kèm ngữ cảnh rủi ro / tương quan file nhạy cảm. |
| **PRIVESC-004** | `RULE_SERVICE_SPAWNED_ROOT_SHELL` | CRITICAL | T1068 | Con/cháu của daemon dịch vụ leo thang từ non-root lên root (không miễn trừ whitelist). |
| **PRIVESC-003** | `RULE_SUSPICIOUS_PATH_PRIV_EXEC` | HIGH | T1059 | Thực thi từ đường dẫn nghi vấn với `EUID == 0` hoặc nhảy quyền ngoài whitelist. |
| **PRIVESC-002** | `RULE_GTFOBINS_SUID_ABUSE` | CRITICAL | T1548.001 | `uid_change_flag == 1`, `is_whitelisted_bin == 0`, và `EUID == 0`. |

---

## 5. Yêu Cầu Hệ Thống & Cài Đặt

### 5.1. Yêu Cầu Môi Trường
- **Hệ điều hành**: Linux Kernel 5.8+ (khuyên dùng Kernel 6.x LTS), Python 3.10+.
- **Quyền hạn**: Quyền `root` (`sudo`) **hoặc** tiến trình Python có capabilities `CAP_BPF` + `CAP_PERFMON` (hoặc `CAP_SYS_ADMIN`) trong `CapEff` (Linux 5.8+). *(Lưu ý: nếu không chạy bằng root, một số đường dẫn `/proc/<pid>/ns/*` hoặc `/proc/<pid>/exe` của tiến trình khác có thể bị kernel giới hạn đọc).*
- **Gói phụ thuộc hệ thống (Arch Linux)**:
  ```bash
  sudo pacman -S bcc python-bcc linux-lts-headers
  ```

### 5.2. Khởi Tạo Môi Trường Ảo & Làm Mới Mô Hình ML
> [!IMPORTANT]
> Sau khi cập nhật mã nguồn, hãy chạy `ml/train.py` trên máy của bạn để làm mới các tệp `.joblib` và `dataset_summary.json` kèm `model_checksums` (SHA-256) khớp với bộ 8 đặc trưng event-stream mới.

```bash
cd ebpf-privesc-detector
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt

# Huấn luyện lại mô hình cold-start & sinh SHA-256 manifest trong ml/models/
.venv/bin/python ml/train.py
```

---

## 6. Hướng Dẫn Sử Dụng, CLI Flags & Kiểm Thử

### 6.1. Chạy Toàn Bộ Unit Test Suite (Không cần Root)
```bash
cd ebpf-privesc-detector
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```

### 6.2. Kiểm Thử Cảnh Báo, Offline Telemetry Replay & Huấn Luyện ML
```bash
cd ebpf-privesc-detector

# Tự kiểm thử assertion với AlertLogger
.venv/bin/python main.py --test-alert

# Offline replay (mặc định tắt ghi alerts.jsonl trừ khi truyền --alert-log)
.venv/bin/python main.py --replay ml/data/sample_telemetry.jsonl --summary-out /tmp/replay_summary.json

# Huấn luyện hoặc kiểm tra telemetry gán nhãn thực tế
.venv/bin/python ml/train.py --telemetry-file ml/data/sample_telemetry.jsonl --check-only
.venv/bin/python ml/train.py --output-dir /tmp/custom_models
```

### 6.3. Chạy Giả Lập Tấn Công An Toàn (Zero-Footprint)
```bash
cd ebpf-privesc-detector
./tests/safe_attack_simulator.sh
```

### 6.4. Giám Sát Thời Gian Thực & Các Tham Số CLI Chính
```bash
cd ebpf-privesc-detector
sudo .venv/bin/python main.py --alert-log alerts.jsonl --ringbuf-pages 256 --cooldown 2.0 --max-log-mb 50
```
- `--alert-log PATH`: Đường dẫn file JSONL đầu ra (mặc định live: `alerts.jsonl`; mặc định `--replay`: tắt trừ khi chỉ định rõ).
- `--no-log`: Tắt hoàn toàn ghi file log JSONL.
- `--quiet`: Ẩn bảng Rich trên terminal (vẫn ghi log file nếu bật).
- `--cooldown SEC`: Thời gian chống lặp cảnh báo theo từng `(tgid, rule_id)` (mặc định `2.0`s).
- `--models-dir DIR`: Chỉ định thư mục chứa `.joblib` và `dataset_summary.json`.
- `--ringbuf-pages N` (alias `--perf-pages`): Số trang `BPF_RINGBUF_OUTPUT` (lũy thừa của 2, mặc định `256`).
- `--max-log-mb MB`: Giới hạn dung lượng mỗi file log JSONL trước khi xoay vòng (mặc định `50.0` MB, giữ tối đa 5 bản sao lưu `0600`).
- `--allow-untrusted-models`: Cho phép nạp model không thuộc sở hữu root khi chạy ở quyền root (chỉ dùng cho kiểm thử).
- `--summary-out PATH`: Xuất báo cáo JSON khi chạy `--replay`.

---

## 7. Đo Kiểm Đối Chuẩn Hiệu Năng (Benchmark vs Auditd)

- Công cụ đo kiểm: [`benchmarks/benchmark_agent_vs_auditd.py`](ebpf-privesc-detector/benchmarks/benchmark_agent_vs_auditd.py)
- Hướng dẫn chi tiết: [`benchmarks/BENCHMARK_GUIDE.md`](ebpf-privesc-detector/benchmarks/BENCHMARK_GUIDE.md)

> [!WARNING]
> **Không dùng `pgrep -f "main.py" | head -n 1`**: Lệnh đó bắt nhầm PID của tiến trình cha `sudo` thay vì tiến trình Python thật. Hãy dùng trực tiếp giá trị `[✓] Agent PID: <PID>` do Agent in ra khi khởi động hoặc `pgrep -nf "python.*main\.py"`.

```bash
AGENT_PID=$(pgrep -nf "python.*main\.py")
ebpf-privesc-detector/.venv/bin/python ebpf-privesc-detector/benchmarks/benchmark_agent_vs_auditd.py \
    --pid "${AGENT_PID}" --label "eBPF-Agent" --duration 30 --output ebpf_benchmark_result.json

AUDITD_PID=$(pgrep -x auditd)
ebpf-privesc-detector/.venv/bin/python ebpf-privesc-detector/benchmarks/benchmark_agent_vs_auditd.py \
    --pid "${AUDITD_PID}" --label "Auditd" --duration 30 --include-children --output auditd_benchmark_result.json
```

---

## 8. Giới Hạn Kỹ Thuật (Known Limitations)

1. **Ranh giới Syscall Entry vs Exit**: `sys_exit_execve`/`sys_exit_execveat` đã hỗ trợ phát hiện và hoàn tác lệnh `exec` thất bại (`FLAG_EXEC_FAILED`); tuy nhiên `sys_enter_openat` và `kprobe/cap_capable` vẫn quan sát ý định tại entry (bao gồm cả các lần mở file bị từ chối `-EACCES`).
2. **Kỹ thuật Tấn công DKOM (Direct Kernel Object Manipulation)**: Nếu kẻ tấn công ghi trực tiếp vào vùng nhớ `struct cred` mà không qua `commit_creds()`, kprobe tại `commit_creds` sẽ không được kích hoạt.
3. **Thời gian biên dịch JIT ban đầu của BCC**: BCC biên dịch `ebpf/probes.c` bằng Clang/LLVM tại runtime mất khoảng 1–3 giây khi khởi động.
4. **Giới hạn quan sát của `kprobe/cap_capable`**: Sự kiện `cap_capable` phản ánh kernel kiểm tra capability chứ không tự khẳng định quyền đã được cấp, do đó chỉ dùng làm cảnh báo `MEDIUM` khi có ngữ cảnh rủi ro đi kèm hoặc `HIGH` khi thoát container.
