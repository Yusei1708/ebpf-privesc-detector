"""
benchmarks/benchmark_agent_vs_auditd.py: Công cụ đo lường hiệu năng định lượng
Đo lường CPU (%) và RAM (RSS MB) từ giao diện /proc/<pid>/stat và /proc/<pid>/status.
Không ngụy tạo số liệu - Không đo độ trễ hoặc tỷ lệ mất gói giả lập nếu chưa có bộ phát tải tương quan.
"""

import os
import sys
import time
import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, Optional


def _percentile(values: List[float], pct: float) -> float:
    """Tính phân vị (percentile) không phụ thuộc thư viện bên thứ ba."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    idx = max(0, min(len(ordered) - 1, idx))
    return round(ordered[idx], 2)


def parse_proc_stat_jiffies(stat_content: str) -> Optional[int]:
    """
    Phân tích an toàn tổng jiffies (utime + stime) từ nội dung /proc/<pid>/stat.
    Tìm dấu ')' cuối cùng để không bị lệch chỉ số khi tên tiến trình (comm) chứa khoảng trắng hoặc dấu ngoặc.
    """
    if not stat_content:
        return None
    rparen = stat_content.rfind(")")
    if rparen == -1:
        return None
    after_comm = stat_content[rparen + 1 :].split()
    if len(after_comm) <= 12:
        return None
    try:
        utime = int(after_comm[11])
        stime = int(after_comm[12])
        return utime + stime
    except (ValueError, IndexError):
        return None


class ProcessMonitor:
    """
    Theo dõi việc tiêu thụ tài nguyên phần cứng của tiến trình mục tiêu
    thông qua giao diện ảo /proc/<pid>/stat và /proc/<pid>/status của Linux Kernel.
    """
    def __init__(self, pid: int):
        self.pid = pid
        self.proc_stat = Path(f"/proc/{pid}/stat")
        self.proc_status = Path(f"/proc/{pid}/status")
        self.clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"]) if hasattr(os, "sysconf") else 100
        self.page_size_kb = (os.sysconf("SC_PAGE_SIZE") // 1024) if hasattr(os, "sysconf") else 4

        if not self.proc_stat.exists():
            raise ProcessLookupError(f"Tiến trình PID {pid} không tồn tại trên hệ thống!")

        self.last_cpu_time = self._read_cpu_time()
        self.last_timestamp = time.monotonic()

    def _read_cpu_time(self) -> float:
        """Đọc tổng thời gian CPU (utime + stime) của tiến trình từ /proc/<pid>/stat"""
        try:
            with open(self.proc_stat, "r", encoding="utf-8", errors="replace") as f:
                total_jiffies = parse_proc_stat_jiffies(f.read())
                if total_jiffies is not None:
                    return float(total_jiffies) / self.clk_tck
        except IOError:
            pass
        return 0.0

    def get_memory_rss_mb(self) -> float:
        """Đọc dung lượng bộ nhớ vật lý thực tế (Resident Set Size - RSS) theo MB"""
        try:
            with open(self.proc_status, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        # Ví dụ: VmRSS:   24560 kB
                        parts = line.split()
                        return round(float(parts[1]) / 1024.0, 2)
        except (IOError, IndexError, ValueError):
            pass
        return 0.0

    def sample_cpu_percent(self) -> float:
        """Tính toán tỷ lệ phần trăm CPU tiêu thụ kể từ lần đo trước"""
        now = time.monotonic()
        elapsed = now - self.last_timestamp
        if elapsed <= 0:
            return 0.0

        current_cpu_time = self._read_cpu_time()
        delta_cpu = max(0.0, current_cpu_time - self.last_cpu_time)

        self.last_cpu_time = current_cpu_time
        self.last_timestamp = now

        # CPU % tính theo 1 core (nếu đa nhân, có thể > 100%)
        cpu_percent = (delta_cpu / elapsed) * 100.0
        return round(cpu_percent, 2)


def run_benchmark(target_pid: int, duration_sec: int, sample_interval: float = 0.5,
                  label: str = "TargetProcess", output_file: Optional[str] = None):
    print(f"[*] Bắt đầu Benchmark cho tiến trình: {label} (PID={target_pid})")
    print(f"    Thời gian đo: {duration_sec}s | Tần suất lấy mẫu: {sample_interval}s")

    try:
        monitor = ProcessMonitor(target_pid)
    except Exception as e:
        print(f"[X] Lỗi khởi tạo ProcessMonitor: {e}")
        return

    cpu_samples: List[float] = []
    rss_samples: List[float] = []
    start_time = time.monotonic()

    try:
        while (time.monotonic() - start_time) < duration_sec:
            time.sleep(sample_interval)
            if not monitor.proc_stat.exists():
                print(f"\n[!] Tiến trình PID={target_pid} đã kết thúc sớm trước khi hết thời gian đo.")
                break
            cpu = monitor.sample_cpu_percent()
            rss = monitor.get_memory_rss_mb()
            cpu_samples.append(cpu)
            rss_samples.append(rss)
            print(f"  [+] Elapsed: {int(time.monotonic() - start_time):2d}s | CPU: {cpu:5.2f}% | RAM (RSS): {rss:6.2f} MB", end="\r")
    except KeyboardInterrupt:
        print("\n[!] Nhận ngắt người dùng. Dừng thu thập mẫu.")

    print("\n[✓] Hoàn thành đo kiểm.")

    avg_cpu = round(sum(cpu_samples) / len(cpu_samples), 2) if cpu_samples else 0.0
    p95_cpu = _percentile(cpu_samples, 95)
    peak_cpu = round(max(cpu_samples), 2) if cpu_samples else 0.0
    avg_rss = round(sum(rss_samples) / len(rss_samples), 2) if rss_samples else 0.0
    p95_rss = _percentile(rss_samples, 95)
    peak_rss = round(max(rss_samples), 2) if rss_samples else 0.0

    report = {
        "label": label,
        "pid": target_pid,
        "duration_sec": duration_sec,
        "samples_collected": len(cpu_samples),
        "cpu_percent": {
            "average": avg_cpu,
            "p95": p95_cpu,
            "peak": peak_cpu,
        },
        "memory_rss_mb": {
            "average": avg_rss,
            "p95": p95_rss,
            "peak": peak_rss,
        },
    }

    print("\n" + "=" * 60)
    print(f"--- BÁO CÁO KẾT QUẢ ĐO KIỂM THỰC NGHIỆM: {label} ---")
    print(f"  - CPU Trung bình:     {avg_cpu}% (P95: {p95_cpu}% | Đỉnh: {peak_cpu}%)")
    print(f"  - RAM RSS Trung bình: {avg_rss} MB (P95: {p95_rss} MB | Đỉnh: {peak_rss} MB)")
    print(f"  - Tổng số mẫu:        {len(cpu_samples)}")
    print("=" * 60)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[✓] Đã lưu báo cáo chi tiết vào file: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Benchmark hiệu năng định lượng giữa eBPF Agent và Linux Auditd")
    parser.add_argument("--pid", type=int, required=True, help="PID của tiến trình cần đo (eBPF Agent hoặc auditd)")
    parser.add_argument("--label", type=str, default="TargetProcess", help="Nhãn tiến trình (ví dụ: eBPF-Agent hoặc Auditd)")
    parser.add_argument("--duration", type=int, default=30, help="Thời gian đo (giây, mặc định: 30s)")
    parser.add_argument("--interval", type=float, default=0.5, help="Chu kỳ lấy mẫu (giây, mặc định: 0.5s)")
    parser.add_argument("--output", type=str, default=None, help="File xuất báo cáo JSON")
    args = parser.parse_args()

    run_benchmark(
        target_pid=args.pid,
        duration_sec=args.duration,
        sample_interval=args.interval,
        label=args.label,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
