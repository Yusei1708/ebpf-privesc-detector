"""
benchmarks/benchmark_agent_vs_auditd.py: Công cụ đo lường hiệu năng định lượng
Đo lường CPU (%) và RAM (RSS MB) từ giao diện /proc/<pid>/stat và /proc/<pid>/status.
Không ngụy tạo số liệu - Không đo độ trễ hoặc tỷ lệ mất gói giả lập nếu chưa có bộ phát tải tương quan.
"""

import os
import sys
import math
import time
import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


def _percentile(values: List[float], pct: float) -> float:
    """Tính phân vị (percentile) không phụ thuộc thư viện bên thứ ba."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(round((pct / 100.0) * (len(ordered) - 1)))
    idx = max(0, min(len(ordered) - 1, idx))
    return round(ordered[idx], 2)


def parse_proc_stat_fields(stat_content: str) -> Optional[Tuple[int, int]]:
    """
    Phân tích tổng jiffies (utime + stime) và starttime (field 22) từ /proc/<pid>/stat.
    Tìm dấu ')' cuối cùng để không bị lệch chỉ số khi comm chứa khoảng trắng hoặc dấu ngoặc.
    """
    if not stat_content:
        return None
    rparen = stat_content.rfind(")")
    if rparen == -1:
        return None
    after_comm = stat_content[rparen + 1 :].split()
    if len(after_comm) <= 19:
        return None
    try:
        utime = int(after_comm[11])
        stime = int(after_comm[12])
        starttime = int(after_comm[19])
        return utime + stime, starttime
    except (ValueError, IndexError):
        return None


def parse_proc_stat_jiffies(stat_content: str) -> Optional[int]:
    """Giữ tương thích ngược: trả về tổng jiffies (utime + stime) từ /proc/<pid>/stat."""
    parsed = parse_proc_stat_fields(stat_content)
    if parsed is None:
        return None
    return parsed[0]


class ProcessMonitor:
    """
    Theo dõi việc tiêu thụ tài nguyên phần cứng của tiến trình mục tiêu (và tùy chọn tiến trình con)
    thông qua giao diện ảo /proc/<pid>/stat và /proc/<pid>/status của Linux Kernel.
    """

    def __init__(self, pid: int, include_children: bool = False):
        if pid <= 0:
            raise ValueError(f"PID không hợp lệ: {pid}")
        self.pid = pid
        self.include_children = include_children
        self.proc_stat = Path(f"/proc/{pid}/stat")
        self.proc_status = Path(f"/proc/{pid}/status")
        self.clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"]) if hasattr(os, "sysconf") else 100

        if not self.proc_stat.exists():
            raise ProcessLookupError(f"Tiến trình PID {pid} không tồn tại trên hệ thống!")

        initial_fields = self._read_stat_fields(pid)
        if initial_fields is None:
            raise PermissionError(f"Không thể đọc hoặc phân tích /proc/{pid}/stat!")

        initial_jiffies, self.start_time = initial_fields
        self.last_cpu_time: float = float(initial_jiffies) / self.clk_tck
        self.last_timestamp: float = time.monotonic()
        self.pid_reused: bool = False
        self._proc_cpu_history: Dict[Tuple[int, int], float] = {
            (pid, self.start_time): self.last_cpu_time
        }

        # Kiểm tra quyền đọc /proc/<pid>/status và VmRSS ngay lúc khởi tạo
        try:
            with open(self.proc_status, "r", encoding="utf-8", errors="replace") as f:
                status_text = f.read()
            if "VmRSS:" not in status_text:
                print(
                    f"[!] Cảnh báo: /proc/{pid}/status không có trường VmRSS (có thể là kernel thread hoặc bị giới hạn).",
                    file=sys.stderr,
                )
        except OSError as e:
            print(f"[!] Cảnh báo: Không đọc được /proc/{pid}/status ({e}).", file=sys.stderr)

        if self.include_children:
            for cpid in self._collect_tree_pids():
                if cpid == self.pid:
                    continue
                cfields = self._read_stat_fields(cpid)
                if cfields is not None:
                    cjiffies, cstart = cfields
                    self._proc_cpu_history[(cpid, cstart)] = float(cjiffies) / self.clk_tck

    def _read_stat_fields(self, pid: int) -> Optional[Tuple[int, int]]:
        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
                return parse_proc_stat_fields(f.read())
        except OSError:
            return None

    def _collect_tree_pids(self) -> List[int]:
        """Thu thập danh sách PID gồm tiến trình gốc và toàn bộ tiến trình con cháu đang chạy."""
        seen: Set[int] = set()
        queue: List[int] = [self.pid]
        children_file_available = False

        while queue:
            curr = queue.pop(0)
            if curr in seen:
                continue
            seen.add(curr)
            task_dir = Path(f"/proc/{curr}/task")
            try:
                for tid_dir in task_dir.iterdir():
                    cfile = tid_dir / "children"
                    try:
                        text = cfile.read_text(encoding="utf-8", errors="replace").strip()
                        children_file_available = True
                    except OSError:
                        continue
                    if not text:
                        continue
                    for tok in text.split():
                        try:
                            cpid = int(tok)
                            if cpid > 0 and cpid not in seen:
                                queue.append(cpid)
                        except ValueError:
                            continue
            except OSError:
                continue

        if children_file_available or len(seen) > 1:
            return list(seen)

        # Fallback nếu kernel không bật CONFIG_PROC_CHILDREN: quét PPID trong /proc/[0-9]*/stat
        ppid_map: Dict[int, List[int]] = {}
        try:
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    content = (entry / "stat").read_text(encoding="utf-8", errors="replace")
                    rparen = content.rfind(")")
                    if rparen == -1:
                        continue
                    after_comm = content[rparen + 1 :].split()
                    if len(after_comm) > 1:
                        ppid = int(after_comm[1])
                        ppid_map.setdefault(ppid, []).append(int(entry.name))
                except (OSError, ValueError):
                    continue
        except OSError:
            return [self.pid]

        result: List[int] = []
        bfs = [self.pid]
        visited: Set[int] = set()
        while bfs:
            curr = bfs.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            result.append(curr)
            bfs.extend(ppid_map.get(curr, []))
        return result

    def is_alive_same_process(self) -> bool:
        """Kiểm tra tiến trình gốc còn tồn tại và không bị kernel tái sử dụng PID (starttime không đổi)."""
        fields = self._read_stat_fields(self.pid)
        if fields is None:
            return False
        if fields[1] != self.start_time:
            self.pid_reused = True
            return False
        return True

    def _read_cpu_time(self) -> Optional[float]:
        """Đọc tổng thời gian CPU (giây) của tiến trình gốc từ /proc/<pid>/stat, trả về None nếu lỗi."""
        fields = self._read_stat_fields(self.pid)
        if fields is None:
            return None
        total_jiffies, starttime = fields
        if starttime != self.start_time:
            self.pid_reused = True
            return None
        return float(total_jiffies) / self.clk_tck

    def _read_rss_mb_for_pid(self, pid: int) -> Optional[float]:
        try:
            with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        return float(parts[1]) / 1024.0
        except (OSError, IndexError, ValueError):
            return None
        return None

    def get_memory_rss_mb(self) -> Optional[float]:
        """Đọc dung lượng bộ nhớ vật lý thực tế (RSS) theo MB; trả về None nếu không đọc được."""
        if not self.is_alive_same_process():
            return None
        if not self.include_children:
            rss = self._read_rss_mb_for_pid(self.pid)
            return round(rss, 2) if rss is not None else None

        total_rss = 0.0
        any_read = False
        for pid in self._collect_tree_pids():
            rss = self._read_rss_mb_for_pid(pid)
            if rss is not None:
                total_rss += rss
                any_read = True
        return round(total_rss, 2) if any_read else None

    def sample_cpu_percent(self) -> Optional[float]:
        """Tính tỷ lệ phần trăm CPU tiêu thụ kể từ lần đo thành công trước; giữ nguyên trạng thái nếu đọc lỗi."""
        now = time.monotonic()
        elapsed = now - self.last_timestamp
        if elapsed <= 0:
            return None

        if not self.include_children:
            current_cpu_time = self._read_cpu_time()
            if current_cpu_time is None:
                return None
            delta_cpu = max(0.0, current_cpu_time - self.last_cpu_time)
            self.last_cpu_time = current_cpu_time
            self.last_timestamp = now
            return round((delta_cpu / elapsed) * 100.0, 2)

        # Kiểm tra tiến trình gốc trước
        root_fields = self._read_stat_fields(self.pid)
        if root_fields is None:
            return None
        if root_fields[1] != self.start_time:
            self.pid_reused = True
            return None

        tree_pids = self._collect_tree_pids()
        active_keys: Set[Tuple[int, int]] = set()
        delta_cpu = 0.0

        for pid in tree_pids:
            fields = self._read_stat_fields(pid)
            if fields is None:
                continue
            jiffies, starttime = fields
            cpu_sec = float(jiffies) / self.clk_tck
            key = (pid, starttime)
            active_keys.add(key)
            prev_cpu = self._proc_cpu_history.get(key)
            if prev_cpu is not None:
                delta_cpu += max(0.0, cpu_sec - prev_cpu)
            else:
                delta_cpu += cpu_sec
            self._proc_cpu_history[key] = cpu_sec

        # Thu dọn các tiến trình con đã thoát khỏi lịch sử
        for old_key in list(self._proc_cpu_history.keys()):
            if old_key not in active_keys:
                del self._proc_cpu_history[old_key]

        self.last_timestamp = now
        return round((delta_cpu / elapsed) * 100.0, 2)


def run_benchmark(
    target_pid: int,
    duration_sec: float,
    sample_interval: float = 0.5,
    label: str = "TargetProcess",
    output_file: Optional[str] = None,
    include_children: bool = False,
) -> Dict[str, object]:
    if target_pid <= 0:
        print(f"[X] PID không hợp lệ ({target_pid}). Phải lớn hơn 0.", file=sys.stderr)
        sys.exit(1)
    if not math.isfinite(duration_sec) or duration_sec <= 0:
        print(f"[X] --duration ({duration_sec}) phải là số hữu hạn lớn hơn 0.", file=sys.stderr)
        sys.exit(1)
    if not math.isfinite(sample_interval) or sample_interval <= 0:
        print(f"[X] --interval ({sample_interval}) phải là số hữu hạn lớn hơn 0.", file=sys.stderr)
        sys.exit(1)

    out_path: Optional[Path] = None
    if output_file:
        out_path = Path(output_file)
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"[X] Không thể tạo thư mục cho --output '{output_file}': {e}", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Bắt đầu Benchmark cho tiến trình: {label} (PID={target_pid}, include_children={include_children})")
    print(f"    Thời gian đo: {duration_sec}s | Tần suất lấy mẫu: {sample_interval}s")

    try:
        monitor = ProcessMonitor(target_pid, include_children=include_children)
    except Exception as e:
        print(f"[X] Lỗi khởi tạo ProcessMonitor: {e}", file=sys.stderr)
        sys.exit(1)

    cpu_samples: List[float] = []
    rss_samples: List[float] = []
    start_time = time.monotonic()

    try:
        while (time.monotonic() - start_time) < duration_sec:
            time.sleep(sample_interval)
            if not monitor.is_alive_same_process():
                if monitor.pid_reused:
                    print(f"\n[!] Phát hiện PID={target_pid} đã bị hệ điều hành tái sử dụng (starttime thay đổi). Dừng đo.")
                else:
                    print(f"\n[!] Tiến trình PID={target_pid} đã kết thúc sớm trước khi hết thời gian đo.")
                break

            cpu = monitor.sample_cpu_percent()
            rss = monitor.get_memory_rss_mb()

            if cpu is not None:
                cpu_samples.append(cpu)
            if rss is not None:
                rss_samples.append(rss)

            cpu_disp = f"{cpu:5.2f}%" if cpu is not None else "  N/A "
            rss_disp = f"{rss:6.2f} MB" if rss is not None else "   N/A   "
            print(
                f"  [+] Elapsed: {int(time.monotonic() - start_time):2d}s | CPU: {cpu_disp} | RAM (RSS): {rss_disp}",
                end="\r",
            )
    except KeyboardInterrupt:
        print("\n[!] Nhận ngắt người dùng. Dừng thu thập mẫu.")

    actual_elapsed_sec = round(time.monotonic() - start_time, 2)
    print("\n[✓] Hoàn thành đo kiểm.")

    avg_cpu = round(sum(cpu_samples) / len(cpu_samples), 2) if cpu_samples else 0.0
    p95_cpu = _percentile(cpu_samples, 95)
    peak_cpu = round(max(cpu_samples), 2) if cpu_samples else 0.0
    avg_rss = round(sum(rss_samples) / len(rss_samples), 2) if rss_samples else 0.0
    p95_rss = _percentile(rss_samples, 95)
    peak_rss = round(max(rss_samples), 2) if rss_samples else 0.0

    report: Dict[str, object] = {
        "label": label,
        "pid": target_pid,
        "include_children": include_children,
        "cpu_count": os.cpu_count() or 1,
        "duration_sec": duration_sec,
        "actual_elapsed_sec": actual_elapsed_sec,
        "samples_collected": len(cpu_samples),
        "rss_samples_collected": len(rss_samples),
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
    print(f"  - Thời gian thực tế:  {actual_elapsed_sec}s (CPU cores: {report['cpu_count']})")
    print(f"  - CPU Trung bình:     {avg_cpu}% (P95: {p95_cpu}% | Đỉnh: {peak_cpu}%)")
    print(f"  - RAM RSS Trung bình: {avg_rss} MB (P95: {p95_rss} MB | Đỉnh: {peak_rss} MB)")
    print(f"  - Tổng số mẫu CPU:    {len(cpu_samples)} | Mẫu RSS: {len(rss_samples)}")
    print("=" * 60)

    if out_path is not None:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"[✓] Đã lưu báo cáo chi tiết vào file: {out_path}")
        except OSError as e:
            print(f"[X] Không thể ghi báo cáo vào '{out_path}': {e}", file=sys.stderr)
            sys.exit(1)

    return report


def main():
    parser = argparse.ArgumentParser(description="Benchmark hiệu năng định lượng giữa eBPF Agent và Linux Auditd")
    parser.add_argument("--pid", type=int, required=True, help="PID của tiến trình cần đo (eBPF Agent hoặc auditd)")
    parser.add_argument("--label", type=str, default="TargetProcess", help="Nhãn tiến trình (ví dụ: eBPF-Agent hoặc Auditd)")
    parser.add_argument("--duration", type=float, default=30.0, help="Thời gian đo (giây, > 0, mặc định: 30)")
    parser.add_argument("--interval", type=float, default=0.5, help="Chu kỳ lấy mẫu (giây, > 0, mặc định: 0.5)")
    parser.add_argument("--include-children", action="store_true", help="Cộng gộp CPU và RSS của các tiến trình con")
    parser.add_argument("--output", type=str, default=None, help="File xuất báo cáo JSON")
    args = parser.parse_args()

    if args.pid <= 0:
        print(f"[X] --pid ({args.pid}) phải là số nguyên dương.", file=sys.stderr)
        sys.exit(1)
    if not math.isfinite(args.duration) or args.duration <= 0:
        print(f"[X] --duration ({args.duration}) phải là số hữu hạn lớn hơn 0.", file=sys.stderr)
        sys.exit(1)
    if not math.isfinite(args.interval) or args.interval <= 0:
        print(f"[X] --interval ({args.interval}) phải là số hữu hạn lớn hơn 0.", file=sys.stderr)
        sys.exit(1)

    run_benchmark(
        target_pid=args.pid,
        duration_sec=args.duration,
        sample_interval=args.interval,
        label=args.label,
        output_file=args.output,
        include_children=args.include_children,
    )


if __name__ == "__main__":
    main()
