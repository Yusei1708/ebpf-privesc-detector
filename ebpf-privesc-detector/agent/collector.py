"""
agent/collector.py: Nhận sự kiện từ BPF Ring Buffer của eBPF, duy trì Process Lineage
và chuyển giao dữ liệu cho bộ trích xuất đặc trưng và phát hiện bất thường.
"""

import os
import sys
import time
import signal
import atexit
import ctypes
import threading
from typing import Optional, Callable, Any, Dict
from pathlib import Path

# Thêm đường dẫn project vào sys.path để import nội bộ
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import (
    FLAG_EXEC_FAILED,
    FeatureExtractor,
    get_event_timestamp,
)


# C struct tương ứng với struct event_t trong ebpf/probes.c
# Khớp chính xác 200 bytes căn chỉnh 8-byte
class CEvent(ctypes.Structure):
    _fields_ = [
        ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("euid", ctypes.c_uint32),
        ("cap", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),       # Bitmask flags matching C struct (offset 28)
        ("cgroup_id", ctypes.c_uint64),
        ("pidns_id", ctypes.c_uint64),    # Active PID namespace inode (Linux 5.8-6.14)
        ("timestamp_ns", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),
    ]


class BPFCollector:
    """
    Quản lý vòng đời của eBPF Probes, thu thập telemetry từ Linux Kernel
    qua BPF Ring Buffer với cơ chế Auto-Cleanup tuyệt đối khi kết thúc hoặc gặp sự cố.
    """
    def __init__(
        self,
        probe_path: Optional[str] = None,
        event_callback: Optional[Callable] = None,
        ringbuf_pages: Optional[int] = None,
        perf_page_cnt: Optional[int] = None,
        exit_callback: Optional[Callable[[int], None]] = None,
    ):
        self.probe_path = probe_path or str(PROJECT_ROOT / "ebpf" / "probes.c")
        self.event_callback = event_callback
        self.exit_callback = exit_callback

        if ringbuf_pages is not None:
            pages = int(ringbuf_pages)
        elif perf_page_cnt is not None:
            pages = int(perf_page_cnt)
        else:
            pages = 256

        if pages < 1 or (pages & (pages - 1)) != 0:
            raise ValueError(f"ringbuf_pages phải là lũy thừa dương của 2, nhận được: {pages}")

        self.ringbuf_pages = pages
        self.perf_page_cnt = pages  # Legacy attribute alias
        self.extractor = FeatureExtractor(window_size_seconds=3.0)
        self.bpf: Optional[Any] = None
        self.running = False
        self._kernel_dropped_total = 0
        self._exe_cache: Dict[int, str] = {}
        self.stats: Dict[str, int] = {
            "events_processed": 0,
            "events_lost": 0,
            "alerts_triggered": 0,
            "callback_errors": 0,
        }

    def _signal_handler(self, signum, frame):
        """Signal handler tối giản: chỉ hạ cờ self.running để tránh re-entrancy trong ctypes callback."""
        self.running = False

    def _has_bpf_privileges(self) -> bool:
        """
        Kiểm tra quyền thực thi eBPF: chấp nhận EUID == 0 hoặc tiến trình có đủ capabilities
        (CAP_SYS_ADMIN hoặc cả CAP_BPF + CAP_PERFMON) trong CapEff của /proc/self/status.
        """
        if os.geteuid() == 0:
            return True
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_eff = int(line.split(":", 1)[1].strip(), 16)
                        has_sys_admin = (cap_eff & (1 << 21)) != 0
                        has_perfmon = (cap_eff & (1 << 38)) != 0
                        has_bpf = (cap_eff & (1 << 39)) != 0
                        return has_sys_admin or (has_bpf and has_perfmon)
        except (OSError, ValueError):
            return False
        return False

    def _read_proc_exe(self, tgid: int) -> str:
        """Đọc /proc/<tgid>/exe một lần cho cache-miss, từ chối đường dẫn '(deleted)'."""
        if tgid <= 0:
            return ""
        if tgid in self._exe_cache:
            return self._exe_cache[tgid]
        resolved = ""
        try:
            target = os.readlink(f"/proc/{tgid}/exe")
            if target and not target.endswith(" (deleted)"):
                resolved = target
        except OSError:
            resolved = ""
        if len(self._exe_cache) >= 4096:
            self._exe_cache.clear()
        self._exe_cache[tgid] = resolved
        return resolved

    def _snapshot_proc_processes(self):
        """
        Chụp nhanh cây tiến trình đang chạy từ /proc khi khởi động agent để phục vụ truy vết
        service_parent_flag và lineage cho các daemon đã khởi chạy trước khi gắn eBPF probes.
        """
        now_mono = time.monotonic()
        try:
            entries = list(os.scandir("/proc"))
        except OSError:
            return

        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
                    stat_line = f.read()
                rparen = stat_line.rfind(")")
                lparen = stat_line.find("(")
                if rparen == -1 or lparen == -1:
                    continue
                stat_comm = stat_line[lparen + 1 : rparen]
                after = stat_line[rparen + 2 :].split()
                ppid = int(after[1]) if len(after) > 1 else 0

                comm = stat_comm
                try:
                    with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as cf:
                        cval = cf.read().strip()
                        if cval:
                            comm = cval
                except OSError:
                    pass

                uid = 0
                euid = 0
                try:
                    with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as sf:
                        for sline in sf:
                            if sline.startswith("Uid:"):
                                parts = sline.split()
                                if len(parts) >= 3:
                                    uid = int(parts[1])
                                    euid = int(parts[2])
                                break
                except (OSError, ValueError):
                    uid = os.stat(f"/proc/{pid}").st_uid
                    euid = uid

                exe_path = ""
                try:
                    link = os.readlink(f"/proc/{pid}/exe")
                    if link and not link.endswith(" (deleted)"):
                        exe_path = link
                except OSError:
                    exe_path = ""

                pidns_id = 0
                mntns_id = 0
                try:
                    pidns_id = int(os.stat(f"/proc/{pid}/ns/pid").st_ino)
                except OSError:
                    pass
                try:
                    mntns_id = int(os.stat(f"/proc/{pid}/ns/mnt").st_ino)
                except OSError:
                    pass

                self.extractor.update_process(
                    pid=pid,
                    ppid=ppid,
                    comm=comm,
                    uid=uid,
                    euid=euid,
                    cgroup_id=0,
                    mntns_id=mntns_id,
                    event_time=now_mono,
                    pidns_id=pidns_id,
                    exe_path=exe_path or None,
                )
            except (OSError, ValueError):
                continue

    def _sync_dropped_events(self):
        """Đồng bộ bộ đếm sự kiện bị rớt từ map per-CPU dropped_events trong kernel."""
        if self.bpf is None:
            return
        try:
            dropped_map = self.bpf["dropped_events"]
            per_cpu = dropped_map[ctypes.c_uint32(0)]
            total_kernel_drops = sum(int(getattr(v, "value", v)) for v in per_cpu)
            delta = total_kernel_drops - self._kernel_dropped_total
            if delta > 0:
                self._kernel_dropped_total = total_kernel_drops
                self.stats["events_lost"] += delta
        except Exception:
            pass

    def _lost_event_cb(self, lost: int):
        """Callback tương thích khi ghi nhận sự kiện bị rớt từ Kernel buffer."""
        self.stats["events_lost"] += int(lost)
        print(f"[!] CẢNH BÁO BUFFER: Bị rớt {lost} sự kiện từ Kernel (tổng lost={self.stats['events_lost']}).")

    def cleanup(self):
        """Tháo gỡ tất cả probe và giải phóng tài nguyên kernel một cách an toàn (idempotent)."""
        self.running = False
        if self.bpf is not None:
            self._sync_dropped_events()
            print("[+] Đang giải phóng bộ nhớ đệm và gỡ bỏ eBPF hooks khỏi Kernel...")
            try:
                self.bpf.cleanup()
            except Exception as e:
                print(f"[-] Cảnh báo khi cleanup BPF: {e}")
            self.bpf = None
            total = self.stats["events_processed"] + self.stats["events_lost"]
            if total > 0:
                drop_rate = (self.stats["events_lost"] / total) * 100.0
                print(
                    f"[*] Thống kê eBPF Ring Buffer: processed={self.stats['events_processed']}, "
                    f"lost={self.stats['events_lost']} ({drop_rate:.2f}% drop), "
                    f"alerts={self.stats['alerts_triggered']}, "
                    f"callback_errors={self.stats['callback_errors']}"
                )
            print("[✓] Hệ thống eBPF đã được dọn dẹp sạch sẽ 100% (Zero-Footprint).")
        try:
            atexit.unregister(self.cleanup)
        except Exception:
            pass

    def _process_event(self, ctx, data, size):
        """Callback xử lý sự kiện khi có dữ liệu từ eBPF Ring Buffer."""
        if not data or size < ctypes.sizeof(CEvent):
            return

        try:
            event = ctypes.cast(data, ctypes.POINTER(CEvent)).contents
            self.stats["events_processed"] += 1

            event_dict = {
                "event_type": int(event.event_type),
                "pid": int(event.pid),
                "tgid": int(event.tgid),
                "ppid": int(event.ppid),
                "uid": int(event.uid),
                "euid": int(event.euid),
                "cap": int(event.cap),
                "flags": int(event.flags),
                "cgroup_id": int(event.cgroup_id),
                "pidns_id": int(event.pidns_id),
                "timestamp_ns": int(event.timestamp_ns),
                "comm": event.comm.decode("utf-8", "replace"),
                "filename": event.filename.decode("utf-8", "replace"),
            }

            ev_ts = get_event_timestamp(event_dict, fallback_time=time.monotonic())
            ev_type = event_dict["event_type"]
            tgid = event_dict["tgid"]
            ev_flags = event_dict["flags"]

            # 1. Thoát tiến trình: đánh dấu vòng đời & xử lý PID reuse + thông báo dọn cooldown
            if ev_type == 5:
                self.extractor.mark_process_exit(tgid, event_time=ev_ts)
                self._exe_cache.pop(tgid, None)
                if self.exit_callback is not None:
                    self.exit_callback(tgid)
                return

            # 2. Fork tiến trình: kế thừa exe_path / suspicious / service_ancestor từ cha
            if ev_type == 6:
                self._exe_cache.pop(tgid, None)
                self.extractor.register_fork(
                    parent_tgid=event_dict["ppid"],
                    child_tgid=tgid,
                    comm=event_dict["comm"],
                    uid=event_dict["uid"],
                    euid=event_dict["euid"],
                    cgroup_id=event_dict["cgroup_id"],
                    pidns_id=event_dict["pidns_id"],
                    mntns_id=0,
                    event_time=ev_ts,
                )
                return

            # 3. Execve/execveat thất bại: hoàn tác exe_path đầu cơ và loại bỏ khỏi cửa sổ
            if ev_type == 1 and (ev_flags & FLAG_EXEC_FAILED) != 0:
                self._exe_cache.pop(tgid, None)
                self.extractor.revert_failed_exec(tgid, event_time=ev_ts)
                return

            if ev_type == 1:
                self._exe_cache.pop(tgid, None)
                exe_path = event_dict["filename"] or None
            else:
                proc = self.extractor.process_tree.get(tgid)
                if proc is None or proc.exited or not proc.exe_path:
                    resolved = self._read_proc_exe(tgid)
                    exe_path = resolved or None
                else:
                    exe_path = None

            # Cập nhật thông tin tiến trình và cây phả hệ cùng miền thời gian monotonic với kernel
            self.extractor.update_process(
                pid=tgid,
                ppid=event_dict["ppid"],
                comm=event_dict["comm"],
                uid=event_dict["uid"],
                euid=event_dict["euid"],
                cgroup_id=event_dict["cgroup_id"],
                mntns_id=0,
                event_time=ev_ts,
                pidns_id=event_dict["pidns_id"],
                exe_path=exe_path,
                is_main_thread=(event_dict["pid"] == tgid),
                event_type=ev_type,
            )

            # Thêm sự kiện vào Sliding Window
            self.extractor.add_event(event_dict)

            # Trích xuất 8 đặc trưng
            feature_vec, raw_features = self.extractor.extract_features(tgid, event_dict)

            # Chuyển tiếp tới hàm callback phát hiện bất thường (nếu có)
            if self.event_callback:
                alert_res = self.event_callback(event_dict, feature_vec, raw_features, self.extractor)
                if alert_res:
                    self.stats["alerts_triggered"] += 1
        except Exception as e:
            self.stats["callback_errors"] += 1
            print(f"[!] Lỗi xử lý sự kiện eBPF trong callback: {e}", file=sys.stderr)

    def start(self):
        """Nạp chương trình eBPF vào Kernel và lắng nghe dữ liệu từ Ring Buffer."""
        if not self._has_bpf_privileges():
            print("[X] LỖI QUYỀN HẠN: Nạp eBPF probe vào Linux Kernel yêu cầu quyền root hoặc CAP_BPF+CAP_PERFMON.", file=sys.stderr)
            print("    Vui lòng chạy lại chương trình với: sudo .venv/bin/python main.py", file=sys.stderr)
            return False

        try:
            from bcc import BPF
        except ImportError:
            print("[X] LỖI: Thư viện 'bcc' hoặc 'python-bcc' chưa được cài đặt!", file=sys.stderr)
            print("    Trên Arch Linux, cài đặt bằng: sudo pacman -S bcc python-bcc", file=sys.stderr)
            return False

        if not os.path.exists(self.probe_path):
            raise FileNotFoundError(f"Không tìm thấy file eBPF probe tại: {self.probe_path}")

        prev_sigint = None
        prev_sigterm = None
        signals_installed = False

        print(f"[*] Đang biên dịch và nạp eBPF probe từ {self.probe_path} vào Kernel...")
        try:
            with open(self.probe_path, "r", encoding="utf-8") as f:
                bpf_source = f.read()

            # Chụp trước các tiến trình hiện có để giữ lineage dịch vụ trước thời điểm chạy agent
            self._snapshot_proc_processes()

            # Nạp BCC eBPF Program với cấu hình RINGBUF_PAGES động
            self.bpf = BPF(text=bpf_source, cflags=[f"-DRINGBUF_PAGES={self.ringbuf_pages}"])
            self.bpf["events"].open_ring_buffer(self._process_event)

            if threading.current_thread() is threading.main_thread():
                prev_sigint = signal.getsignal(signal.SIGINT)
                prev_sigterm = signal.getsignal(signal.SIGTERM)
                signal.signal(signal.SIGINT, self._signal_handler)
                signal.signal(signal.SIGTERM, self._signal_handler)
                signals_installed = True

            atexit.register(self.cleanup)
            self.running = True
            print(f"[✓] Agent PID: {os.getpid()}")
            print(
                "[✓] eBPF Probes (Ring Buffer) đã gắn thành công vào "
                "sys_enter_execve, sys_exit_execve, sys_enter_execveat, sys_exit_execveat, "
                "commit_creds, cap_capable, sys_enter_openat, sched_process_fork, sched_process_exit."
            )
            print("[*] Đang giám sát các sự kiện đặc quyền theo thời gian thực (Nhấn Ctrl+C để dừng)...")
        except Exception as e:
            print(f"[X] LỖI NẠP HOẶC BIÊN DỊCH eBPF PROBE: {e}", file=sys.stderr)
            print("    Gợi ý: Kiểm tra linux-headers / linux-lts-headers đã cài đặt đúng phiên bản kernel hiện tại.", file=sys.stderr)
            self.cleanup()
            return False

        # Vòng lặp poll dữ liệu từ Ring Buffer với cleanup được tiết lưu mỗi 10s
        try:
            last_cleanup = time.monotonic()
            while self.running and self.bpf is not None:
                self.bpf.ring_buffer_poll(timeout=100)
                now = time.monotonic()
                if (now - last_cleanup) >= 10.0:
                    self._sync_dropped_events()
                    self.extractor.cleanup_old_processes(reference_time=now)
                    last_cleanup = now
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()
            if signals_installed:
                try:
                    signal.signal(signal.SIGINT, prev_sigint)
                    signal.signal(signal.SIGTERM, prev_sigterm)
                except Exception:
                    pass

        return True
