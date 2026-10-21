"""
agent/collector.py: Nhận sự kiện từ Ring/Perf Buffer của eBPF, duy trì Process Lineage
và chuyển giao dữ liệu cho bộ trích xuất đặc trưng và phát hiện bất thường.
"""

import os
import sys
import time
import signal
import atexit
import ctypes
from typing import Optional, Callable, Any, Dict, List
from pathlib import Path

# Thêm đường dẫn project vào sys.path để import nội bộ
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import FeatureExtractor

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
        ("_pad", ctypes.c_uint32),       # Explicit 4-byte padding matching C struct
        ("cgroup_id", ctypes.c_uint64),
        ("mntns_id", ctypes.c_uint64),
        ("timestamp_ns", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 128),
    ]


class BPFCollector:
    """
    Quản lý vòng đời của eBPF Probes, thu thập telemetry từ Linux Kernel
    với cơ chế Auto-Cleanup tuyệt đối khi kết thúc hoặc gặp sự cố.
    """
    def __init__(self, probe_path: Optional[str] = None, event_callback: Optional[Callable] = None):
        self.probe_path = probe_path or str(PROJECT_ROOT / "ebpf" / "probes.c")
        self.event_callback = event_callback
        self.extractor = FeatureExtractor(window_size_seconds=3.0)
        self.bpf: Optional[Any] = None
        self.running = False

        # Đăng ký cơ chế dọn dẹp khẩn cấp qua atexit và signal handler
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"\n[!] Nhận tín hiệu ngắt {signum}. Đang dọn dẹp và tháo gỡ eBPF probes...")
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Tháo gỡ tất cả probe và giải phóng tài nguyên kernel"""
        if self.bpf is not None:
            self.running = False
            print("[+] Đang giải phóng bộ nhớ đệm và gỡ bỏ eBPF hooks khỏi Kernel...")
            try:
                # BCC tự động detach kprobes/tracepoints khi đóng object
                self.bpf.cleanup()
            except Exception as e:
                print(f"[-] Cảnh báo khi cleanup BPF: {e}")
            self.bpf = None
            print("[✓] Hệ thống eBPF đã được dọn dẹp sạch sẽ 100% (Zero-Footprint).")
        else:
            self.running = False

    def _process_event(self, cpu, data, size):
        """Callback xử lý sự kiện khi có dữ liệu từ eBPF Perf Ring Buffer"""
        event = ctypes.cast(data, ctypes.POINTER(CEvent)).contents

        event_dict = {
            "event_type": event.event_type,
            "pid": event.pid,
            "tgid": event.tgid,
            "ppid": event.ppid,
            "uid": event.uid,
            "euid": event.euid,
            "cap": event.cap,
            "cgroup_id": event.cgroup_id,
            "mntns_id": event.mntns_id,
            "timestamp_ns": event.timestamp_ns,
            "comm": event.comm.decode("utf-8", "replace"),
            "filename": event.filename.decode("utf-8", "replace"),
        }

        # Cập nhật thông tin tiến trình và cây phả hệ
        self.extractor.update_process(
            pid=event_dict["tgid"],
            ppid=event_dict["ppid"],
            comm=event_dict["comm"],
            uid=event_dict["uid"],
            euid=event_dict["euid"],
            cgroup_id=event_dict["cgroup_id"],
            mntns_id=event_dict["mntns_id"],
        )

        # Thêm sự kiện vào Sliding Window
        self.extractor.add_event(event_dict)

        # Trích xuất 8 đặc trưng
        feature_vec, raw_features = self.extractor.extract_features(event_dict["tgid"], event_dict)

        # Chuyển tiếp tới hàm callback phát hiện bất thường (nếu có)
        if self.event_callback:
            self.event_callback(event_dict, feature_vec, raw_features, self.extractor)

    def start(self):
        """Nạp chương trình eBPF vào Kernel và lắng nghe dữ liệu"""
        # Kiểm tra quyền root / đặc quyền hệ thống trước khi khởi tạo
        if os.geteuid() != 0:
            print("[X] LỖI QUYỀN HẠN: Nạp eBPF probe vào Linux Kernel yêu cầu quyền root.")
            print("    Vui lòng chạy lại chương trình với: sudo .venv/bin/python main.py")
            print("    (Hoặc cấp các capabilities đặc quyền: CAP_BPF, CAP_PERFMON, CAP_SYS_RESOURCE)")
            return False

        try:
            from bcc import BPF
        except ImportError:
            print("[X] LỖI: Thư viện 'bcc' hoặc 'python-bcc' chưa được cài đặt!")
            print("    Trên Arch Linux, cài đặt bằng: sudo pacman -S bcc python-bcc")
            print("    Sau đó chạy lại với quyền sudo hoặc cấp quyền CAP_BPF.")
            return False

        if not os.path.exists(self.probe_path):
            raise FileNotFoundError(f"Không tìm thấy file eBPF probe tại: {self.probe_path}")

        print(f"[*] Đang biên dịch và nạp eBPF probe từ {self.probe_path} vào Kernel...")
        try:
            with open(self.probe_path, "r") as f:
                bpf_source = f.read()

            # Nạp BCC eBPF Program
            self.bpf = BPF(text=bpf_source)
            self.bpf["events"].open_perf_buffer(self._process_event)
            self.running = True
            print("[✓] eBPF Probes đã gắn thành công vào sys_enter_execve, commit_creds, cap_capable, sys_enter_openat.")
            print("[*] Đang giám sát các sự kiện đặc quyền theo thời gian thực (Nhấn Ctrl+C để dừng)...")
        except Exception as e:
            print(f"[X] LỖI NẠP HOẶC BIÊN DỊCH eBPF PROBE: {e}")
            print("    Gợi ý: Kiểm tra linux-lts-headers đã cài đặt đúng phiên bản kernel hiện tại.")
            self.cleanup()
            return False

        # Vòng lặp poll dữ liệu từ Perf Buffer
        try:
            while self.running and self.bpf is not None:
                self.bpf.perf_buffer_poll(timeout=100)
                self.extractor.cleanup_old_processes()
        except KeyboardInterrupt:
            pass
        finally:
            self.cleanup()

        return True
