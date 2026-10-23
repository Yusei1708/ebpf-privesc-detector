"""
agent/features.py: Trích xuất đặc trưng hành vi tiến trình từ sự kiện eBPF
Sử dụng kỹ thuật Sliding Window (3 giây) theo timestamp của sự kiện,
Process Lineage, xử lý an toàn PID reuse và ranh giới thư mục chính xác.
"""

import time
import bisect
from collections import deque, defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
import numpy as np

# Danh sách nhị phân SUID hợp lệ của hệ điều hành Linux thông thường
WHITELISTED_SUID_BINS: Set[str] = {
    "sudo",
    "su",
    "passwd",
    "pkexec",
    "newgrp",
    "chsh",
    "chfn",
    "gpasswd",
    "mount",
    "umount",
    "crontab",
    "ping",
}

# Các thư mục thực thi đáng ngờ (ranh giới thư mục chuẩn xác)
SUSPICIOUS_DIRECTORIES = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/user",
)

# Danh sách daemon/dịch vụ mạng hoặc interpreter thường bị khai thác (Web Shell, RCE)
SERVICE_PARENT_NAMES: Set[str] = {
    "nginx",
    "apache2",
    "httpd",
    "node",
    "python",
    "python3",
    "php",
    "php-fpm",
    "ruby",
    "java",
    "redis-server",
    "mysqld",
    "postgres",
    "caddy",
    "gunicorn",
    "uwsgi",
    "dockerd",
    "containerd",
    "sh",
    "bash",
}

# Tên các feature chuẩn hóa
FEATURE_NAMES: List[str] = [
    "exec_count",
    "uid_change_flag",
    "is_whitelisted_bin",
    "suspicious_path_flag",
    "service_parent_flag",
    "sensitive_file_access",
    "cap_check_count",
    "priv_syscall_rate",
]


def is_suspicious_path(path: str) -> bool:
    """
    Kiểm tra xem đường dẫn có nằm trong thư mục tạm/nguy hiểm hay không.
    So sánh chính xác theo ranh giới thư mục để tránh so khớp sai (ví dụ: /tmpfoo không thuộc /tmp).
    """
    if not path or not isinstance(path, str):
        return False
    clean = path.strip()
    for base in SUSPICIOUS_DIRECTORIES:
        if clean == base or clean.startswith(base + "/"):
            return True
    if clean.startswith("/memfd:"):
        return True
    return False


def get_event_timestamp(event: Dict[str, Any], fallback_time: Optional[float] = None) -> float:
    """
    Trích xuất timestamp thực tế của sự kiện theo đơn vị giây (float).
    Ưu tiên:
      1. timestamp_ns (nanoseconds từ kernel bpf_ktime_get_ns())
      2. timestamp_iso (chuẩn ISO-8601 UTC)
      3. timestamp (số giây UNIX epoch)
      4. fallback_time hoặc time.time() nếu dữ liệu thiếu
    """
    if not event or not isinstance(event, dict):
        return fallback_time if fallback_time is not None else time.time()

    # 1. timestamp_ns từ nhân Linux
    ts_ns = event.get("timestamp_ns")
    if ts_ns is not None:
        try:
            val_ns = float(ts_ns)
            if val_ns > 0:
                return val_ns / 1e9
        except (ValueError, TypeError):
            pass

    # 2. timestamp (epoch seconds)
    ts_sec = event.get("timestamp")
    if ts_sec is not None:
        try:
            val_sec = float(ts_sec)
            if val_sec > 0:
                return val_sec
        except (ValueError, TypeError):
            pass

    # 3. timestamp_iso
    ts_iso = event.get("timestamp_iso")
    if ts_iso and isinstance(ts_iso, str):
        try:
            dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
            return dt.timestamp()
        except Exception:
            pass

    return fallback_time if fallback_time is not None else time.time()


class ProcessNode:
    """Đại diện cho một node trong cây phả hệ tiến trình (Process Lineage)"""
    def __init__(self, pid: int, ppid: int, comm: str, uid: int, euid: int, cgroup_id: int, mntns_id: int, start_time: float):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.uid = uid
        self.euid = euid
        self.cgroup_id = cgroup_id
        self.mntns_id = mntns_id
        self.exe_paths: List[str] = []
        self.start_time = start_time
        self.last_seen = start_time


class FeatureExtractor:
    """
    Quản lý bộ đệm sự kiện theo cửa sổ trượt (Sliding Window 3.0s) dựa trên
    timestamp thực tế của sự kiện.
    Hỗ trợ cả trực tiếp (live eBPF) lẫn phát lại ngoại tuyến (offline telemetry replay).
    """
    def __init__(self, window_size_seconds: float = 3.0):
        self.window_size = float(window_size_seconds)
        # Lưu sự kiện theo tgid: tgid -> list[(event_timestamp_float, event_dict)] (luôn duy trì sắp xếp)
        self.event_windows: Dict[int, List[Tuple[float, Dict[str, Any]]]] = defaultdict(list)
        # Bảng theo dõi cây phả hệ tiến trình: pid -> ProcessNode
        self.process_tree: Dict[int, ProcessNode] = {}
        # Theo dõi UID ban đầu khi tiến trình bắt đầu xuất hiện
        self.initial_uids: Dict[int, int] = {}

    def update_process(self, pid: int, ppid: int, comm: str, uid: int, euid: int, cgroup_id: int, mntns_id: int, event_time: Optional[float] = None):
        """
        Cập nhật trạng thái tiến trình một cách an toàn.
        Lưu ý kỹ thuật về Vòng đời & Tái sử dụng PID (PID Reuse):
        - Không xóa trạng thái chỉ vì tiến trình tạm dừng (idle).
        - Không coi việc thay đổi PPID đơn thuần là PID reuse, vì trong Linux khi tiến trình cha chết,
          tiến trình con sẽ tự động được gán lại (reparent) sang init (PID 1) hoặc systemd/subreaper.
        - Giữ nguyên trạng thái để không làm mất bằng chứng chuỗi tấn công (lineage).
        """
        ts = event_time if event_time is not None else time.time()

        if pid in self.process_tree:
            node = self.process_tree[pid]
            # Cập nhật thông tin và ghi nhận thời gian thấy mới nhất
            node.ppid = ppid
            node.comm = comm
            node.uid = uid
            node.euid = euid
            node.last_seen = max(node.last_seen, ts)
        else:
            self.process_tree[pid] = ProcessNode(pid, ppid, comm, uid, euid, cgroup_id, mntns_id, start_time=ts)
            self.initial_uids[pid] = uid

    def add_event(self, event: Dict[str, Any]):
        """
        Thêm sự kiện mới vào sliding window của tiến trình dựa trên timestamp của sự kiện.
        Tự động xử lý sự kiện đến muộn hoặc xáo trộn thứ tự thời gian.
        """
        tgid = event.get("tgid", 0)
        ev_ts = get_event_timestamp(event)

        # Cập nhật hoặc tạo tiến trình tương ứng
        if tgid not in self.process_tree:
            self.update_process(
                pid=tgid,
                ppid=event.get("ppid", 0),
                comm=event.get("comm", ""),
                uid=event.get("uid", 1000),
                euid=event.get("euid", 1000),
                cgroup_id=event.get("cgroup_id", 0),
                mntns_id=event.get("mntns_id", 0),
                event_time=ev_ts,
            )
        else:
            self.process_tree[tgid].last_seen = max(self.process_tree[tgid].last_seen, ev_ts)

        # Chèn vào cửa sổ trượt có duy trì thứ tự thời gian (Sorted insertion)
        window = self.event_windows[tgid]
        if not window or ev_ts >= window[-1][0]:
            window.append((ev_ts, event))
        else:
            # Sự kiện đến trễ: chèn nhị phân đúng vị trí timestamp
            timestamps = [entry[0] for entry in window]
            idx = bisect.bisect_right(timestamps, ev_ts)
            window.insert(idx, (ev_ts, event))

        self._prune_window(tgid, ev_ts)

    def _prune_window(self, tgid: int, current_event_time: float):
        """Loại bỏ các sự kiện có timestamp cũ hơn current_event_time - window_size"""
        window = self.event_windows.get(tgid)
        if not window:
            return

        cutoff = current_event_time - self.window_size
        # Tìm vị trí sự kiện đầu tiên thỏa mãn >= cutoff
        while window and window[0][0] < cutoff:
            window.pop(0)

        if not window and tgid in self.event_windows:
            del self.event_windows[tgid]

    def cleanup_old_processes(self, max_idle_seconds: float = 300.0, reference_time: Optional[float] = None):
        """
        Dọn dẹp các tiến trình đã kết thúc hoặc không còn hoạt động sau một khoảng thời gian dài an toàn (5 phút).
        Không xóa tùy tiện trong các khoảng thời gian ngắn để tránh mất dấu vết phả hệ.
        """
        ref_ts = reference_time if reference_time is not None else time.time()
        dead_pids = [
            pid for pid, node in self.process_tree.items()
            if (ref_ts - node.last_seen) > max_idle_seconds
        ]
        for pid in dead_pids:
            self.process_tree.pop(pid, None)
            self.initial_uids.pop(pid, None)
            self.event_windows.pop(pid, None)

    def _find_service_in_lineage(self, proc: ProcessNode, max_depth: int = 5) -> int:
        """
        Truy vết cây phả hệ cha-con (Process Lineage):
        Kiểm tra xem tiến trình hiện tại có tổ tiên nào là web/network service hay không.
        """
        curr = proc
        depth = 0
        while curr and curr.ppid in self.process_tree and depth < max_depth:
            parent = self.process_tree[curr.ppid]
            if parent.comm in SERVICE_PARENT_NAMES:
                return 1
            curr = parent
            depth += 1
        return 0

    def extract_features(self, tgid: int, current_event: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Trích xuất 8 đặc trưng chuẩn hóa dựa trên timestamp sự kiện:
        1. exec_count: Số lần gọi execve trong window
        2. uid_change_flag: 1 nếu chuyển từ UID != 0 sang EUID == 0
        3. is_whitelisted_bin: 1 nếu thuộc danh sách nhị phân hợp lệ, 0 nếu ngoài danh sách
        4. suspicious_path_flag: 1 nếu chạy từ /tmp, /dev/shm, /var/tmp (ranh giới chính xác)
        5. service_parent_flag: 1 nếu cha/tổ tiên là dịch vụ mạng/web/shell
        6. sensitive_file_access: Số lần yêu cầu mở /etc/shadow, /etc/sudoers, /etc/passwd
        7. cap_check_count: Số lần kiểm tra CAP_SETUID, CAP_SYS_ADMIN, etc.
        8. priv_syscall_rate: Tần suất gọi sự kiện nhạy cảm trên giây trong window
        """
        # Xác định mốc thời gian chuẩn từ sự kiện hiện tại hoặc sự kiện mới nhất trong cửa sổ
        cur_ts = get_event_timestamp(current_event) if current_event else None
        if cur_ts is None:
            if self.event_windows.get(tgid):
                cur_ts = self.event_windows[tgid][-1][0]
            else:
                cur_ts = time.time()

        self._prune_window(tgid, cur_ts)
        window_entries = self.event_windows.get(tgid, [])
        events_in_win = [entry[1] for entry in window_entries]

        if current_event and not any(ev is current_event for ev in events_in_win):
            events_in_win.append(current_event)

        proc = self.process_tree.get(tgid)
        parent_proc = self.process_tree.get(proc.ppid) if proc else None

        # 1. exec_count: Số lần gọi execve (EVENT_EXECVE = 1)
        exec_count = sum(1 for e in events_in_win if e.get("event_type") == 1)

        # 2. uid_change_flag (Chuyển đổi từ UID/EUID ban đầu != 0 sang EUID == 0)
        uid_change_flag = 0
        init_uid = self.initial_uids.get(tgid, proc.uid if proc else None)
        curr_euid = proc.euid if proc else (current_event.get("euid") if current_event else None)

        if init_uid is not None and curr_euid is not None:
            if init_uid != 0 and curr_euid == 0:
                uid_change_flag = 1

        # Kiểm tra chi tiết sự kiện commit_creds (EVENT_COMMIT_CREDS = 2) trong window
        for e in events_in_win:
            if e.get("event_type") == 2:
                e_uid = e.get("uid", 0)
                e_euid = e.get("euid", 0)
                if e_uid != 0 and e_euid == 0:
                    uid_change_flag = 1
                    break

        # 3. is_whitelisted_bin: 1 nếu là binary SUID hợp lệ, 0 nếu không nằm trong danh sách
        comm = proc.comm if proc else (current_event.get("comm", "") if current_event else "")
        filename = ""
        for e in reversed(events_in_win):
            if e.get("filename"):
                filename = e.get("filename")
                break
        bin_name = filename.split("/")[-1] if filename else comm

        if bin_name in WHITELISTED_SUID_BINS:
            is_whitelisted_bin = 1  # 1: Hợp lệ theo chuẩn whitelist
        else:
            is_whitelisted_bin = 0  # 0: Ngoài whitelist

        # 4. suspicious_path_flag: 1 nếu thực thi từ thư mục tạm nguy hiểm (so sánh ranh giới chuẩn xác)
        suspicious_path_flag = 0
        for e in events_in_win:
            fn = e.get("filename", "")
            if is_suspicious_path(fn):
                suspicious_path_flag = 1
                break

        # 5. service_parent_flag: Gom hành vi cha-con & tổ tiên
        service_parent_flag = 0
        if proc:
            service_parent_flag = self._find_service_in_lineage(proc)
            if not service_parent_flag and parent_proc:
                if parent_proc.comm in SERVICE_PARENT_NAMES:
                    service_parent_flag = 1
        elif current_event:
            pcomm = current_event.get("parent_comm", "")
            if pcomm in SERVICE_PARENT_NAMES:
                service_parent_flag = 1

        # 6. sensitive_file_access: Số lần yêu cầu mở /etc/shadow, /etc/sudoers, /etc/passwd (EVENT_OPENAT = 4)
        sensitive_file_access = sum(1 for e in events_in_win if e.get("event_type") == 4)

        # 7. cap_check_count: Số lần kiểm tra Capability nhạy cảm (EVENT_CAP_CHECK = 3)
        cap_check_count = sum(1 for e in events_in_win if e.get("event_type") == 3)

        # 8. priv_syscall_rate: Tần suất gọi sự kiện nhạy cảm trên giây theo timestamp thực tế
        priv_events_count = len(events_in_win)
        if priv_events_count <= 1:
            priv_syscall_rate = float(priv_events_count) / self.window_size
        else:
            first_ts = window_entries[0][0] if window_entries else (cur_ts - 1.0)
            last_ts = window_entries[-1][0] if window_entries else cur_ts
            duration = max(last_ts - first_ts, 0.1)
            duration = min(duration, self.window_size)
            priv_syscall_rate = float(priv_events_count) / duration

        raw_features = {
            "exec_count": exec_count,
            "uid_change_flag": uid_change_flag,
            "is_whitelisted_bin": is_whitelisted_bin,
            "suspicious_path_flag": suspicious_path_flag,
            "service_parent_flag": service_parent_flag,
            "sensitive_file_access": sensitive_file_access,
            "cap_check_count": cap_check_count,
            "priv_syscall_rate": round(priv_syscall_rate, 2),
        }

        feature_vector = np.array([
            exec_count,
            uid_change_flag,
            is_whitelisted_bin,
            suspicious_path_flag,
            service_parent_flag,
            sensitive_file_access,
            cap_check_count,
            priv_syscall_rate,
        ], dtype=np.float32)

        return feature_vector, raw_features
