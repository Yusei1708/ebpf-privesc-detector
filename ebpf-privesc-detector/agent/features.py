"""
agent/features.py: Trích xuất đặc trưng hành vi tiến trình từ sự kiện eBPF
Sử dụng kỹ thuật Sliding Window (3 giây), Process Lineage, xử lý PID reuse và gom hành vi cha-con.
"""

import time
from collections import deque, defaultdict
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

# Các đường dẫn thực thi đáng ngờ (nơi attacker hay drop payload/script)
SUSPICIOUS_PATH_PREFIXES = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/user",
    "/memfd:",
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


class ProcessNode:
    """Đại diện cho một node trong cây phả hệ tiến trình (Process Lineage)"""
    def __init__(self, pid: int, ppid: int, comm: str, uid: int, euid: int, cgroup_id: int, mntns_id: int):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.uid = uid
        self.euid = euid
        self.cgroup_id = cgroup_id
        self.mntns_id = mntns_id
        self.exe_paths: List[str] = []
        self.start_time = time.time()
        self.last_seen = time.time()


class FeatureExtractor:
    """
    Quản lý bộ đệm sự kiện theo cửa sổ trượt (Sliding Window 3.0s),
    hỗ trợ PID Reuse Detection, Process Lineage Aggregation
    và trích xuất vector 8 đặc trưng nhất quán.
    """
    def __init__(self, window_size_seconds: float = 3.0):
        self.window_size = window_size_seconds
        # Lưu sự kiện theo tgid: tgid -> deque[(timestamp_float, event_dict)]
        self.event_windows: Dict[int, deque] = defaultdict(deque)
        # Bảng theo dõi cây phả hệ tiến trình: pid -> ProcessNode
        self.process_tree: Dict[int, ProcessNode] = {}
        # Theo dõi UID ban đầu khi tiến trình bắt đầu hoạt động
        self.initial_uids: Dict[int, int] = {}
        # Theo dõi thời điểm xuất hiện lần đầu của tiến trình
        self.process_start_times: Dict[int, float] = {}

    def update_process(self, pid: int, ppid: int, comm: str, uid: int, euid: int, cgroup_id: int, mntns_id: int):
        now = time.time()

        # Kiểm tra hiện tượng tái sử dụng PID (PID Recycling/Reuse)
        # Nếu PID đã tồn tại nhưng có khoảng trống thời gian lớn (> window_size * 2) hoặc PPID thay đổi đột ngột
        if pid in self.process_tree:
            node = self.process_tree[pid]
            time_gap = now - node.last_seen
            if time_gap > (self.window_size * 2) or (ppid != node.ppid and ppid != 0 and node.ppid != 0):
                # Phát hiện PID reuse: Reset context để không ô nhiễm tiến trình mới
                self.event_windows[pid].clear()
                self.initial_uids[pid] = uid
                self.process_start_times[pid] = now
                self.process_tree[pid] = ProcessNode(pid, ppid, comm, uid, euid, cgroup_id, mntns_id)
                return

            node.ppid = ppid
            node.comm = comm
            node.uid = uid
            node.euid = euid
            node.last_seen = now
        else:
            self.process_tree[pid] = ProcessNode(pid, ppid, comm, uid, euid, cgroup_id, mntns_id)
            self.initial_uids[pid] = uid
            self.process_start_times[pid] = now

    def add_event(self, event: Dict[str, Any]):
        """Thêm sự kiện mới vào sliding window của tiến trình"""
        tgid = event.get("tgid", 0)
        now = time.time()

        # Nếu sự kiện là execve mới cho một tiến trình đã idle lâu, reset window
        if event.get("event_type") == 1 and tgid in self.process_tree:  # EVENT_EXECVE
            node = self.process_tree[tgid]
            if (now - node.last_seen) > self.window_size:
                self.event_windows[tgid].clear()
                self.initial_uids[tgid] = event.get("uid", 1000)

        self.event_windows[tgid].append((now, event))
        self._prune_window(tgid, now)

    def _prune_window(self, tgid: int, current_time: float):
        """Xóa các sự kiện đã vượt quá kích thước cửa sổ trượt (3s)"""
        q = self.event_windows[tgid]
        cutoff = current_time - self.window_size
        while q and q[0][0] < cutoff:
            q.popleft()
        if not q and tgid in self.event_windows:
            del self.event_windows[tgid]

    def cleanup_old_processes(self, max_idle_seconds: float = 60.0):
        """Dọn dẹp các tiến trình đã kết thúc hoặc không còn hoạt động"""
        now = time.time()
        dead_pids = [
            pid for pid, node in self.process_tree.items()
            if now - node.last_seen > max_idle_seconds
        ]
        for pid in dead_pids:
            self.process_tree.pop(pid, None)
            self.initial_uids.pop(pid, None)
            self.process_start_times.pop(pid, None)
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
        Trích xuất 8 đặc trưng chuẩn hóa:
        1. exec_count: Số lần gọi execve trong window
        2. uid_change_flag: 1 nếu chuyển từ UID != 0 sang EUID == 0
        3. is_whitelisted_bin: 1 nếu thuộc danh sách nhị phân hợp lệ, 0 nếu ngoài danh sách
        4. suspicious_path_flag: 1 nếu chạy từ /tmp, /dev/shm, /var/tmp
        5. service_parent_flag: 1 nếu cha/tổ tiên là dịch vụ mạng/web/shell
        6. sensitive_file_access: Số lần yêu cầu mở /etc/shadow, /etc/sudoers, /etc/passwd
        7. cap_check_count: Số lần kiểm tra CAP_SETUID, CAP_SYS_ADMIN, etc.
        8. priv_syscall_rate: Tốc độ gọi syscall nhạy cảm trên giây trong window
        """
        now = time.time()
        self._prune_window(tgid, now)
        events_in_win = [ev for _, ev in self.event_windows.get(tgid, [])]
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
            is_whitelisted_bin = 0  # 0: Không thuộc whitelist (cần theo dõi)

        # 4. suspicious_path_flag: 1 nếu chạy từ thư mục tạm nguy hiểm
        suspicious_path_flag = 0
        for e in events_in_win:
            fn = e.get("filename", "")
            if any(fn.startswith(p) for p in SUSPICIOUS_PATH_PREFIXES):
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

        # 8. priv_syscall_rate: Tần suất gọi syscall/sự kiện nhạy cảm trên một giây trong window
        # Nếu có >= 2 sự kiện, đo khoảng thời gian thực tế giữa sự kiện đầu và cuối trong window
        priv_events_count = len(events_in_win)
        if priv_events_count <= 1:
            priv_syscall_rate = float(priv_events_count) / self.window_size
        else:
            first_ts = self.event_windows[tgid][0][0] if self.event_windows.get(tgid) else (now - 1.0)
            duration = max(now - first_ts, 0.1)
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
