"""
agent/features.py: Trích xuất đặc trưng hành vi tiến trình từ sự kiện eBPF
Sử dụng kỹ thuật Sliding Window (3 giây) và Process Lineage
"""

import time
from collections import deque, defaultdict
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

# Danh sách nhị phân SUID hợp lệ của hệ điều hành Linux thông thường
WHITELISTED_SUID_BINS = {
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
SERVICE_PARENT_NAMES = {
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
FEATURE_NAMES = [
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
    Quản lý bộ đệm sự kiện theo cửa sổ trượt (Sliding Window 3.0s)
    và trích xuất vector 8 đặc trưng để phục vụ cả Rule Engine lẫn ML Model.
    """
    def __init__(self, window_size_seconds: float = 3.0):
        self.window_size = window_size_seconds
        # Lưu sự kiện theo tgid: tgid -> deque[(timestamp, event_dict)]
        self.event_windows: Dict[int, deque] = defaultdict(deque)
        # Bảng theo dõi cây phả hệ tiến trình: pid -> ProcessNode
        self.process_tree: Dict[int, ProcessNode] = {}
        # Theo dõi lịch sử UID để bắt việc nhảy quyền
        self.initial_uids: Dict[int, int] = {}

    def update_process(self, pid: int, ppid: int, comm: str, uid: int, euid: int, cgroup_id: int, mntns_id: int):
        if pid not in self.process_tree:
            self.process_tree[pid] = ProcessNode(pid, ppid, comm, uid, euid, cgroup_id, mntns_id)
            self.initial_uids[pid] = uid
        else:
            node = self.process_tree[pid]
            node.ppid = ppid
            node.comm = comm
            node.uid = uid
            node.euid = euid
            node.last_seen = time.time()

    def add_event(self, event: Dict[str, Any]):
        """Thêm sự kiện mới vào sliding window của tiến trình"""
        tgid = event.get("tgid", 0)
        now = time.time()
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
            self.event_windows.pop(pid, None)

    def extract_features(self, tgid: int, current_event: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Trích xuất 8 đặc trưng:
        1. exec_count: Số lần gọi execve trong window
        2. uid_change_flag: 1 nếu chuyển từ UID != 0 sang EUID == 0
        3. is_whitelisted_bin: 0 nếu thuộc danh sách hợp lệ, 1 nếu không hợp lệ
        4. suspicious_path_flag: 1 nếu chạy từ /tmp, /dev/shm, /var/tmp
        5. service_parent_flag: 1 nếu cha là dịch vụ mạng/web/shell
        6. sensitive_file_access: Số lần đọc /etc/shadow, /etc/sudoers, /etc/passwd
        7. cap_check_count: Số lần kiểm tra CAP_SETUID, CAP_SYS_ADMIN, etc.
        8. priv_syscall_rate: Tốc độ gọi syscall nhạy cảm trong window
        """
        now = time.time()
        self._prune_window(tgid, now)
        events_in_win = [ev for _, ev in self.event_windows.get(tgid, [])]
        if current_event and not any(ev is current_event for ev in events_in_win):
            events_in_win.append(current_event)

        proc = self.process_tree.get(tgid)
        parent_proc = self.process_tree.get(proc.ppid) if proc else None

        # 1. exec_count
        exec_count = sum(1 for e in events_in_win if e.get("event_type") == 1)

        # 2. uid_change_flag (Chuyển từ UID != 0 sang EUID == 0)
        uid_change_flag = 0
        init_uid = self.initial_uids.get(tgid, proc.uid if proc else 1000)
        curr_euid = proc.euid if proc else (current_event.get("euid", 1000) if current_event else 1000)
        if init_uid != 0 and curr_euid == 0:
            uid_change_flag = 1
        for e in events_in_win:
            if e.get("event_type") == 2:  # commit_creds
                if e.get("uid", 1000) != 0 and e.get("euid", 1000) == 0:
                    uid_change_flag = 1
                    break

        # 3. is_whitelisted_bin (0 nếu thuộc whitelist, 1 nếu bất thường)
        # Kiểm tra comm và filename
        comm = proc.comm if proc else (current_event.get("comm", "") if current_event else "")
        filename = ""
        for e in reversed(events_in_win):
            if e.get("filename"):
                filename = e.get("filename")
                break
        bin_name = filename.split("/")[-1] if filename else comm

        if bin_name in WHITELISTED_SUID_BINS:
            is_whitelisted_bin = 0  # Hợp lệ
        else:
            is_whitelisted_bin = 1  # Không thuộc whitelist

        # 4. suspicious_path_flag
        suspicious_path_flag = 0
        for e in events_in_win:
            fn = e.get("filename", "")
            if any(fn.startswith(p) for p in SUSPICIOUS_PATH_PREFIXES):
                suspicious_path_flag = 1
                break

        # 5. service_parent_flag (Tiến trình cha là web/network daemon hoặc service)
        service_parent_flag = 0
        if parent_proc:
            pcomm = parent_proc.comm
            if pcomm in SERVICE_PARENT_NAMES:
                service_parent_flag = 1
        elif current_event:
            # Fallback nếu cha chưa có trong cache nhưng là shell/service phổ biến
            pcomm = current_event.get("parent_comm", "")
            if pcomm in SERVICE_PARENT_NAMES:
                service_parent_flag = 1

        # 6. sensitive_file_access (/etc/shadow, /etc/sudoers, /etc/passwd)
        sensitive_file_access = sum(1 for e in events_in_win if e.get("event_type") == 4)

        # 7. cap_check_count (CAP_SETUID, CAP_SYS_ADMIN, etc.)
        cap_check_count = sum(1 for e in events_in_win if e.get("event_type") == 3)

        # 8. priv_syscall_rate (số sự kiện nhạy cảm / cửa sổ 3s)
        priv_syscall_rate = float(len(events_in_win)) / max(self.window_size, 0.1)

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
