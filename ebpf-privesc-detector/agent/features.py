"""
agent/features.py: Trích xuất đặc trưng hành vi tiến trình từ sự kiện eBPF
Sử dụng kỹ thuật Sliding Window (3 giây) theo timestamp của sự kiện,
Process Lineage, xử lý an toàn PID reuse và ranh giới thư mục chính xác.
"""

import time
import bisect
import posixpath
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
import numpy as np

# Mã Linux Capabilities theo <uapi/linux/capability.h>
CAP_DAC_OVERRIDE = 1
CAP_SETGID = 6
CAP_SETUID = 7
CAP_NET_ADMIN = 12
CAP_SYS_MODULE = 16
CAP_SYS_PTRACE = 19
CAP_SYS_ADMIN = 21

HIGH_RISK_CAPS: Set[int] = {
    CAP_SETGID,
    CAP_SETUID,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_ADMIN,
}

CAP_NAME_MAP: Dict[int, str] = {
    CAP_DAC_OVERRIDE: "CAP_DAC_OVERRIDE",
    CAP_SETGID: "CAP_SETGID",
    CAP_SETUID: "CAP_SETUID",
    CAP_NET_ADMIN: "CAP_NET_ADMIN",
    CAP_SYS_MODULE: "CAP_SYS_MODULE",
    CAP_SYS_PTRACE: "CAP_SYS_PTRACE",
    CAP_SYS_ADMIN: "CAP_SYS_ADMIN",
}

# Thư mục hệ thống tin cậy chứa nhị phân SUID hợp lệ
TRUSTED_BIN_DIRS: Set[str] = {
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
}

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

# Danh sách daemon/dịch vụ mạng hoặc runtime ứng dụng thường bị khai thác (Web Shell, RCE)
# Lưu ý: KHÔNG đưa shell tương tác (sh, bash) hay container runtime chung vào đây để tránh false positive;
# bộ truy vết phả hệ sẽ tự lần ngược qua sh/bash tối đa 5 cấp để tìm daemon cha như nginx/php-fpm.
SERVICE_PARENT_NAMES: Set[str] = {
    "nginx",
    "apache2",
    "httpd",
    "lighttpd",
    "node",
    "python",
    "python3",
    "php",
    "php-fpm",
    "ruby",
    "java",
    "redis-server",
    "mysqld",
    "mariadbd",
    "postgres",
    "caddy",
    "gunicorn",
    "uwsgi",
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


def _normalize_posix_path(path: str) -> str:
    """Chuẩn hóa đường dẫn POSIX và gộp nhiều dấu '/' ở đầu nếu có."""
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def is_suspicious_path(path: str) -> bool:
    """
    Kiểm tra xem đường dẫn có nằm trong thư mục tạm/nguy hiểm hay không.
    So sánh chính xác theo ranh giới thư mục để tránh so khớp sai (ví dụ: /tmpfoo không thuộc /tmp).
    """
    if not path or not isinstance(path, str):
        return False
    clean = path.strip()
    if clean.startswith("/memfd:") or clean == "(execveat:fd)":
        return True
    normalized = _normalize_posix_path(clean) if clean.startswith("/") else clean
    for base in SUSPICIOUS_DIRECTORIES:
        if normalized == base or normalized.startswith(base + "/"):
            return True
    return False


def is_whitelisted_binary(exe_path: str, comm: str = "") -> bool:
    """
    Xác minh nhị phân SUID có thuộc danh sách hợp lệ hay không:
    - Khi có exe_path (từ sys_enter_execve/execveat), bắt buộc chuẩn hóa qua posixpath.normpath
      và kiểm tra thư mục cha nằm trong TRUSTED_BIN_DIRS (/usr/bin, /bin, /usr/sbin, /sbin)
      để chặn giả mạo kiểu /tmp/sudo hay /usr/bin/../../tmp/sudo.
    - Chỉ đối chiếu comm khi chưa có thông tin exe_path (ví dụ commit_creds xuất hiện trước execve).
    """
    clean_path = exe_path.strip() if isinstance(exe_path, str) else ""
    if clean_path:
        if not clean_path.startswith("/") or is_suspicious_path(clean_path):
            return False
        normalized = _normalize_posix_path(clean_path)
        if is_suspicious_path(normalized):
            return False
        parent_dir = posixpath.dirname(normalized)
        bin_name = posixpath.basename(normalized)
        return parent_dir in TRUSTED_BIN_DIRS and bin_name in WHITELISTED_SUID_BINS

    clean_comm = comm.strip() if isinstance(comm, str) else ""
    return bool(clean_comm) and clean_comm in WHITELISTED_SUID_BINS


def extract_explicit_timestamp(event: Optional[Dict[str, Any]]) -> Optional[float]:
    """
    Trích xuất timestamp tường minh từ bản ghi sự kiện theo đơn vị giây (float).
    Trả về None nếu sự kiện không chứa bất kỳ trường thời gian hợp lệ nào.
    Ưu tiên:
      1. timestamp_ns (nanoseconds từ kernel bpf_ktime_get_ns())
      2. timestamp (số giây float)
      3. timestamp_iso (chuẩn ISO-8601 UTC)
    """
    if not event or not isinstance(event, dict):
        return None

    # 1. timestamp_ns từ nhân Linux
    ts_ns = event.get("timestamp_ns")
    if ts_ns is not None:
        try:
            val_ns = float(ts_ns)
            if val_ns > 0:
                return val_ns / 1e9
        except (ValueError, TypeError):
            pass

    # 2. timestamp (seconds)
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

    return None


def get_event_timestamp(event: Dict[str, Any], fallback_time: Optional[float] = None) -> float:
    """
    Trích xuất timestamp thực tế của sự kiện theo đơn vị giây (float),
    sử dụng fallback_time hoặc time.time() nếu bản ghi thiếu trường thời gian.
    """
    explicit_ts = extract_explicit_timestamp(event)
    if explicit_ts is not None:
        return explicit_ts
    return fallback_time if fallback_time is not None else time.time()


class ProcessNode:
    """Đại diện cho một node trong cây phả hệ tiến trình (Process Lineage)"""
    def __init__(
        self,
        pid: int,
        ppid: int,
        comm: str,
        uid: int,
        euid: int,
        cgroup_id: int,
        mntns_id: int = 0,
        start_time: float = 0.0,
        pidns_id: int = 0,
        exe_path: str = "",
    ):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.uid = uid
        self.euid = euid
        self.cgroup_id = cgroup_id
        self.mntns_id = mntns_id
        self.pidns_id = pidns_id
        self.exe_path = exe_path
        self.exited = False
        self.start_time = start_time
        self.last_seen = start_time


class FeatureExtractor:
    """
    Quản lý bộ đệm sự kiện theo cửa sổ trượt (Sliding Window 3.0s) dựa trên
    timestamp thực tế của sự kiện.
    Hỗ trợ cả trực tiếp (live eBPF) lẫn phát lại ngoại tuyến (offline telemetry replay).
    """
    def __init__(
        self,
        window_size_seconds: float = 3.0,
        max_idle_seconds: float = 300.0,
        max_window_events: int = 512,
    ):
        self.window_size = float(window_size_seconds)
        self.max_idle_seconds = float(max_idle_seconds)
        self.max_window_events = max(1, int(max_window_events))
        self.latest_event_time: Optional[float] = None
        # Lưu sự kiện theo tgid: tgid -> list[(event_timestamp_float, event_dict)] (luôn duy trì sắp xếp)
        self.event_windows: Dict[int, List[Tuple[float, Dict[str, Any]]]] = defaultdict(list)
        # Bảng theo dõi cây phả hệ tiến trình: pid -> ProcessNode
        self.process_tree: Dict[int, ProcessNode] = {}
        # Theo dõi UID ban đầu khi tiến trình bắt đầu xuất hiện
        self.initial_uids: Dict[int, int] = {}

    def _resolve_timestamp(self, tgid: int, explicit_ts: Optional[float]) -> float:
        """
        Chọn mốc thời gian đồng nhất cùng miền đồng hồ (monotonic hoặc epoch)
        khi sự kiện thử nghiệm không cung cấp trường timestamp tường minh.
        """
        if explicit_ts is not None:
            self.latest_event_time = (
                max(self.latest_event_time, explicit_ts)
                if self.latest_event_time is not None
                else explicit_ts
            )
            return explicit_ts
        if self.event_windows.get(tgid):
            return self.event_windows[tgid][-1][0]
        if tgid in self.process_tree:
            return self.process_tree[tgid].last_seen
        if self.latest_event_time is not None:
            return self.latest_event_time
        return time.time()

    def mark_process_exit(self, tgid: int, event_time: Optional[float] = None):
        """
        Ghi nhận tiến trình đã thoát (từ EVENT_PROCESS_EXIT / sched_process_exit).
        Xóa cửa sổ sự kiện của PID đã kết thúc nhưng tạm giữ ProcessNode (exited=True)
        để tiến trình con đang chạy vẫn truy vết được phả hệ tổ tiên; khi PID bị tái sử dụng
        thì update_process sẽ lập tức làm mới toàn bộ trạng thái.
        """
        ts = self._resolve_timestamp(tgid, event_time)
        self.event_windows.pop(tgid, None)
        node = self.process_tree.get(tgid)
        if node is not None:
            node.exited = True
            node.last_seen = max(node.last_seen, ts)

    def update_process(
        self,
        pid: int,
        ppid: int,
        comm: str,
        uid: int,
        euid: int,
        cgroup_id: int,
        mntns_id: int = 0,
        event_time: Optional[float] = None,
        pidns_id: int = 0,
        exe_path: Optional[str] = None,
    ):
        """
        Cập nhật trạng thái tiến trình một cách an toàn.
        Lưu ý kỹ thuật về Vòng đời & Tái sử dụng PID (PID Reuse):
        - Nếu nhận EVENT_PROCESS_EXIT (node.exited == True), lần xuất hiện tiếp theo của PID này
          chắc chắn là tiến trình mới và được khởi tạo lại toàn bộ trạng thái.
        - Không xóa trạng thái chỉ vì tiến trình tạm dừng ngắn hạn (vài giây) hay thay đổi PPID (reparenting).
        - Kiểm tra ngưỡng không hoạt động dài hạn (max_idle_seconds) TRƯỚC KHI cập nhật last_seen
          để làm mới an toàn khi thiếu sự kiện thoát tiến trình.
        """
        ts = self._resolve_timestamp(pid, event_time)
        clean_exe = exe_path.strip() if isinstance(exe_path, str) else ""

        if pid in self.process_tree:
            node = self.process_tree[pid]
            if node.exited or (ts - node.last_seen) > self.max_idle_seconds:
                # Tiến trình cũ đã thoát hoặc ngưng hoạt động vượt ngưỡng -> khởi tạo mới trạng thái PID
                self.event_windows.pop(pid, None)
                self.process_tree[pid] = ProcessNode(
                    pid,
                    ppid,
                    comm,
                    uid,
                    euid,
                    cgroup_id,
                    mntns_id=mntns_id,
                    start_time=ts,
                    pidns_id=pidns_id,
                    exe_path=clean_exe,
                )
                self.initial_uids[pid] = uid
            else:
                # Cập nhật thông tin và ghi nhận thời gian thấy mới nhất (bảo toàn initial_uids & lineage)
                node.ppid = ppid
                node.comm = comm
                node.uid = uid
                node.euid = euid
                node.cgroup_id = cgroup_id
                if mntns_id:
                    node.mntns_id = mntns_id
                if pidns_id:
                    node.pidns_id = pidns_id
                if clean_exe:
                    node.exe_path = clean_exe
                node.last_seen = max(node.last_seen, ts)
        else:
            self.process_tree[pid] = ProcessNode(
                pid,
                ppid,
                comm,
                uid,
                euid,
                cgroup_id,
                mntns_id=mntns_id,
                start_time=ts,
                pidns_id=pidns_id,
                exe_path=clean_exe,
            )
            self.initial_uids[pid] = uid

    def add_event(self, event: Dict[str, Any]):
        """
        Thêm sự kiện mới vào sliding window của tiến trình dựa trên timestamp của sự kiện.
        Tự động xử lý sự kiện thoát tiến trình, sự kiện đến muộn và giới hạn kích thước cửa sổ.
        """
        tgid = event.get("tgid", 0)
        ev_type = event.get("event_type")
        explicit_ts = extract_explicit_timestamp(event)

        if ev_type == 5:
            self.mark_process_exit(tgid, event_time=explicit_ts)
            return

        ev_ts = self._resolve_timestamp(tgid, explicit_ts)
        raw_fn = event.get("filename", "")
        exec_path = raw_fn.strip() if ev_type == 1 and isinstance(raw_fn, str) else ""

        # Cập nhật hoặc tạo tiến trình tương ứng (kiểm tra exited/idle TRƯỚC KHI cập nhật last_seen)
        existing = self.process_tree.get(tgid)
        if existing is None or existing.exited or (ev_ts - existing.last_seen) > self.max_idle_seconds:
            self.update_process(
                pid=tgid,
                ppid=event.get("ppid", 0) or 0,
                comm=event.get("comm", "") or "",
                uid=1000 if event.get("uid") is None else event.get("uid"),
                euid=1000 if event.get("euid") is None else event.get("euid"),
                cgroup_id=event.get("cgroup_id", 0) or 0,
                mntns_id=event.get("mntns_id", 0) or 0,
                event_time=ev_ts,
                pidns_id=event.get("pidns_id", 0) or 0,
                exe_path=exec_path,
            )
        else:
            existing.last_seen = max(existing.last_seen, ev_ts)
            if exec_path:
                existing.exe_path = exec_path

        # Chèn vào cửa sổ trượt có duy trì thứ tự thời gian (Sorted insertion)
        window = self.event_windows[tgid]
        if not window or ev_ts >= window[-1][0]:
            window.append((ev_ts, event))
        else:
            # Sự kiện đến trễ: chèn nhị phân đúng vị trí timestamp
            timestamps = [entry[0] for entry in window]
            idx = bisect.bisect_right(timestamps, ev_ts)
            window.insert(idx, (ev_ts, event))

        self._prune_window(tgid, window[-1][0])

        # Giới hạn kích thước cửa sổ để tránh tràn bộ nhớ khi tiến trình tạo bão syscall
        window = self.event_windows.get(tgid)
        if window and len(window) > self.max_window_events:
            del window[: len(window) - self.max_window_events]

    def _prune_window(self, tgid: int, current_event_time: Optional[float] = None, current_time: Optional[float] = None):
        """Loại bỏ các sự kiện có timestamp cũ hơn mốc hiện tại trừ đi window_size bằng binary search O(log N)."""
        ref_time = current_event_time if current_event_time is not None else current_time
        if ref_time is None:
            return

        window = self.event_windows.get(tgid)
        if not window:
            return

        cutoff = float(ref_time) - self.window_size
        if window[-1][0] < cutoff:
            del self.event_windows[tgid]
            return
        if window[0][0] >= cutoff:
            return

        # So sánh bằng 1-tuple (cutoff,) hoàn toàn an toàn vì luôn nhỏ hơn 2-tuple (ts, dict) khi ts == cutoff
        cut_idx = bisect.bisect_left(window, (cutoff,))
        if cut_idx > 0:
            del window[:cut_idx]

    def cleanup_old_processes(self, max_idle_seconds: Optional[float] = None, reference_time: Optional[float] = None):
        """
        Dọn dẹp các tiến trình đã kết thúc hoặc không còn hoạt động sau một khoảng thời gian dài an toàn (5 phút).
        Không xóa tùy tiện trong các khoảng thời gian ngắn để tránh mất dấu vết phả hệ.
        """
        idle_limit = self.max_idle_seconds if max_idle_seconds is None else float(max_idle_seconds)
        if reference_time is not None:
            ref_ts = float(reference_time)
        elif self.latest_event_time is not None:
            ref_ts = self.latest_event_time
        else:
            ref_ts = time.time()

        dead_pids = [
            pid for pid, node in self.process_tree.items()
            if (ref_ts - node.last_seen) > idle_limit
        ]
        for pid in dead_pids:
            self.process_tree.pop(pid, None)
            self.initial_uids.pop(pid, None)
            self.event_windows.pop(pid, None)

    def _find_service_in_lineage(self, proc: ProcessNode, max_depth: int = 5) -> int:
        """
        Truy vết cây phả hệ cha-con (Process Lineage):
        Kiểm tra xem tiến trình hiện tại có tổ tiên nào là web/network service hay không (có chống vòng lặp).
        """
        curr = proc
        depth = 0
        visited: Set[int] = {proc.pid}
        while curr and curr.ppid in self.process_tree and depth < max_depth:
            if curr.ppid in visited:
                break
            visited.add(curr.ppid)
            parent = self.process_tree[curr.ppid]
            if parent.comm in SERVICE_PARENT_NAMES:
                return 1
            curr = parent
            depth += 1
        return 0

    def extract_features(self, tgid: int, current_event: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Trích xuất 8 đặc trưng chuẩn hóa dựa trên timestamp sự kiện:
        1. exec_count: Số lần gọi execve/execveat trong window
        2. uid_change_flag: 1 nếu chuyển từ UID != 0 sang EUID == 0
        3. is_whitelisted_bin: 1 nếu thuộc danh sách SUID hợp lệ tại thư mục hệ thống tin cậy, 0 nếu ngoài danh sách
        4. suspicious_path_flag: 1 nếu chạy từ /tmp, /dev/shm, /var/tmp, /run/user, memfd (ranh giới chính xác)
        5. service_parent_flag: 1 nếu cha/tổ tiên là dịch vụ mạng/web/app daemon
        6. sensitive_file_access: Số lần yêu cầu mở /etc/shadow, /etc/sudoers, /etc/passwd, /etc/gshadow, /etc/ld.so.preload
        7. cap_check_count: Số lần kiểm tra Capability nhạy cảm
        8. priv_syscall_rate: Tần suất gọi sự kiện nhạy cảm trên giây trong window
        """
        # Xác định mốc thời gian chuẩn từ sự kiện hiện tại hoặc sự kiện mới nhất trong cửa sổ (cùng miền đồng hồ)
        explicit_cur_ts = extract_explicit_timestamp(current_event)
        cur_ts = self._resolve_timestamp(tgid, explicit_cur_ts)

        self._prune_window(tgid, cur_ts)
        window_entries = self.event_windows.get(tgid, [])
        events_in_win = [entry[1] for entry in window_entries]

        if current_event and not any(ev is current_event for ev in events_in_win):
            events_in_win.append(current_event)

        proc = self.process_tree.get(tgid)

        # Một vòng duyệt duy nhất O(N) để tính các bộ đếm và cờ hành vi
        exec_count = 0
        sensitive_file_access = 0
        cap_check_count = 0
        has_commit_creds_jump = False
        latest_exec_filename = ""
        has_suspicious_path = bool(proc and is_suspicious_path(proc.exe_path))

        for e in events_in_win:
            ev_type = e.get("event_type")
            fn = e.get("filename") or ""
            if ev_type == 1:
                exec_count += 1
                if fn:
                    latest_exec_filename = fn
            elif ev_type == 2:
                e_uid = 0 if e.get("uid") is None else e.get("uid")
                e_euid = 1000 if e.get("euid") is None else e.get("euid")
                if e_uid != 0 and e_euid == 0:
                    has_commit_creds_jump = True
            elif ev_type == 3:
                cap_check_count += 1
            elif ev_type == 4:
                sensitive_file_access += 1

            if not has_suspicious_path and fn and is_suspicious_path(fn):
                has_suspicious_path = True

        # 2. uid_change_flag (Chuyển đổi từ UID/EUID ban đầu != 0 sang EUID == 0)
        uid_change_flag = 0
        init_uid = self.initial_uids.get(tgid, proc.uid if proc else None)
        curr_euid = proc.euid if proc else (current_event.get("euid") if current_event else None)

        if init_uid is not None and curr_euid is not None:
            if init_uid != 0 and curr_euid == 0:
                uid_change_flag = 1
        if has_commit_creds_jump:
            uid_change_flag = 1

        # 4. suspicious_path_flag: 1 nếu thực thi từ thư mục tạm nguy hiểm (kể cả khi execve đã trôi qua cửa sổ 3s)
        suspicious_path_flag = 1 if has_suspicious_path else 0

        # 3. is_whitelisted_bin: Chỉ tin cậy nhị phân SUID trong /usr/bin, /bin, /usr/sbin, /sbin
        # Tuyệt đối KHÔNG lấy đường dẫn file dữ liệu của EVENT_OPENAT (ví dụ /etc/sudoers) làm tên binary!
        comm = proc.comm if proc else ((current_event.get("comm") or "") if current_event else "")
        exec_path = latest_exec_filename or (proc.exe_path if proc else "")
        is_whitelisted_bin = 1 if (suspicious_path_flag == 0 and is_whitelisted_binary(exec_path, comm)) else 0

        # 5. service_parent_flag: Gom hành vi cha-con & tổ tiên
        service_parent_flag = 0
        if proc:
            service_parent_flag = self._find_service_in_lineage(proc)
        elif current_event:
            pcomm = current_event.get("parent_comm") or ""
            if pcomm in SERVICE_PARENT_NAMES:
                service_parent_flag = 1

        # 8. priv_syscall_rate: Tần suất gọi sự kiện nhạy cảm trên giây theo timestamp thực tế
        priv_events_count = len(events_in_win)
        if priv_events_count <= 1:
            priv_syscall_rate = float(priv_events_count) / self.window_size
        else:
            first_ts = window_entries[0][0] if window_entries else (cur_ts - 1.0)
            last_ts = max(window_entries[-1][0], cur_ts) if window_entries else cur_ts
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
