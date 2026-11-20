"""
agent/features.py: Trích xuất đặc trưng hành vi tiến trình từ sự kiện eBPF
Sử dụng kỹ thuật Sliding Window (3 giây) theo timestamp của sự kiện,
Process Lineage, xử lý an toàn PID reuse, kế thừa fork() và ranh giới thư mục chính xác.
"""

import re
import time
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

# Bitmask flags khớp với struct event_t.flags trong ebpf/probes.c
FLAG_OPEN_WRITE = 1 << 0       # 0x01
FLAG_CRED_UID_GAIN = 1 << 1    # 0x02
FLAG_CRED_CAP_GAIN = 1 << 2    # 0x04
FLAG_CAP_USERNS = 1 << 4       # 0x10
FLAG_EXEC_FAILED = 1 << 5      # 0x20

# Thư mục hệ thống tin cậy chứa nhị phân SUID hợp lệ
TRUSTED_BIN_DIRS: Set[str] = {
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
}

# Đường dẫn daemon xác thực / hệ thống tin cậy được phép đọc /etc/shadow khi chạy dưới quyền root
TRUSTED_AUTH_DAEMON_PATHS: Set[str] = {
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/bin/unix_chkpwd",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/login",
    "/bin/login",
    "/usr/sbin/cron",
    "/usr/bin/cron",
    "/usr/sbin/crond",
    "/usr/bin/crond",
    "/usr/lib/polkit-1/polkitd",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
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
    "/run/shm",
    "/dev/mqueue",
)

# Danh sách daemon/dịch vụ mạng hoặc runtime ứng dụng thường bị khai thác (Web Shell, RCE)
# KHÔNG đưa shell tương tác (sh, bash) hay container runtime chung vào đây để tránh false positive.
SERVICE_PARENT_NAMES: Set[str] = {
    "nginx",
    "apache2",
    "httpd",
    "lighttpd",
    "node",
    "nodejs",
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

_PROC_FD_EXEC_RE = re.compile(r"^/proc/(?:self|\d+)/fd/")
_ALWAYS_SENSITIVE_OPEN_TARGETS: Set[str] = {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
}
_WRITE_ONLY_SENSITIVE_OPEN_TARGETS: Set[str] = {
    "/etc/ld.so.preload",
    "/etc/passwd",
}


def _safe_flags_int(val: Any) -> Optional[int]:
    """Chuyển đổi flags sang int một cách an toàn; trả về None nếu không có hoặc không hợp lệ."""
    if val is None or isinstance(val, bool):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _normalize_posix_path(path: str) -> str:
    """Chuẩn hóa đường dẫn POSIX và gộp nhiều dấu '/' ở đầu nếu có."""
    if not path or not isinstance(path, str):
        return ""
    clean = path.strip()
    if not clean:
        return ""
    normalized = posixpath.normpath(clean)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def is_fileless_exec_path(path: str) -> bool:
    """Kiểm tra đường dẫn thực thi fileless: (execveat:fd), /memfd:*, /proc/self/fd/*, /proc/<digits>/fd/*."""
    if not path or not isinstance(path, str):
        return False
    clean = path.strip()
    if not clean:
        return False
    if clean == "(execveat:fd)" or clean.startswith("/memfd:"):
        return True
    if clean.startswith("/"):
        normalized = _normalize_posix_path(clean)
        if normalized.startswith("/memfd:"):
            return True
        if _PROC_FD_EXEC_RE.match(normalized):
            return True
    return False


def is_suspicious_path(path: str) -> bool:
    """
    Kiểm tra xem đường dẫn có nằm trong thư mục tạm/nguy hiểm hay thực thi fileless hay không.
    So sánh chính xác theo ranh giới thư mục để tránh so khớp sai (ví dụ: /tmpfoo không thuộc /tmp).
    """
    if not path or not isinstance(path, str):
        return False
    if is_fileless_exec_path(path):
        return True
    clean = path.strip()
    normalized = _normalize_posix_path(clean) if clean.startswith("/") else clean
    for base in SUSPICIOUS_DIRECTORIES:
        if normalized == base or normalized.startswith(base + "/"):
            return True
    return False


def is_whitelisted_binary(exe_path: str, comm: str = "") -> bool:
    """
    Xác minh nhị phân SUID có thuộc danh sách hợp lệ hay không (FAIL-CLOSED):
    - Bắt buộc phải có exe_path đã xác thực (tuyệt đối không fallback sang comm khi exe_path rỗng).
    - Từ chối đường dẫn kết thúc bằng ' (deleted)' hoặc nằm trong đường dẫn nghi vấn.
    - Chuẩn hóa qua _normalize_posix_path và kiểm tra thư mục cha nằm trong TRUSTED_BIN_DIRS.
    """
    clean_path = exe_path.strip() if isinstance(exe_path, str) else ""
    if not clean_path:
        return False
    if clean_path.endswith(" (deleted)"):
        return False
    if not clean_path.startswith("/") or is_suspicious_path(clean_path):
        return False
    normalized = _normalize_posix_path(clean_path)
    if is_suspicious_path(normalized):
        return False
    parent_dir = posixpath.dirname(normalized)
    bin_name = posixpath.basename(normalized)
    return parent_dir in TRUSTED_BIN_DIRS and bin_name in WHITELISTED_SUID_BINS


def is_sensitive_open_target(filename: str, flags: Optional[int] = None) -> bool:
    """
    Kiểm tra đường dẫn mở tệp nhạy cảm sau khi chuẩn hóa POSIX:
    - Luôn True với /etc/shadow, /etc/gshadow, /etc/sudoers hoặc /etc/sudoers.d/*
    - Với /etc/ld.so.preload và /etc/passwd: CHỈ True khi cờ flags có bit FLAG_OPEN_WRITE.
    """
    if not filename or not isinstance(filename, str):
        return False
    clean = filename.strip()
    if not clean.startswith("/"):
        return False
    normalized = _normalize_posix_path(clean)
    if normalized in _ALWAYS_SENSITIVE_OPEN_TARGETS or normalized.startswith("/etc/sudoers.d/"):
        return True
    if normalized in _WRITE_ONLY_SENSITIVE_OPEN_TARGETS:
        parsed_flags = _safe_flags_int(flags)
        return parsed_flags is not None and (parsed_flags & FLAG_OPEN_WRITE) != 0
    return False


def is_service_comm(comm: str) -> bool:
    """Kiểm tra tên tiến trình có phải dịch vụ web/network/app daemon (hỗ trợ tên theo phiên bản)."""
    if not comm or not isinstance(comm, str):
        return False
    clean = comm.strip()
    if clean in SERVICE_PARENT_NAMES:
        return True
    return clean.startswith(("python3.", "python2.", "php-fpm", "php8.", "php7."))


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
    if ts_ns is not None and not isinstance(ts_ns, bool):
        try:
            val_ns = float(ts_ns)
            if np.isfinite(val_ns) and val_ns > 0:
                return val_ns / 1e9
        except (ValueError, TypeError):
            pass

    # 2. timestamp (seconds)
    ts_sec = event.get("timestamp")
    if ts_sec is not None and not isinstance(ts_sec, bool):
        try:
            val_sec = float(ts_sec)
            if np.isfinite(val_sec) and val_sec > 0:
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
        original_ppid: Optional[int] = None,
        prev_exe_path: str = "",
        ever_suspicious_path: Optional[bool] = None,
        has_service_ancestor: bool = False,
        prev_ever_suspicious_path: Optional[bool] = None,
    ):
        self.pid = pid
        self.ppid = ppid
        self.original_ppid = ppid if original_ppid is None else original_ppid
        self.comm = comm
        self.uid = uid
        self.euid = euid
        self.cgroup_id = cgroup_id
        self.mntns_id = mntns_id
        self.pidns_id = pidns_id
        self.exe_path = exe_path
        self.prev_exe_path = prev_exe_path
        init_susp = is_suspicious_path(exe_path) if ever_suspicious_path is None else bool(ever_suspicious_path)
        self.ever_suspicious_path = init_susp
        self.prev_ever_suspicious_path = (
            init_susp if prev_ever_suspicious_path is None else bool(prev_ever_suspicious_path)
        )
        self.has_service_ancestor = bool(has_service_ancestor)
        self.exited = False
        self.exit_time: Optional[float] = None
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
        exited_ttl_seconds: float = 15.0,
        max_processes: int = 50_000,
    ):
        self.window_size = float(window_size_seconds)
        self.max_idle_seconds = float(max_idle_seconds)
        self.max_window_events = max(1, int(max_window_events))
        self.exited_ttl_seconds = float(exited_ttl_seconds)
        self.max_processes = max(1, int(max_processes))
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

    def _enforce_process_cap(self):
        """Giới hạn tổng số node trong process_tree tránh tràn RAM khi xảy ra fork storm."""
        excess = len(self.process_tree) - self.max_processes
        if excess <= 0:
            return

        exited_candidates = sorted(
            ((node.last_seen, pid) for pid, node in self.process_tree.items() if node.exited),
            key=lambda item: item[0],
        )
        for _, pid in exited_candidates[:excess]:
            self.process_tree.pop(pid, None)
            self.initial_uids.pop(pid, None)
            self.event_windows.pop(pid, None)
            excess -= 1
            if excess <= 0:
                return

        if excess > 0:
            active_candidates = sorted(
                ((node.last_seen, pid) for pid, node in self.process_tree.items()),
                key=lambda item: item[0],
            )
            for _, pid in active_candidates[:excess]:
                self.process_tree.pop(pid, None)
                self.initial_uids.pop(pid, None)
                self.event_windows.pop(pid, None)

    def _create_process_node(
        self,
        pid: int,
        ppid: int,
        comm: str,
        uid: int,
        euid: int,
        cgroup_id: int,
        mntns_id: int,
        ts: float,
        pidns_id: int,
        clean_exe: str,
    ):
        parent = self.process_tree.get(ppid)
        has_svc = bool(parent and (parent.has_service_ancestor or is_service_comm(parent.comm)))
        if not clean_exe and parent is not None:
            eff_exe = parent.exe_path
            eff_susp = bool(parent.ever_suspicious_path)
        else:
            eff_exe = clean_exe
            eff_susp = is_suspicious_path(clean_exe)

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
            exe_path=eff_exe,
            original_ppid=ppid,
            prev_exe_path=eff_exe,
            ever_suspicious_path=eff_susp,
            has_service_ancestor=has_svc,
            prev_ever_suspicious_path=eff_susp,
        )
        self.initial_uids[pid] = uid
        self._enforce_process_cap()

    def _update_existing_node(
        self,
        node: ProcessNode,
        ppid: int,
        comm: str,
        uid: Optional[int],
        euid: Optional[int],
        cgroup_id: int,
        mntns_id: int,
        ts: float,
        pidns_id: int,
        clean_exe: str,
        is_main_thread: bool = True,
        event_type: Optional[int] = None,
    ):
        # Bảo toàn original_ppid và không ghi đè ppid > 1 thành 1 khi reparent về init
        if ppid > 0 and (node.ppid <= 1 or ppid != 1):
            node.ppid = ppid
        if not node.has_service_ancestor:
            parent = self.process_tree.get(node.ppid) or (
                self.process_tree.get(node.original_ppid) if node.original_ppid > 1 else None
            )
            if parent and (parent.has_service_ancestor or is_service_comm(parent.comm)):
                node.has_service_ancestor = True

        # Không để worker thread ghi đè comm của tiến trình chính trừ khi execve thành công
        if comm and (is_main_thread or event_type == 1 or not node.comm):
            node.comm = comm

        if uid is not None:
            node.uid = uid
        if euid is not None:
            node.euid = euid
        if cgroup_id:
            node.cgroup_id = cgroup_id
        if mntns_id:
            node.mntns_id = mntns_id
        if pidns_id:
            node.pidns_id = pidns_id

        if clean_exe and clean_exe != node.exe_path:
            node.prev_exe_path = node.exe_path
            node.prev_ever_suspicious_path = node.ever_suspicious_path
            node.exe_path = clean_exe
            if is_suspicious_path(clean_exe):
                node.ever_suspicious_path = True

        node.last_seen = max(node.last_seen, ts)

    def mark_process_exit(self, tgid: int, event_time: Optional[float] = None):
        """
        Ghi nhận tiến trình đã thoát (từ EVENT_PROCESS_EXIT / sched_process_exit).
        Xóa cửa sổ sự kiện của PID đã kết thúc nhưng tạm giữ ProcessNode (exited=True)
        để tiến trình con đang chạy vẫn truy vết được phả hệ tổ tiên; khi PID bị tái sử dụng
        thì update_process hoặc register_fork sẽ lập tức làm mới toàn bộ trạng thái.
        """
        ts = self._resolve_timestamp(tgid, event_time)
        self.event_windows.pop(tgid, None)
        node = self.process_tree.get(tgid)
        if node is not None:
            node.exited = True
            node.exit_time = ts if node.exit_time is None else max(node.exit_time, ts)
            node.last_seen = max(node.last_seen, ts)

    def register_fork(
        self,
        parent_tgid: int,
        child_tgid: int,
        comm: str = "",
        uid: int = 1000,
        euid: int = 1000,
        cgroup_id: int = 0,
        pidns_id: int = 0,
        mntns_id: int = 0,
        event_time: Optional[float] = None,
    ):
        """
        Ghi nhận sự kiện fork (EVENT_PROCESS_FORK = 6):
        Tạo node cho child_tgid kế thừa exe_path, ever_suspicious_path và has_service_ancestor
        từ parent_tgid để ngăn bypass bằng prctl(PR_SET_NAME) + fork().
        """
        if child_tgid <= 0:
            return
        ts = self._resolve_timestamp(child_tgid, event_time)
        parent = self.process_tree.get(parent_tgid)

        eff_comm = comm.strip() if isinstance(comm, str) and comm.strip() else (parent.comm if parent else "")
        eff_cgroup = cgroup_id or (parent.cgroup_id if parent else 0)
        eff_pidns = pidns_id or (parent.pidns_id if parent else 0)
        eff_mntns = mntns_id or (parent.mntns_id if parent else 0)

        self._create_process_node(
            pid=child_tgid,
            ppid=parent_tgid,
            comm=eff_comm,
            uid=uid,
            euid=euid,
            cgroup_id=eff_cgroup,
            mntns_id=eff_mntns,
            ts=ts,
            pidns_id=eff_pidns,
            clean_exe="",
        )

    def revert_failed_exec(self, tgid: int, event_time: Optional[float] = None):
        """
        Hoàn tác trạng thái exe_path và sự kiện sys_enter_execve đầu cơ khi sys_exit_execve(at)
        trả về lỗi (ret < 0, FLAG_EXEC_FAILED), chống đầu độc whitelist bằng execve giả mạo.
        """
        node = self.process_tree.get(tgid)
        if node is not None:
            node.exe_path = node.prev_exe_path
            node.ever_suspicious_path = node.prev_ever_suspicious_path
            if event_time is not None:
                ts = self._resolve_timestamp(tgid, event_time)
                node.last_seen = max(node.last_seen, ts)

        window = self.event_windows.get(tgid)
        if window:
            for idx in range(len(window) - 1, -1, -1):
                ev = window[idx][1]
                flags = _safe_flags_int(ev.get("flags")) or 0
                if ev.get("event_type") == 1 and (flags & FLAG_EXEC_FAILED) == 0:
                    del window[idx]
                    break
            if not window:
                self.event_windows.pop(tgid, None)

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
        is_main_thread: bool = True,
        event_type: Optional[int] = None,
    ):
        """
        Cập nhật trạng thái tiến trình một cách an toàn.
        - Nếu nhận EVENT_PROCESS_EXIT (node.exited == True) với timestamp không cũ hơn exit_time,
          khởi tạo lại toàn bộ trạng thái cho tiến trình mới (PID reuse).
        - Nếu timestamp cũ hơn exit_time (out-of-order trước khi thoát), bỏ qua để tránh hồi sinh PID đã chết.
        - Kiểm tra ngưỡng không hoạt động dài hạn (max_idle_seconds) TRƯỚC KHI cập nhật last_seen.
        """
        ts = self._resolve_timestamp(pid, event_time)
        clean_exe = exe_path.strip() if isinstance(exe_path, str) else ""

        if pid in self.process_tree:
            node = self.process_tree[pid]
            if node.exited:
                if event_time is not None and node.exit_time is not None and ts < node.exit_time:
                    return
                self._create_process_node(
                    pid=pid,
                    ppid=ppid,
                    comm=comm,
                    uid=uid,
                    euid=euid,
                    cgroup_id=cgroup_id,
                    mntns_id=mntns_id,
                    ts=ts,
                    pidns_id=pidns_id,
                    clean_exe=clean_exe,
                )
            elif (ts - node.last_seen) > self.max_idle_seconds:
                self._create_process_node(
                    pid=pid,
                    ppid=ppid,
                    comm=comm,
                    uid=uid,
                    euid=euid,
                    cgroup_id=cgroup_id,
                    mntns_id=mntns_id,
                    ts=ts,
                    pidns_id=pidns_id,
                    clean_exe=clean_exe,
                )
            else:
                self._update_existing_node(
                    node=node,
                    ppid=ppid,
                    comm=comm,
                    uid=uid,
                    euid=euid,
                    cgroup_id=cgroup_id,
                    mntns_id=mntns_id,
                    ts=ts,
                    pidns_id=pidns_id,
                    clean_exe=clean_exe,
                    is_main_thread=is_main_thread,
                    event_type=event_type,
                )
        else:
            self._create_process_node(
                pid=pid,
                ppid=ppid,
                comm=comm,
                uid=uid,
                euid=euid,
                cgroup_id=cgroup_id,
                mntns_id=mntns_id,
                ts=ts,
                pidns_id=pidns_id,
                clean_exe=clean_exe,
            )

    def add_event(self, event: Dict[str, Any]):
        """
        Thêm sự kiện mới vào sliding window của tiến trình dựa trên timestamp của sự kiện.
        Đảm bảo đồng nhất hoàn toàn giữa live eBPF và offline replay (cùng cập nhật node
        khi add_event được gọi trực tiếp).
        """
        tgid = event.get("tgid", 0) or 0
        ev_type = event.get("event_type")
        ev_flags = _safe_flags_int(event.get("flags")) or 0
        explicit_ts = extract_explicit_timestamp(event)

        if ev_type == 5:
            self.mark_process_exit(tgid, event_time=explicit_ts)
            return

        if ev_type == 6:
            self.register_fork(
                parent_tgid=int(event.get("ppid") or 0),
                child_tgid=int(tgid),
                comm=str(event.get("comm") or ""),
                uid=1000 if event.get("uid") is None else int(event["uid"]),
                euid=1000 if event.get("euid") is None else int(event["euid"]),
                cgroup_id=int(event.get("cgroup_id") or 0),
                pidns_id=int(event.get("pidns_id") or 0),
                mntns_id=int(event.get("mntns_id") or 0),
                event_time=explicit_ts,
            )
            return

        if ev_type == 1 and (ev_flags & FLAG_EXEC_FAILED) != 0:
            self.revert_failed_exec(tgid, event_time=explicit_ts)
            return

        ev_ts = self._resolve_timestamp(tgid, explicit_ts)
        raw_fn = event.get("filename", "")
        exec_path = raw_fn.strip() if ev_type == 1 and isinstance(raw_fn, str) else ""

        existing = self.process_tree.get(tgid)
        if existing is not None and existing.exited and explicit_ts is not None and existing.exit_time is not None and explicit_ts < existing.exit_time:
            return

        if existing is None or existing.exited or (ev_ts - existing.last_seen) > self.max_idle_seconds:
            self._create_process_node(
                pid=tgid,
                ppid=event.get("ppid", 0) or 0,
                comm=event.get("comm", "") or "",
                uid=1000 if event.get("uid") is None else event.get("uid"),
                euid=1000 if event.get("euid") is None else event.get("euid"),
                cgroup_id=event.get("cgroup_id", 0) or 0,
                mntns_id=event.get("mntns_id", 0) or 0,
                ts=ev_ts,
                pidns_id=event.get("pidns_id", 0) or 0,
                clean_exe=exec_path,
            )
        else:
            ev_pid = event.get("pid")
            is_main = ev_pid is None or ev_pid == 0 or ev_pid == tgid
            self._update_existing_node(
                node=existing,
                ppid=event.get("ppid", 0) or 0,
                comm=event.get("comm", "") or "",
                uid=event.get("uid"),
                euid=event.get("euid"),
                cgroup_id=event.get("cgroup_id", 0) or 0,
                mntns_id=event.get("mntns_id", 0) or 0,
                ts=ev_ts,
                pidns_id=event.get("pidns_id", 0) or 0,
                clean_exe=exec_path,
                is_main_thread=is_main,
                event_type=ev_type,
            )

        # Chèn vào cửa sổ trượt có duy trì thứ tự thời gian (không tạo bản sao list phụ)
        window = self.event_windows[tgid]
        if not window or ev_ts >= window[-1][0]:
            window.append((ev_ts, event))
        elif ev_ts < window[0][0]:
            window.insert(0, (ev_ts, event))
        else:
            lo, hi = 0, len(window)
            while lo < hi:
                mid = (lo + hi) // 2
                if ev_ts < window[mid][0]:
                    hi = mid
                else:
                    lo = mid + 1
            window.insert(lo, (ev_ts, event))

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

        lo, hi = 0, len(window)
        while lo < hi:
            mid = (lo + hi) // 2
            if window[mid][0] < cutoff:
                lo = mid + 1
            else:
                hi = mid
        if lo > 0:
            del window[:lo]

    def cleanup_old_processes(
        self,
        max_idle_seconds: Optional[float] = None,
        reference_time: Optional[float] = None,
        exited_ttl_seconds: Optional[float] = None,
    ):
        """
        Dọn dẹp các tiến trình đã kết thúc (quá exited_ttl_seconds=15s) hoặc ngưng hoạt động
        dài hạn (quá max_idle_seconds=300s), đồng thời giữ tổng số node <= max_processes.
        """
        idle_limit = self.max_idle_seconds if max_idle_seconds is None else float(max_idle_seconds)
        exit_ttl = self.exited_ttl_seconds if exited_ttl_seconds is None else float(exited_ttl_seconds)

        if reference_time is not None:
            ref_ts = float(reference_time)
        elif self.latest_event_time is not None:
            ref_ts = self.latest_event_time
        else:
            ref_ts = time.time()

        dead_pids = [
            pid for pid, node in self.process_tree.items()
            if (node.exited and (ref_ts - node.last_seen) > exit_ttl)
            or (ref_ts - node.last_seen) > idle_limit
        ]
        for pid in dead_pids:
            self.process_tree.pop(pid, None)
            self.initial_uids.pop(pid, None)
            self.event_windows.pop(pid, None)

        self._enforce_process_cap()

    def _find_service_in_lineage(self, proc: ProcessNode, max_depth: int = 5) -> int:
        """
        Truy vết cây phả hệ cha-con (Process Lineage):
        Kiểm tra xem tiến trình hiện tại có tổ tiên nào là web/network service hay không.
        """
        if proc.has_service_ancestor:
            return 1

        curr = proc
        depth = 0
        visited: Set[int] = {proc.pid}
        while curr and depth < max_depth:
            parent_pid = curr.ppid
            if parent_pid not in self.process_tree and curr.original_ppid > 1 and curr.original_ppid in self.process_tree:
                parent_pid = curr.original_ppid
            if parent_pid not in self.process_tree or parent_pid in visited:
                break
            visited.add(parent_pid)
            parent = self.process_tree[parent_pid]
            if parent.has_service_ancestor or is_service_comm(parent.comm):
                return 1
            curr = parent
            depth += 1
        return 0

    def get_process_lineage(self, tgid: int, max_depth: int = 5) -> List[str]:
        """
        Trả về danh sách tổ tiên của tiến trình theo thứ tự tổ tiên cũ nhất trước,
        ví dụ: ["nginx(3000)", "sh(6001)"].
        """
        proc = self.process_tree.get(tgid)
        if proc is None:
            return []

        ancestors: List[str] = []
        curr = proc
        depth = 0
        visited: Set[int] = {tgid}

        while curr and depth < max_depth:
            parent_pid = curr.ppid
            if parent_pid not in self.process_tree and curr.original_ppid > 1 and curr.original_ppid in self.process_tree:
                parent_pid = curr.original_ppid
            if parent_pid not in self.process_tree or parent_pid in visited:
                break
            visited.add(parent_pid)
            parent = self.process_tree[parent_pid]
            label_comm = parent.comm.strip() if parent.comm else "?"
            ancestors.append(f"{label_comm}({parent.pid})")
            curr = parent
            depth += 1

        ancestors.reverse()
        return ancestors

    def extract_features(self, tgid: int, current_event: Optional[Dict[str, Any]] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Trích xuất 8 đặc trưng chuẩn hóa dựa trên timestamp sự kiện:
        1. exec_count: Số lần gọi execve/execveat thành công trong window
        2. uid_change_flag: 1 nếu chuyển từ UID != 0 sang EUID == 0 hoặc nhảy quyền/cap qua commit_creds
        3. is_whitelisted_bin: 1 nếu thuộc danh sách SUID hợp lệ tại thư mục hệ thống tin cậy (fail-closed)
        4. suspicious_path_flag: 1 nếu chạy từ /tmp, /dev/shm, /var/tmp, /run/user, /run/shm, /dev/mqueue hoặc fileless
        5. service_parent_flag: 1 nếu cha/tổ tiên là dịch vụ mạng/web/app daemon
        6. sensitive_file_access: Số lần yêu cầu mở tệp nhạy cảm khớp chuẩn is_sensitive_open_target()
        7. cap_check_count: Số lần kiểm tra Capability nhạy cảm
        8. priv_syscall_rate: round(priv_events_count / window_size, 4)
        """
        explicit_cur_ts = extract_explicit_timestamp(current_event)
        cur_ts = self._resolve_timestamp(tgid, explicit_cur_ts)

        self._prune_window(tgid, cur_ts)
        window_entries = self.event_windows.get(tgid, [])

        include_current = False
        if current_event:
            cur_ev_type = current_event.get("event_type")
            cur_flags = _safe_flags_int(current_event.get("flags")) or 0
            is_non_window_control = cur_ev_type in (5, 6) or (cur_ev_type == 1 and (cur_flags & FLAG_EXEC_FAILED) != 0)
            if not is_non_window_control:
                if not window_entries:
                    include_current = True
                elif window_entries[-1][1] is not current_event:
                    include_current = not any(entry[1] is current_event for entry in window_entries)

        proc = self.process_tree.get(tgid)

        exec_count = 0
        sensitive_file_access = 0
        cap_check_count = 0
        has_commit_creds_jump = False
        latest_exec_filename = ""
        has_suspicious_path = bool(proc and (proc.ever_suspicious_path or is_suspicious_path(proc.exe_path)))
        priv_events_count = len(window_entries) + (1 if include_current else 0)

        def _process_single_event(e: Dict[str, Any]):
            nonlocal exec_count, sensitive_file_access, cap_check_count
            nonlocal has_commit_creds_jump, latest_exec_filename, has_suspicious_path
            ev_type = e.get("event_type")
            fn = e.get("filename") or ""
            ev_flags = _safe_flags_int(e.get("flags"))

            if ev_type == 1:
                if ev_flags is not None and (ev_flags & FLAG_EXEC_FAILED) != 0:
                    return
                exec_count += 1
                if fn:
                    latest_exec_filename = fn
                    if not has_suspicious_path and is_suspicious_path(fn):
                        has_suspicious_path = True
            elif ev_type == 2:
                e_uid = 0 if e.get("uid") is None else e.get("uid")
                e_euid = 1000 if e.get("euid") is None else e.get("euid")
                if (e_uid != 0 and e_euid == 0) or (
                    ev_flags is not None and (ev_flags & (FLAG_CRED_UID_GAIN | FLAG_CRED_CAP_GAIN)) != 0
                ):
                    has_commit_creds_jump = True
            elif ev_type == 3:
                cap_check_count += 1
            elif ev_type == 4:
                if is_sensitive_open_target(fn, ev_flags):
                    sensitive_file_access += 1

        for _, e in window_entries:
            _process_single_event(e)
        if include_current and current_event:
            _process_single_event(current_event)

        # 2. uid_change_flag (Chuyển đổi từ UID ban đầu != 0 sang EUID == 0 hoặc commit_creds gain)
        uid_change_flag = 0
        init_uid = self.initial_uids.get(tgid, proc.uid if proc else None)
        if current_event and current_event.get("euid") is not None:
            curr_euid = current_event.get("euid")
        else:
            curr_euid = proc.euid if proc else None

        if init_uid is not None and curr_euid is not None:
            if init_uid != 0 and curr_euid == 0:
                uid_change_flag = 1
        if has_commit_creds_jump:
            uid_change_flag = 1

        # 4. suspicious_path_flag (sticky trên ProcessNode qua ever_suspicious_path)
        suspicious_path_flag = 1 if has_suspicious_path else 0

        # 3. is_whitelisted_bin: Fail-closed nếu thiếu exe_path đã xác thực
        comm = proc.comm if proc else ((current_event.get("comm") or "") if current_event else "")
        exec_path = latest_exec_filename or (proc.exe_path if proc else "")
        is_whitelisted_bin = 1 if (suspicious_path_flag == 0 and is_whitelisted_binary(exec_path, comm)) else 0

        # 5. service_parent_flag: Gom hành vi cha-con & tổ tiên
        service_parent_flag = 0
        if proc:
            service_parent_flag = self._find_service_in_lineage(proc)
        elif current_event:
            pcomm = current_event.get("parent_comm") or ""
            if is_service_comm(pcomm):
                service_parent_flag = 1
            else:
                ppid_ev = current_event.get("ppid")
                if isinstance(ppid_ev, int) and ppid_ev in self.process_tree:
                    parent_node = self.process_tree[ppid_ev]
                    if (
                        parent_node.has_service_ancestor
                        or is_service_comm(parent_node.comm)
                        or self._find_service_in_lineage(parent_node)
                    ):
                        service_parent_flag = 1

        # 8. priv_syscall_rate: đồng nhất hoàn toàn giữa raw_features và feature_vector[7]
        priv_syscall_rate = round(float(priv_events_count) / self.window_size, 4) if self.window_size > 0 else 0.0

        raw_features = {
            "exec_count": exec_count,
            "uid_change_flag": uid_change_flag,
            "is_whitelisted_bin": is_whitelisted_bin,
            "suspicious_path_flag": suspicious_path_flag,
            "service_parent_flag": service_parent_flag,
            "sensitive_file_access": sensitive_file_access,
            "cap_check_count": cap_check_count,
            "priv_syscall_rate": priv_syscall_rate,
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
