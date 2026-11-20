"""
agent/alert_logger.py: Ghi nhận cảnh báo có cấu trúc dạng JSONL an toàn
Tuân thủ:
  - Timestamp ISO-8601 UTC kết hợp nanoseconds kernel
  - Khử ký tự điều khiển / ANSI escape để chống log injection và từ chối NaN/Inf
  - Xử lý lỗi I/O an toàn ra stderr, không làm gián đoạn luồng eBPF
  - Đảm bảo quyền file an toàn (0600), chống symlink (O_NOFOLLOW) và xoay vòng log theo kích thước
"""

import os
import re
import sys
import json
import math
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

try:
    from agent.features import CAP_NAME_MAP
except ImportError:
    CAP_NAME_MAP = {
        1: "CAP_DAC_OVERRIDE",
        6: "CAP_SETGID",
        7: "CAP_SETUID",
        12: "CAP_NET_ADMIN",
        16: "CAP_SYS_MODULE",
        19: "CAP_SYS_PTRACE",
        21: "CAP_SYS_ADMIN",
    }

EVENT_NAME_MAP = {
    1: "EXECVE",
    2: "COMMIT_CREDS",
    3: "CAP_CHECK",
    4: "OPENAT",
    5: "PROCESS_EXIT",
    6: "PROCESS_FORK",
}

_ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_string(val: Any, max_len: int = 256) -> str:
    """Loại bỏ ANSI escape, ký tự điều khiển và null byte để chống log/terminal injection."""
    if val is None:
        return ""
    s = str(val)
    s = _ANSI_ESCAPE_RE.sub("", s)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _CONTROL_CHARS_RE.sub("", s).strip()
    return s[:max_len]


def _safe_int(val: Any, default: Optional[int] = 0) -> Optional[int]:
    """Chuyển đổi an toàn giá trị sang int kể cả khi None, bool hoặc chuỗi rỗng."""
    if val is None or isinstance(val, bool) or type(val).__name__ == "bool_":
        return default
    if isinstance(val, float) and not math.isfinite(val):
        return default
    try:
        return int(val)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Chuyển đổi an toàn giá trị sang float hữu hạn (từ chối NaN/Inf/bool)."""
    if val is None or isinstance(val, bool) or type(val).__name__ == "bool_":
        return default
    try:
        fval = float(val)
        return fval if math.isfinite(fval) else default
    except (TypeError, ValueError, OverflowError):
        return default


def get_host_pidns_id() -> Optional[int]:
    """
    Lấy inode number của PID Namespace gốc trên máy Host.
    Ưu tiên đọc /proc/1/ns/pid (khi chạy với quyền root), fallback sang /proc/self/ns/pid
    (khi chạy kiểm thử user-space không đặc quyền trên máy Host).
    """
    for ns_path in ("/proc/1/ns/pid", "/proc/self/ns/pid"):
        try:
            ino = os.stat(ns_path).st_ino
            if ino > 0:
                return int(ino)
        except OSError:
            continue
    return None


def get_host_mntns_id() -> Optional[int]:
    """
    Lấy inode number của Mount Namespace gốc trên máy Host (tương thích dữ liệu cũ).
    Ưu tiên đọc /proc/1/ns/mnt (khi chạy với quyền root), fallback sang /proc/self/ns/mnt
    (khi chạy kiểm thử user-space không đặc quyền trên máy Host).
    """
    for ns_path in ("/proc/1/ns/mnt", "/proc/self/ns/mnt"):
        try:
            ino = os.stat(ns_path).st_ino
            if ino > 0:
                return int(ino)
        except OSError:
            continue
    return None


def is_container_event(
    event: Dict[str, Any],
    host_mntns_id: Optional[int] = None,
    host_pidns_id: Optional[int] = None,
) -> bool:
    """
    Xác định sự kiện phát sinh từ Container hoặc Namespace cô lập.
    Trả về True nếu EITHER pidns_id OR mntns_id khác với namespace gốc của Host
    (hỗ trợ nhận diện chính xác cả container chạy --pid=host).
    """
    if not isinstance(event, dict):
        return False
    if "is_container" in event and isinstance(event["is_container"], bool):
        return event["is_container"]

    pidns_id = _safe_int(event.get("pidns_id"), 0) or 0
    if pidns_id > 0:
        ref_pidns = host_pidns_id if host_pidns_id is not None else get_host_pidns_id()
        if ref_pidns is not None and ref_pidns > 0 and pidns_id != ref_pidns:
            return True

    mntns_id = _safe_int(event.get("mntns_id"), 0) or 0
    if mntns_id > 0:
        ref_mntns = host_mntns_id if host_mntns_id is not None else get_host_mntns_id()
        if ref_mntns is not None and ref_mntns > 0 and mntns_id != ref_mntns:
            return True

    return False


class AlertLogger:
    """
    Quản lý ghi log cảnh báo JSONL an toàn, chống symlink và hỗ trợ xoay vòng theo kích thước.
    """
    def __init__(
        self,
        log_path: Optional[str] = None,
        host_mntns_id: Optional[int] = None,
        host_pidns_id: Optional[int] = None,
        max_bytes: int = 50 * 1024 * 1024,
        backup_count: int = 5,
    ):
        self.log_path = Path(log_path) if log_path else Path("alerts.jsonl")
        self.host_mntns_id = host_mntns_id if host_mntns_id is not None else get_host_mntns_id()
        self.host_pidns_id = host_pidns_id if host_pidns_id is not None else get_host_pidns_id()
        self.max_bytes = max(0, int(max_bytes))
        self.backup_count = max(0, int(backup_count))
        self._lock = threading.Lock()
        self._ensure_secure_file()

    def _open_secure_fd(self) -> int:
        """Mở file an toàn không theo dõi symlink với quyền 0600."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(self.log_path), flags, stat.S_IRUSR | stat.S_IWUSR)
        try:
            os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return fd

    def _ensure_secure_file(self) -> None:
        """Khởi tạo thư mục và phân quyền 0600 (owner read/write) an toàn không qua symlink."""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(self.log_path) and os.path.islink(self.log_path):
                print(
                    f"[!] Cảnh báo bảo mật: từ chối sử dụng symlink làm file log ({self.log_path})",
                    file=sys.stderr,
                )
                return
            fd = self._open_secure_fd()
            os.close(fd)
        except Exception as e:
            print(f"[!] Cảnh báo không thể thiết lập quyền file log: {e}", file=sys.stderr)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        """Xoay vòng file log khi đạt ngưỡng max_bytes (gọi bên trong self._lock)."""
        if self.max_bytes <= 0:
            return
        try:
            if not os.path.lexists(self.log_path) or os.path.islink(self.log_path):
                return
            st = os.lstat(self.log_path)
            if not stat.S_ISREG(st.st_mode):
                return
            if st.st_size == 0 or (st.st_size + incoming_bytes) <= self.max_bytes:
                return

            if self.backup_count > 0:
                for idx in range(self.backup_count - 1, 0, -1):
                    src = Path(f"{self.log_path}.{idx}")
                    dst = Path(f"{self.log_path}.{idx + 1}")
                    if os.path.lexists(src) and not os.path.islink(src):
                        os.replace(src, dst)
                first_backup = Path(f"{self.log_path}.1")
                os.replace(self.log_path, first_backup)
            else:
                os.unlink(self.log_path)
        except OSError as e:
            print(f"[!] Cảnh báo lỗi xoay vòng file log: {e}", file=sys.stderr)

    def log_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Ghi một bản ghi cảnh báo JSONL an toàn.
        Trả về True nếu ghi thành công, False nếu gặp sự cố I/O hoặc dữ liệu lỗi.
        """
        if not isinstance(alert_data, dict):
            return False

        try:
            raw_event = alert_data.get("event")
            event = raw_event if isinstance(raw_event, dict) else {}
            raw_feat_obj = alert_data.get("raw_features")
            raw_feat = raw_feat_obj if isinstance(raw_feat_obj, dict) else {}
            match = alert_data.get("match")

            is_container = is_container_event(
                event,
                host_mntns_id=self.host_mntns_id,
                host_pidns_id=self.host_pidns_id,
            )
            e_type = _safe_int(event.get("event_type"), 0) or 0
            rule_name = alert_data.get("rule_name")
            highest_severity = sanitize_string(
                alert_data.get("highest_severity")
                or alert_data.get("rule_sev")
                or (match.severity if match else "INFO")
            )

            triggered_rule = None
            if match is not None or (isinstance(rule_name, str) and rule_name and rule_name != "N/A"):
                rule_desc = match.description if match else alert_data.get("rule_description")
                rule_rat = match.rationale if match else alert_data.get("rule_rationale")
                triggered_rule = {
                    "rule_id": match.rule_id if match else None,
                    "name": match.name if match else sanitize_string(rule_name),
                    "severity": match.severity if match else sanitize_string(alert_data.get("rule_sev") or "INFO"),
                    "mitre_id": match.mitre_id if match else None,
                    "description": sanitize_string(rule_desc, max_len=512),
                    "rationale": sanitize_string(rule_rat, max_len=512),
                }

            matched_rules = alert_data.get("matched_rules")
            if isinstance(matched_rules, list):
                rule_ids = [sanitize_string(r) for r in matched_rules]
            elif match is not None:
                rule_ids = [match.rule_id]
            else:
                rule_ids = []

            raw_lineage = alert_data.get("lineage")
            lineage: List[str] = (
                [sanitize_string(item) for item in raw_lineage if sanitize_string(item)]
                if isinstance(raw_lineage, list)
                else []
            )

            cap_val: Optional[int] = None
            cap_name: Optional[str] = None
            if e_type == 3:
                cap_val = _safe_int(event.get("cap"), default=None)
                if cap_val is not None:
                    cap_name = CAP_NAME_MAP.get(cap_val, f"CAP_{cap_val}")

            serialized_features: Dict[str, Any] = {}
            for k, v in raw_feat.items():
                key = str(k)
                if v is None:
                    serialized_features[key] = 0
                elif isinstance(v, bool) or type(v).__name__ == "bool_":
                    serialized_features[key] = int(v)
                elif isinstance(v, int) or (hasattr(v, "dtype") and "int" in str(v.dtype)):
                    serialized_features[key] = int(v)
                else:
                    try:
                        fval = float(v)
                        if math.isfinite(fval):
                            serialized_features[key] = round(fval, 4)
                        else:
                            serialized_features[key] = 0.0
                    except (TypeError, ValueError, OverflowError):
                        serialized_features[key] = sanitize_string(v)

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "timestamp_ns": _safe_int(event.get("timestamp_ns"), 0),
                "event_type": e_type,
                "event_name": EVENT_NAME_MAP.get(e_type, "UNKNOWN"),
                "pid": _safe_int(event.get("pid"), 0),
                "tgid": _safe_int(event.get("tgid"), 0),
                "ppid": _safe_int(event.get("ppid"), 0),
                "uid": _safe_int(event.get("uid"), default=None),
                "euid": _safe_int(event.get("euid"), default=None),
                "cap": cap_val,
                "cap_name": cap_name,
                "flags": _safe_int(event.get("flags"), 0),
                "comm": sanitize_string(event.get("comm", "")),
                "path": sanitize_string(event.get("filename", "")),
                "cgroup_id": _safe_int(event.get("cgroup_id"), 0),
                "pidns_id": _safe_int(event.get("pidns_id"), 0),
                "mntns_id": _safe_int(event.get("mntns_id"), 0),
                "is_container": is_container,
                "lineage": lineage,
                "threat_score": _safe_int(alert_data.get("threat_score"), 0),
                "highest_severity": highest_severity,
                "rf_score": round(_safe_float(alert_data.get("rf_prob"), 0.0), 4),
                "anomaly_score": round(_safe_float(alert_data.get("iso_score"), 0.0), 4),
                "is_ml_anomaly": bool(alert_data.get("is_ml_anomaly", False)),
                "triggered_rule": triggered_rule,
                "matched_rules": rule_ids,
                "features": serialized_features,
            }

            line = json.dumps(record, ensure_ascii=False, allow_nan=False)
            payload = (line + "\n").encode("utf-8")

            with self._lock:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self._rotate_if_needed(len(payload))
                fd = self._open_secure_fd()
                try:
                    view = memoryview(payload)
                    written = 0
                    while written < len(payload):
                        n = os.write(fd, view[written:])
                        if n <= 0:
                            raise OSError("os.write returned 0 bytes")
                        written += n
                finally:
                    os.close(fd)
            return True
        except OSError as e:
            print(f"[!] Lỗi I/O khi ghi log cảnh báo: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"[!] Lỗi serialization cảnh báo: {e}", file=sys.stderr)
            return False
