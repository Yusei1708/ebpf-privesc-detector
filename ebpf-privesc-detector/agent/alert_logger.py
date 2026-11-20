"""
agent/alert_logger.py: Ghi nhận cảnh báo có cấu trúc dạng JSONL an toàn
Tuân thủ:
  - Timestamp ISO-8601 UTC kết hợp nanoseconds kernel
  - Không rò rỉ dữ liệu bí mật
  - Xử lý lỗi I/O an toàn, không làm gián đoạn luồng eBPF
  - Đảm bảo quyền file an toàn (0600)
"""

import os
import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

EVENT_NAME_MAP = {
    1: "EXECVE",
    2: "COMMIT_CREDS",
    3: "CAP_CHECK",
    4: "OPENAT",
    5: "PROCESS_EXIT",
}


def sanitize_string(val: Any) -> str:
    """Loại bỏ ký tự điều khiển lạ hoặc null byte để tránh log injection"""
    if val is None:
        return ""
    s = str(val).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return s[:256]


def _safe_int(val: Any, default: int = 0) -> int:
    """Chuyển đổi an toàn giá trị sang int kể cả khi None hoặc chuỗi rỗng."""
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    """Chuyển đổi an toàn giá trị sang float kể cả khi None hoặc kiểu NumPy."""
    if val is None or isinstance(val, bool):
        return default
    try:
        return float(val)
    except (TypeError, ValueError):
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
    Xác định sự kiện phát sinh từ Container hoặc Namespace cô lập (PID NS / Mount NS).
    So sánh namespace inode của sự kiện với namespace gốc của máy Host thay vì chỉ kiểm tra != 0.
    """
    if not isinstance(event, dict):
        return False
    if "is_container" in event and isinstance(event["is_container"], bool):
        return event["is_container"]

    pidns_id = _safe_int(event.get("pidns_id"), 0)
    if pidns_id > 0:
        ref_pidns = host_pidns_id if host_pidns_id is not None else get_host_pidns_id()
        if ref_pidns is not None and ref_pidns > 0:
            return pidns_id != ref_pidns

    mntns_id = _safe_int(event.get("mntns_id"), 0)
    if mntns_id > 0:
        ref_mntns = host_mntns_id if host_mntns_id is not None else get_host_mntns_id()
        if ref_mntns is not None and ref_mntns > 0:
            return mntns_id != ref_mntns

    return False


class AlertLogger:
    """
    Quản lý ghi log cảnh báo JSONL an toàn
    """
    def __init__(
        self,
        log_path: Optional[str] = None,
        host_mntns_id: Optional[int] = None,
        host_pidns_id: Optional[int] = None,
    ):
        self.log_path = Path(log_path) if log_path else Path("alerts.jsonl")
        self.host_mntns_id = host_mntns_id if host_mntns_id is not None else get_host_mntns_id()
        self.host_pidns_id = host_pidns_id if host_pidns_id is not None else get_host_pidns_id()
        self._ensure_secure_file()

    def _ensure_secure_file(self):
        """Khởi tạo thư mục và phân quyền 0600 (owner read/write) an toàn cho file log"""
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not self.log_path.exists():
                self.log_path.touch(mode=0o600, exist_ok=True)
            else:
                # Cập nhật quyền hạn chặt chẽ nếu file đã tồn tại
                try:
                    os.chmod(self.log_path, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
        except Exception as e:
            print(f"[!] Cảnh báo không thể thiết lập quyền file log: {e}")

    def log_alert(self, alert_data: Dict[str, Any]) -> bool:
        """
        Ghi một bản ghi cảnh báo JSONL
        Trả về True nếu ghi thành công, False nếu gặp sự cố I/O hoặc dữ liệu lỗi (không làm sập agent)
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
            e_type = _safe_int(event.get("event_type"), 0)
            rule_name = alert_data.get("rule_name")

            triggered_rule = None
            if match is not None or (isinstance(rule_name, str) and rule_name and rule_name != "N/A"):
                triggered_rule = {
                    "rule_id": match.rule_id if match else None,
                    "name": match.name if match else rule_name,
                    "severity": match.severity if match else (alert_data.get("rule_sev") or "INFO"),
                    "mitre_id": match.mitre_id if match else None,
                }

            matched_rules = alert_data.get("matched_rules")
            if isinstance(matched_rules, list):
                rule_ids = [str(r) for r in matched_rules]
            elif match is not None:
                rule_ids = [match.rule_id]
            else:
                rule_ids = []

            serialized_features: Dict[str, Any] = {}
            for k, v in raw_feat.items():
                key = str(k)
                if v is None:
                    serialized_features[key] = 0
                elif isinstance(v, bool):
                    serialized_features[key] = int(v)
                elif isinstance(v, int) or (hasattr(v, "dtype") and "int" in str(v.dtype)):
                    serialized_features[key] = int(v)
                else:
                    try:
                        fval = float(v)
                        serialized_features[key] = round(fval, 4)
                    except (TypeError, ValueError):
                        serialized_features[key] = sanitize_string(v)

            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "timestamp_ns": _safe_int(event.get("timestamp_ns"), 0),
                "event_type": e_type,
                "event_name": EVENT_NAME_MAP.get(e_type, "UNKNOWN"),
                "pid": _safe_int(event.get("pid"), 0),
                "tgid": _safe_int(event.get("tgid"), 0),
                "ppid": _safe_int(event.get("ppid"), 0),
                "uid": _safe_int(event.get("uid"), 1000),
                "euid": _safe_int(event.get("euid"), 1000),
                "comm": sanitize_string(event.get("comm", "")),
                "path": sanitize_string(event.get("filename", "")),
                "cgroup_id": _safe_int(event.get("cgroup_id"), 0),
                "pidns_id": _safe_int(event.get("pidns_id"), 0),
                "mntns_id": _safe_int(event.get("mntns_id"), 0),
                "is_container": is_container,
                "threat_score": _safe_int(alert_data.get("threat_score"), 0),
                "rf_score": round(_safe_float(alert_data.get("rf_prob"), 0.0), 4),
                "anomaly_score": round(_safe_float(alert_data.get("iso_score"), 0.0), 4),
                "triggered_rule": triggered_rule,
                "matched_rules": rule_ids,
                "features": serialized_features,
            }

            line = json.dumps(record, ensure_ascii=False)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            return True
        except IOError as e:
            # Bắt lỗi I/O để đảm bảo luồng thu thập kernel telemetry không bị gián đoạn
            print(f"[!] Lỗi I/O khi ghi log cảnh báo: {e}")
            return False
        except Exception as e:
            print(f"[!] Lỗi serialization cảnh báo: {e}")
            return False
