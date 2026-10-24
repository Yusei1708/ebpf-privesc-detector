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
}


def sanitize_string(val: Any) -> str:
    """Loại bỏ ký tự điều khiển lạ hoặc null byte để tránh log injection"""
    if val is None:
        return ""
    s = str(val).replace("\x00", "").replace("\r", " ").replace("\n", " ").strip()
    return s[:256]


class AlertLogger:
    """
    Quản lý ghi log cảnh báo JSONL an toàn
    """
    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path) if log_path else Path("alerts.jsonl")
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
        Trả về True nếu ghi thành công, False nếu gặp sự cố I/O (không ném ngoại lệ làm sập agent)
        """
        event = alert_data.get("event", {})
        raw_feat = alert_data.get("raw_features", {})
        match = alert_data.get("match")

        is_container = bool(event.get("cgroup_id", 0) != 0 and event.get("mntns_id", 0) != 0)
        e_type = event.get("event_type", 0)

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "timestamp_ns": int(event.get("timestamp_ns", 0)),
            "event_type": int(e_type),
            "event_name": EVENT_NAME_MAP.get(e_type, "UNKNOWN"),
            "pid": int(event.get("pid", 0)),
            "tgid": int(event.get("tgid", 0)),
            "ppid": int(event.get("ppid", 0)),
            "uid": int(event.get("uid", 1000)),
            "euid": int(event.get("euid", 1000)),
            "comm": sanitize_string(event.get("comm", "")),
            "path": sanitize_string(event.get("filename", "")),
            "cgroup_id": int(event.get("cgroup_id", 0)),
            "mntns_id": int(event.get("mntns_id", 0)),
            "is_container": is_container,
            "threat_score": int(alert_data.get("threat_score", 0)),
            "rf_score": round(float(alert_data.get("rf_prob", 0.0)), 4),
            "anomaly_score": round(float(alert_data.get("iso_score", 0.0)), 4),
            "triggered_rule": {
                "rule_id": match.rule_id if match else None,
                "name": match.name if match else alert_data.get("rule_name", "N/A"),
                "severity": match.severity if match else alert_data.get("rule_sev", "INFO"),
                "mitre_id": match.mitre_id if match else None,
            } if (match or alert_data.get("rule_name") != "N/A") else None,
            "features": {
                k: round(v, 2) if isinstance(v, float) else int(v)
                for k, v in raw_feat.items()
            },
        }

        try:
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
