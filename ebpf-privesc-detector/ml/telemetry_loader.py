"""
ml/telemetry_loader.py: Đọc, xác thực và tiền xử lý dữ liệu telemetry thực tế từ file CSV hoặc JSONL
Thực hiện kiểm tra nghiêm ngặt theo schema: trường bắt buộc, kiểu dữ liệu, độ dài chuỗi, nhãn (0/1),
session_id, flags và tất cả trường timestamp. Hỗ trợ trích xuất đặc trưng ổn định theo từng phiên.
"""

import csv
import sys
import json
import math
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional, Iterator, Callable
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import (
    FEATURE_NAMES,
    FLAG_EXEC_FAILED,
    FeatureExtractor,
    extract_explicit_timestamp,
)

SCHEMA_PATH = PROJECT_ROOT / "ml" / "data" / "telemetry_schema.json"

EVENT_SORT_RANK: Dict[int, int] = {
    6: 0,  # PROCESS_FORK đầu tiên để khởi tạo quan hệ cha-con trước exec/open
    1: 1,  # EXECVE
    2: 2,  # COMMIT_CREDS
    3: 3,  # CAP_CHECK
    4: 4,  # OPENAT
    5: 5,  # PROCESS_EXIT cuối cùng khi trùng timestamp
}


class TelemetryValidationError(ValueError):
    """Ngoại lệ khi bản ghi telemetry không hợp lệ theo schema chuẩn."""
    def __init__(self, line_number: int, field_name: str, message: str, raw_data: Optional[Dict[str, Any]] = None):
        super().__init__(f"[Dòng {line_number}] Lỗi trường '{field_name}': {message}")
        self.line_number = line_number
        self.field_name = field_name
        self.field = field_name
        self.message = message
        self.raw_data = raw_data


def _parse_strict_int(val: Any) -> int:
    """Chuyển đổi nghiêm ngặt sang số nguyên; từ chối bool/np.bool_ và số thực không nguyên."""
    if isinstance(val, (bool, np.bool_)):
        raise ValueError("Giá trị boolean không hợp lệ cho trường số nguyên")
    if isinstance(val, (int, np.integer)):
        return int(val)
    if isinstance(val, (float, np.floating)):
        fval = float(val)
        if not np.isfinite(fval) or not fval.is_integer():
            raise ValueError(f"Giá trị '{val}' không phải số nguyên hợp lệ")
        return int(fval)
    if isinstance(val, str):
        s = val.strip()
        if not s:
            raise ValueError("Chuỗi rỗng")
        return int(s)
    raise ValueError(f"Kiểu dữ liệu không hợp lệ: {type(val).__name__}")


class TelemetryLoader:
    """
    Nạp và xác thực dữ liệu telemetry từ file CSV hoặc JSONL.
    Hỗ trợ chế độ có nhãn bắt buộc (huấn luyện) hoặc không nhãn (offline replay).
    """
    REQUIRED_FIELDS = (
        "event_type",
        "tgid",
        "pid",
        "uid",
        "euid",
        "comm",
        "label",
        "session_id",
    )

    REQUIRED_BASE_FIELDS = (
        "event_type",
        "tgid",
        "pid",
        "uid",
        "euid",
        "comm",
        "session_id",
    )

    OPTIONAL_NONNEG_INT_FIELDS = (
        "ppid",
        "cap",
        "flags",
        "cgroup_id",
        "mntns_id",
        "pidns_id",
    )

    def __init__(self, schema_file: Optional[Path] = None, require_label: bool = True):
        self.schema_file = schema_file or SCHEMA_PATH
        self.require_label = bool(require_label)
        self.schema = self._load_schema()
        props = self.schema.get("properties", {}) if isinstance(self.schema, dict) else {}
        self.comm_max_len = int(props.get("comm", {}).get("maxLength", 16) or 16)
        self.filename_max_len = int(props.get("filename", {}).get("maxLength", 256) or 256)

    def _load_schema(self) -> Dict[str, Any]:
        if self.schema_file.exists():
            try:
                with open(self.schema_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            except Exception:
                pass
        return {}

    def validate_record(self, record: Dict[str, Any], line_no: int) -> Dict[str, Any]:
        """
        Kiểm tra tính hợp lệ của bản ghi telemetry (không làm biến đổi dict đầu vào):
        - Kiểm tra các trường bắt buộc và từ chối alert log
        - Kiểm tra kiểu dữ liệu, độ dài chuỗi theo telemetry_schema.json
        - Kiểm tra nghiêm ngặt mọi trường timestamp có mặt theo thứ tự timestamp_ns -> timestamp -> timestamp_iso
        """
        if not isinstance(record, dict):
            raise TelemetryValidationError(
                line_no,
                "root",
                f"Bản ghi phải là đối tượng JSON/Dict, nhận được {type(record).__name__}",
            )

        if "threat_score" in record or "matched_rules" in record or "triggered_rule" in record:
            raise TelemetryValidationError(
                line_no,
                "format",
                "File này có cấu trúc Alert Log (chứa 'threat_score', 'triggered_rule' hoặc 'matched_rules'), không phải Telemetry thô. "
                "Alert log không thể dùng trực tiếp để huấn luyện mô hình. Vui lòng thu thập telemetry theo ml/data/telemetry_schema.json.",
                record,
            )

        validated = dict(record)
        required_fields = self.REQUIRED_FIELDS if self.require_label else self.REQUIRED_BASE_FIELDS

        # 1. Kiểm tra sự tồn tại của các trường bắt buộc
        for req in required_fields:
            if req not in validated or validated[req] is None or (isinstance(validated[req], str) and not validated[req].strip()):
                raise TelemetryValidationError(
                    line_no,
                    req,
                    f"Trường bắt buộc '{req}' bị thiếu hoặc có giá trị rỗng",
                    record,
                )

        # 2. Kiểm tra event_type (1..6)
        try:
            ev_type = _parse_strict_int(validated["event_type"])
            if ev_type not in (1, 2, 3, 4, 5, 6):
                raise TelemetryValidationError(
                    line_no,
                    "event_type",
                    f"Giá trị event_type không hợp lệ ({ev_type}). Phải là 1 (execve/execveat), 2 (commit_creds), 3 (cap_capable), 4 (openat), 5 (process_exit), hoặc 6 (process_fork)",
                    record,
                )
            validated["event_type"] = ev_type
        except TelemetryValidationError:
            raise
        except (ValueError, TypeError):
            raise TelemetryValidationError(line_no, "event_type", "event_type phải là số nguyên", record)

        # 3. Kiểm tra các định danh tiến trình và người dùng (TGID, PID, UID, EUID)
        for num_field in ("tgid", "pid", "uid", "euid"):
            try:
                val = _parse_strict_int(validated[num_field])
                if val < 0:
                    raise TelemetryValidationError(line_no, num_field, f"Giá trị không được âm: {val}", record)
                validated[num_field] = val
            except TelemetryValidationError:
                raise
            except (ValueError, TypeError):
                raise TelemetryValidationError(line_no, num_field, f"Trường '{num_field}' phải là số nguyên hợp lệ", record)

        if validated["tgid"] < 1:
            raise TelemetryValidationError(line_no, "tgid", f"TGID (Process ID) phải >= 1, nhận được {validated['tgid']}", record)
        if validated["pid"] < 1:
            raise TelemetryValidationError(line_no, "pid", f"PID (Thread ID) phải >= 1, nhận được {validated['pid']}", record)

        # Kiểm tra các trường số nguyên không âm tùy chọn nếu có mặt
        for opt_field in self.OPTIONAL_NONNEG_INT_FIELDS:
            if opt_field in validated and validated[opt_field] is not None:
                try:
                    opt_val = _parse_strict_int(validated[opt_field])
                    if opt_val < 0:
                        raise TelemetryValidationError(line_no, opt_field, f"Giá trị không được âm: {opt_val}", record)
                    validated[opt_field] = opt_val
                except TelemetryValidationError:
                    raise
                except (ValueError, TypeError):
                    raise TelemetryValidationError(line_no, opt_field, f"Trường '{opt_field}' phải là số nguyên hợp lệ", record)

        # 4. Kiểm tra nhãn huấn luyện (label: 0 hoặc 1) nếu bắt buộc hoặc có mặt
        if self.require_label or ("label" in validated and validated["label"] is not None):
            try:
                lbl = _parse_strict_int(validated["label"])
                if lbl not in (0, 1):
                    raise TelemetryValidationError(line_no, "label", f"Nhãn 'label' phải là 0 (Benign) hoặc 1 (Attack), nhận được {lbl}", record)
                validated["label"] = lbl
            except TelemetryValidationError:
                raise
            except (ValueError, TypeError):
                raise TelemetryValidationError(line_no, "label", "Trường 'label' phải là số nguyên (0 hoặc 1)", record)

        # 5. Kiểm tra kiểu dữ liệu & độ dài chuỗi (comm, filename, session_id)
        comm_val = validated["comm"]
        if not isinstance(comm_val, str):
            raise TelemetryValidationError(line_no, "comm", f"Trường 'comm' phải là chuỗi (string), nhận được {type(comm_val).__name__}", record)
        if not comm_val.strip():
            raise TelemetryValidationError(line_no, "comm", "Trường 'comm' không được để trống", record)
        if len(comm_val) > self.comm_max_len:
            raise TelemetryValidationError(
                line_no,
                "comm",
                f"Độ dài 'comm' vượt quá {self.comm_max_len} ký tự ({len(comm_val)})",
                record,
            )

        if "filename" in validated:
            fn_val = validated["filename"]
            if not isinstance(fn_val, str):
                raise TelemetryValidationError(
                    line_no,
                    "filename",
                    f"Trường 'filename' phải là chuỗi (string), nhận được {type(fn_val).__name__}",
                    record,
                )
            if len(fn_val) > self.filename_max_len:
                raise TelemetryValidationError(
                    line_no,
                    "filename",
                    f"Độ dài 'filename' vượt quá {self.filename_max_len} ký tự ({len(fn_val)})",
                    record,
                )

        sid_val = validated["session_id"]
        if not isinstance(sid_val, str):
            raise TelemetryValidationError(
                line_no,
                "session_id",
                f"Trường 'session_id' phải là chuỗi (string), nhận được {type(sid_val).__name__}",
                record,
            )
        session_id = sid_val.strip()
        if not session_id:
            raise TelemetryValidationError(line_no, "session_id", "session_id không được để trống", record)
        validated["session_id"] = session_id

        # 6. Kiểm tra nghiêm ngặt mọi trường timestamp có mặt (ưu tiên timestamp_ns -> timestamp -> timestamp_iso)
        has_ts = False
        if "timestamp_ns" in validated and validated["timestamp_ns"] is not None:
            try:
                ts_ns = _parse_strict_int(validated["timestamp_ns"])
            except (ValueError, TypeError):
                raise TelemetryValidationError(line_no, "timestamp_ns", "timestamp_ns phải là số nguyên > 0", record)
            if ts_ns <= 0:
                raise TelemetryValidationError(line_no, "timestamp_ns", f"timestamp_ns phải > 0, nhận được {ts_ns}", record)
            validated["timestamp_ns"] = ts_ns
            has_ts = True

        if "timestamp" in validated and validated["timestamp"] is not None:
            raw_ts = validated["timestamp"]
            if isinstance(raw_ts, (bool, np.bool_)):
                raise TelemetryValidationError(line_no, "timestamp", "timestamp không được là boolean", record)
            try:
                ts_sec = float(raw_ts)
            except (ValueError, TypeError):
                raise TelemetryValidationError(line_no, "timestamp", f"timestamp không hợp lệ: {raw_ts}", record)
            if not math.isfinite(ts_sec) or ts_sec <= 0:
                raise TelemetryValidationError(line_no, "timestamp", f"timestamp phải là số dương hữu hạn, nhận được {raw_ts}", record)
            validated["timestamp"] = ts_sec
            has_ts = True

        if "timestamp_iso" in validated and validated["timestamp_iso"] is not None:
            raw_iso = validated["timestamp_iso"]
            if not isinstance(raw_iso, str) or not raw_iso.strip():
                raise TelemetryValidationError(line_no, "timestamp_iso", "timestamp_iso phải là chuỗi ISO-8601 hợp lệ", record)
            try:
                datetime.fromisoformat(raw_iso.strip().replace("Z", "+00:00"))
            except Exception:
                raise TelemetryValidationError(line_no, "timestamp_iso", f"timestamp_iso không đúng chuẩn ISO-8601: {raw_iso}", record)
            validated["timestamp_iso"] = raw_iso.strip()
            has_ts = True

        if not has_ts:
            raise TelemetryValidationError(
                line_no,
                "timestamp",
                "Bản ghi phải có ít nhất một trường thời gian hợp lệ (timestamp_ns, timestamp, hoặc timestamp_iso)",
                record,
            )

        return validated

    def load_jsonl(self, file_path: str) -> List[Dict[str, Any]]:
        """Đọc và xác thực danh sách bản ghi telemetry từ file JSONL."""
        records: List[Dict[str, Any]] = []
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy file telemetry tại: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as e:
                    raise TelemetryValidationError(line_no, "json_syntax", f"Lỗi cú pháp JSON: {e}")

                validated = self.validate_record(data, line_no)
                records.append(validated)

        return records

    def load_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Đọc và xác thực danh sách bản ghi telemetry từ file CSV (bảo toàn chuỗi & số nguyên 64-bit)."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy file telemetry tại: {file_path}")

        optional_blank_omit = {
            "ppid",
            "cap",
            "flags",
            "cgroup_id",
            "mntns_id",
            "pidns_id",
            "timestamp_ns",
            "timestamp",
            "timestamp_iso",
        }
        if not self.require_label:
            optional_blank_omit.add("label")

        records: List[Dict[str, Any]] = []
        line_no = 1
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f, restkey=None, restval=None)
                fieldnames = reader.fieldnames
                if not fieldnames or all(not (col and col.strip()) for col in fieldnames):
                    raise TelemetryValidationError(1, "csv_format", "File CSV rỗng hoặc không có dòng tiêu đề hợp lệ")

                for idx, row_dict in enumerate(reader, start=2):
                    line_no = idx
                    if None in row_dict or any(v is None for v in row_dict.values()):
                        raise TelemetryValidationError(
                            line_no,
                            "csv_format",
                            "Số lượng cột trong dòng CSV không khớp với tiêu đề",
                        )

                    clean_dict: Dict[str, Any] = {}
                    for k, v in row_dict.items():
                        if isinstance(v, str) and v.strip() == "" and k in optional_blank_omit:
                            continue
                        clean_dict[k] = v

                    validated = self.validate_record(clean_dict, line_no)
                    records.append(validated)
        except TelemetryValidationError:
            raise
        except UnicodeDecodeError as e:
            raise TelemetryValidationError(line_no, "csv_encoding", f"Lỗi mã hóa UTF-8 khi đọc CSV: {e}")
        except csv.Error as e:
            raise TelemetryValidationError(line_no, "csv_format", f"Lỗi cú pháp CSV: {e}")

        return records

    def iter_session_features(
        self,
        events: List[Dict[str, Any]],
        window_size_seconds: float = 3.0,
        on_exit: Optional[Callable[[int], None]] = None,
    ) -> Iterator[Tuple[str, Dict[str, Any], np.ndarray, Dict[str, Any], FeatureExtractor]]:
        """
        Nhóm sự kiện theo session_id, sắp xếp ổn định theo (timestamp, event_type_rank)
        đặt PROCESS_FORK(6) đầu tiên và PROCESS_EXIT(5) cuối cùng khi trùng timestamp,
        rồi trích xuất tuần tự đặc trưng với FeatureExtractor cô lập cho từng phiên.
        """
        grouped_sessions: Dict[str, List[Dict[str, Any]]] = {}
        for ev in events:
            sid = str(ev.get("session_id", "default"))
            grouped_sessions.setdefault(sid, []).append(ev)

        for sid, sess_events in grouped_sessions.items():
            sorted_events = sorted(
                sess_events,
                key=lambda ev: (
                    extract_explicit_timestamp(ev) or 0.0,
                    EVENT_SORT_RANK.get(int(ev.get("event_type", 0) or 0), 99),
                ),
            )
            extractor = FeatureExtractor(window_size_seconds=window_size_seconds)

            for ev in sorted_events:
                tgid = int(ev["tgid"])
                ev_type = int(ev["event_type"])
                flags = int(ev.get("flags", 0) or 0)
                ev_ts = extract_explicit_timestamp(ev)
                if ev_ts is None:
                    ev_ts = time.time()

                if ev_type == 5:
                    extractor.mark_process_exit(tgid, event_time=ev_ts)
                    if on_exit is not None:
                        on_exit(tgid)
                    continue

                if ev_type == 6:
                    extractor.register_fork(
                        parent_tgid=int(ev.get("ppid", 0) or 0),
                        child_tgid=tgid,
                        comm=str(ev.get("comm", "") or ""),
                        uid=int(ev["uid"]),
                        euid=int(ev["euid"]),
                        cgroup_id=int(ev.get("cgroup_id", 0) or 0),
                        pidns_id=int(ev.get("pidns_id", 0) or 0),
                        mntns_id=int(ev.get("mntns_id", 0) or 0),
                        event_time=ev_ts,
                    )
                    continue

                if ev_type == 1 and (flags & FLAG_EXEC_FAILED) != 0:
                    extractor.revert_failed_exec(tgid, event_time=ev_ts)
                    continue

                extractor.update_process(
                    pid=tgid,
                    ppid=int(ev.get("ppid", 0) or 0),
                    comm=str(ev.get("comm", "") or ""),
                    uid=int(ev["uid"]),
                    euid=int(ev["euid"]),
                    cgroup_id=int(ev.get("cgroup_id", 0) or 0),
                    mntns_id=int(ev.get("mntns_id", 0) or 0),
                    event_time=ev_ts,
                    pidns_id=int(ev.get("pidns_id", 0) or 0),
                    exe_path=str(ev.get("filename", "") or "") if ev_type == 1 else None,
                    is_main_thread=(int(ev["pid"]) == tgid),
                    event_type=ev_type,
                )
                extractor.add_event(ev)
                feat_vec, raw_feat = extractor.extract_features(tgid, ev)
                yield sid, ev, feat_vec, raw_feat, extractor

    def convert_events_to_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Duyệt chuỗi sự kiện qua iter_session_features() cô lập theo từng session_id
        để trích xuất ma trận 8 đặc trưng mà không làm rò rỉ ngữ cảnh/PID giữa các phiên.
        """
        feature_rows: List[Dict[str, Any]] = []
        for sid, ev, _, raw_feat, _ in self.iter_session_features(events):
            row = dict(raw_feat)
            row["session_id"] = sid
            if "label" in ev and ev["label"] is not None:
                row["label"] = int(ev["label"])
            feature_rows.append(row)

        if not feature_rows:
            cols = FEATURE_NAMES + (["session_id", "label"] if self.require_label else ["session_id"])
            return pd.DataFrame(columns=cols)

        return pd.DataFrame(feature_rows)
