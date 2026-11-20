"""
ml/telemetry_loader.py: Đọc, xác thực và tiền xử lý dữ liệu telemetry thực tế từ file CSV hoặc JSONL
Thực hiện kiểm tra nghiêm ngặt theo schema: trường bắt buộc, kiểu dữ liệu, nhãn (0/1),
session_id và timestamp. Báo lỗi chi tiết kèm số dòng nếu dữ liệu sai/thiếu.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import FEATURE_NAMES, FeatureExtractor, get_event_timestamp

SCHEMA_PATH = PROJECT_ROOT / "ml" / "data" / "telemetry_schema.json"


class TelemetryValidationError(ValueError):
    """Ngoại lệ khi bản ghi telemetry không hợp lệ theo schema chuẩn"""
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
    Nạp và xác thực dữ liệu telemetry gán nhãn thực tế từ file CSV hoặc JSONL
    Đảm bảo tính toàn vẹn dữ liệu cho huấn luyện Machine Learning.
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

    OPTIONAL_NONNEG_INT_FIELDS = (
        "ppid",
        "cap",
        "cgroup_id",
        "mntns_id",
        "pidns_id",
    )

    def __init__(self, schema_file: Optional[Path] = None):
        self.schema_file = schema_file or SCHEMA_PATH
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        if self.schema_file.exists():
            try:
                with open(self.schema_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def validate_record(self, record: Dict[str, Any], line_no: int) -> Dict[str, Any]:
        """
        Kiểm tra tính hợp lệ của bản ghi telemetry (không làm biến đổi dict đầu vào):
        - Kiểm tra các trường bắt buộc
        - Kiểm tra kiểu dữ liệu (từ chối bool cho trường số) và miền giá trị
        - Không âm thầm gán giá trị mặc định cho dữ liệu bị khuyết thiếu quan trọng
        """
        if not isinstance(record, dict):
            raise TelemetryValidationError(line_no, "root", f"Bản ghi phải là đối tượng JSON/Dict, nhận được {type(record).__name__}")

        # Kiểm tra nếu người dùng nhầm lẫn truyền file cảnh báo (Alert log)
        if "threat_score" in record or "matched_rules" in record or "triggered_rule" in record:
            raise TelemetryValidationError(
                line_no,
                "format",
                "File này có cấu trúc Alert Log (chứa 'threat_score', 'triggered_rule' hoặc 'matched_rules'), không phải Telemetry có nhãn ground-truth. "
                "Alert log không thể dùng trực tiếp để huấn luyện mô hình. Vui lòng thu thập telemetry có gán nhãn theo ml/data/telemetry_schema.json.",
                record
            )

        validated = dict(record)

        # 1. Kiểm tra sự tồn tại của các trường bắt buộc
        for req in self.REQUIRED_FIELDS:
            if req not in validated or validated[req] is None or (isinstance(validated[req], str) and not validated[req].strip()):
                raise TelemetryValidationError(line_no, req, f"Trường bắt buộc '{req}' bị thiếu hoặc có giá trị rỗng", record)

        # 2. Kiểm tra event_type
        try:
            ev_type = _parse_strict_int(validated["event_type"])
            if ev_type not in (1, 2, 3, 4, 5):
                raise TelemetryValidationError(
                    line_no,
                    "event_type",
                    f"Giá trị event_type không hợp lệ ({ev_type}). Phải là 1 (execve/execveat), 2 (commit_creds), 3 (cap_capable), 4 (openat), hoặc 5 (process_exit)",
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

        # 4. Kiểm tra nhãn huấn luyện (label: 0 hoặc 1)
        try:
            lbl = _parse_strict_int(validated["label"])
            if lbl not in (0, 1):
                raise TelemetryValidationError(line_no, "label", f"Nhãn 'label' phải là 0 (Benign) hoặc 1 (Attack), nhận được {lbl}", record)
            validated["label"] = lbl
        except TelemetryValidationError:
            raise
        except (ValueError, TypeError):
            raise TelemetryValidationError(line_no, "label", "Trường 'label' phải là số nguyên (0 hoặc 1)", record)

        # 5. Kiểm tra session_id (bắt buộc để GroupShuffleSplit không bị rò rỉ dữ liệu)
        session_id = str(validated["session_id"]).strip()
        if not session_id:
            raise TelemetryValidationError(line_no, "session_id", "session_id không được để trống", record)
        validated["session_id"] = session_id

        # 6. Kiểm tra timestamp
        has_ts = False
        if "timestamp_ns" in validated and validated["timestamp_ns"] is not None:
            try:
                ts_ns = _parse_strict_int(validated["timestamp_ns"])
                if ts_ns > 0:
                    has_ts = True
                    validated["timestamp_ns"] = ts_ns
            except (ValueError, TypeError):
                pass

        if not has_ts and "timestamp_iso" in validated and validated["timestamp_iso"]:
            try:
                datetime.fromisoformat(str(validated["timestamp_iso"]).replace("Z", "+00:00"))
                has_ts = True
            except Exception:
                raise TelemetryValidationError(line_no, "timestamp_iso", f"timestamp_iso không đúng chuẩn ISO-8601: {validated.get('timestamp_iso')}", record)

        if not has_ts and "timestamp" in validated and validated["timestamp"] is not None:
            raw_ts = validated["timestamp"]
            if not isinstance(raw_ts, (bool, np.bool_)):
                try:
                    ts_sec = float(raw_ts)
                    if np.isfinite(ts_sec) and ts_sec > 0:
                        has_ts = True
                        validated["timestamp"] = ts_sec
                except (ValueError, TypeError):
                    pass

        if not has_ts:
            raise TelemetryValidationError(line_no, "timestamp", "Bản ghi phải có ít nhất một trường thời gian hợp lệ (timestamp_ns, timestamp_iso, hoặc timestamp)", record)

        return validated

    def load_jsonl(self, file_path: str) -> List[Dict[str, Any]]:
        """Đọc và xác thực danh sách bản ghi telemetry từ file JSONL"""
        records = []
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
        """Đọc và xác thực danh sách bản ghi telemetry từ file CSV"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy file telemetry tại: {file_path}")

        try:
            df = pd.read_csv(path)
        except pd.errors.EmptyDataError:
            raise TelemetryValidationError(1, "csv_format", "File CSV rỗng hoặc không có dòng tiêu đề hợp lệ")

        records = []
        # Header là dòng 1, dữ liệu bắt đầu từ dòng 2
        for idx, row in df.iterrows():
            line_no = int(idx) + 2
            row_dict = row.to_dict()
            # Bỏ NaN pandas
            clean_dict = {k: v for k, v in row_dict.items() if pd.notna(v)}
            validated = self.validate_record(clean_dict, line_no)
            records.append(validated)

        return records

    def convert_events_to_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Duyệt chuỗi sự kiện đã được xác thực qua FeatureExtractor cô lập theo từng session_id
        để trích xuất ma trận 8 đặc trưng mà không làm rò rỉ ngữ cảnh/PID giữa các phiên.
        """
        extractors: Dict[str, FeatureExtractor] = {}
        feature_rows: List[Dict[str, Any]] = []

        for ev in events:
            sid = str(ev["session_id"])
            if sid not in extractors:
                extractors[sid] = FeatureExtractor(window_size_seconds=3.0)
            extractor = extractors[sid]

            tgid = int(ev["tgid"])
            ev_type = int(ev["event_type"])
            ev_ts = get_event_timestamp(ev)

            if ev_type == 5:
                extractor.mark_process_exit(tgid, event_time=ev_ts)
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
            )
            extractor.add_event(ev)
            _, raw_feat = extractor.extract_features(tgid, ev)

            row = dict(raw_feat)
            row["session_id"] = sid
            row["label"] = int(ev["label"])
            feature_rows.append(row)

        if not feature_rows:
            return pd.DataFrame(columns=FEATURE_NAMES + ["session_id", "label"])

        return pd.DataFrame(feature_rows)
