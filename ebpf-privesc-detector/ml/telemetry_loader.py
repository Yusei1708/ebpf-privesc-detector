"""
ml/telemetry_loader.py: Đọc, xác thực và tiền xử lý dữ liệu telemetry thực tế từ file CSV hoặc JSONL
Thực hiện kiểm tra nghiêm ngặt theo schema: trường bắt buộc, kiểu dữ liệu, nhãn (0/1),
session_id và timestamp. Báo lỗi chi tiết kèm số dòng nếu dữ liệu sai/thiếu.
"""

import os
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
from agent.features import FEATURE_NAMES, FeatureExtractor, get_event_timestamp

SCHEMA_PATH = PROJECT_ROOT / "ml" / "data" / "telemetry_schema.json"


class TelemetryValidationError(ValueError):
    """Ngoại lệ khi bản ghi telemetry không hợp lệ theo schema chuẩn"""
    def __init__(self, line_number: int, field_name: str, message: str, raw_data: Optional[Dict[str, Any]] = None):
        super().__init__(f"[Dòng {line_number}] Lỗi trường '{field_name}': {message}")
        self.line_number = line_number
        self.field_name = field_name
        self.raw_data = raw_data


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
        Kiểm tra tính hợp lệ của bản ghi telemetry:
        - Kiểm tra các trường bắt buộc
        - Kiểm tra kiểu dữ liệu và miền giá trị
        - Không âm thầm gán giá trị mặc định cho dữ liệu bị khuyết thiếu quan trọng
        """
        if not isinstance(record, dict):
            raise TelemetryValidationError(line_no, "root", f"Bản ghi phải là đối tượng JSON/Dict, nhận được {type(record).__name__}")

        # 1. Kiểm tra sự tồn tại của các trường bắt buộc
        for req in self.REQUIRED_FIELDS:
            if req not in record or record[req] is None or (isinstance(record[req], str) and not record[req].strip()):
                raise TelemetryValidationError(line_no, req, f"Trường bắt buộc '{req}' bị thiếu hoặc có giá trị rỗng", record)

        # 2. Kiểm tra event_type
        try:
            ev_type = int(record["event_type"])
            if ev_type not in (1, 2, 3, 4):
                raise TelemetryValidationError(line_no, "event_type", f"Giá trị event_type không hợp lệ ({ev_type}). Phải là 1 (execve), 2 (commit_creds), 3 (cap_capable), hoặc 4 (openat)", record)
            record["event_type"] = ev_type
        except (ValueError, TypeError):
            raise TelemetryValidationError(line_no, "event_type", "event_type phải là số nguyên", record)

        # 3. Kiểm tra các định danh tiến trình và người dùng (TGID, PID, UID, EUID)
        for num_field in ("tgid", "pid", "uid", "euid"):
            try:
                val = int(record[num_field])
                if val < 0:
                    raise TelemetryValidationError(line_no, num_field, f"Giá trị không được âm: {val}", record)
                record[num_field] = val
            except (ValueError, TypeError):
                raise TelemetryValidationError(line_no, num_field, f"Trường '{num_field}' phải là số nguyên hợp lệ", record)

        if record["tgid"] < 1:
            raise TelemetryValidationError(line_no, "tgid", f"TGID (Process ID) phải >= 1, nhận được {record['tgid']}", record)

        # 4. Kiểm tra nhãn huấn luyện (label: 0 hoặc 1)
        try:
            lbl = int(record["label"])
            if lbl not in (0, 1):
                raise TelemetryValidationError(line_no, "label", f"Nhãn 'label' phải là 0 (Benign) hoặc 1 (Attack), nhận được {lbl}", record)
            record["label"] = lbl
        except (ValueError, TypeError):
            raise TelemetryValidationError(line_no, "label", "Trường 'label' phải là số nguyên (0 hoặc 1)", record)

        # 5. Kiểm tra session_id (bắt buộc để GroupShuffleSplit không bị rò rỉ dữ liệu)
        session_id = str(record["session_id"]).strip()
        if not session_id:
            raise TelemetryValidationError(line_no, "session_id", "session_id không được để trống", record)
        record["session_id"] = session_id

        # 6. Kiểm tra timestamp
        has_ts = False
        if "timestamp_ns" in record and record["timestamp_ns"] is not None:
            try:
                ts_ns = int(record["timestamp_ns"])
                if ts_ns > 0:
                    has_ts = True
                    record["timestamp_ns"] = ts_ns
            except (ValueError, TypeError):
                pass

        if not has_ts and "timestamp_iso" in record and record["timestamp_iso"]:
            try:
                datetime.fromisoformat(str(record["timestamp_iso"]).replace("Z", "+00:00"))
                has_ts = True
            except Exception:
                raise TelemetryValidationError(line_no, "timestamp_iso", f"timestamp_iso không đúng chuẩn ISO-8601: {record.get('timestamp_iso')}", record)

        if not has_ts and "timestamp" in record and record["timestamp"] is not None:
            try:
                ts_sec = float(record["timestamp"])
                if ts_sec > 0:
                    has_ts = True
                    record["timestamp"] = ts_sec
            except (ValueError, TypeError):
                pass

        if not has_ts:
            raise TelemetryValidationError(line_no, "timestamp", "Bản ghi phải có ít nhất một trường thời gian hợp lệ (timestamp_ns, timestamp_iso, hoặc timestamp)", record)

        return record

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

        df = pd.read_csv(path)
        records = []
        # Header là dòng 1, dữ liệu bắt đầu từ dòng 2
        for idx, row in df.iterrows():
            line_no = idx + 2
            row_dict = row.to_dict()
            # Bỏ NaN pandas
            clean_dict = {k: v for k, v in row_dict.items() if pd.notna(v)}
            validated = self.validate_record(clean_dict, line_no)
            records.append(validated)

        return records

    def convert_events_to_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Duyệt chuỗi sự kiện đã được xác thực qua FeatureExtractor
        để trích xuất ma trận 8 đặc trưng cùng nhãn và session_id.
        """
        extractor = FeatureExtractor(window_size_seconds=3.0)
        feature_rows = []

        for ev in events:
            tgid = ev["tgid"]
            ev_ts = get_event_timestamp(ev)

            extractor.update_process(
                pid=tgid,
                ppid=int(ev.get("ppid", 0)),
                comm=str(ev.get("comm", "")),
                uid=int(ev["uid"]),
                euid=int(ev["euid"]),
                cgroup_id=int(ev.get("cgroup_id", 0)),
                mntns_id=int(ev.get("mntns_id", 0)),
                event_time=ev_ts,
            )
            extractor.add_event(ev)
            vec, raw_feat = extractor.extract_features(tgid, ev)

            row = dict(raw_feat)
            row["session_id"] = ev["session_id"]
            row["label"] = int(ev["label"])
            feature_rows.append(row)

        return pd.DataFrame(feature_rows)
