"""
ml/telemetry_loader.py: Đọc, xác thực và tiền xử lý dữ liệu telemetry thực tế từ file CSV hoặc JSONL
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
from agent.features import FEATURE_NAMES, FeatureExtractor

SCHEMA_PATH = PROJECT_ROOT / "ml" / "data" / "telemetry_schema.json"


class TelemetryLoader:
    """
    Nạp dữ liệu telemetry gán nhãn thực tế từ file CSV hoặc JSONL
    Chuyển đổi chuỗi sự kiện telemetry thành bảng 8 đặc trưng qua FeatureExtractor
    """
    def __init__(self, schema_file: Optional[Path] = None):
        self.schema_file = schema_file or SCHEMA_PATH
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        if self.schema_file.exists():
            with open(self.schema_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def load_jsonl(self, file_path: str) -> List[Dict[str, Any]]:
        """Đọc danh sách bản ghi telemetry từ file JSONL"""
        records = []
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy file telemetry tại: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data = json.loads(line)
                    records.append(data)
                except json.JSONDecodeError as e:
                    print(f"[!] Cảnh báo dòng {line_no} không hợp lệ JSON: {e}")
        return records

    def load_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Đọc danh sách bản ghi telemetry từ file CSV"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Không tìm thấy file telemetry tại: {file_path}")

        df = pd.read_csv(path)
        return df.to_dict(orient="records")

    def convert_events_to_features(self, events: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Duyệt chuỗi sự kiện theo thứ tự thời gian qua FeatureExtractor
        để trích xuất ma trận 8 đặc trưng cùng nhãn và session_id.
        """
        extractor = FeatureExtractor(window_size_seconds=3.0)
        feature_rows = []

        for ev in events:
            tgid = ev.get("tgid", ev.get("pid", 0))
            extractor.update_process(
                pid=tgid,
                ppid=ev.get("ppid", 0),
                comm=ev.get("comm", ""),
                uid=ev.get("uid", 1000),
                euid=ev.get("euid", 1000),
                cgroup_id=ev.get("cgroup_id", 0),
                mntns_id=ev.get("mntns_id", 0),
            )
            extractor.add_event(ev)
            vec, raw_feat = extractor.extract_features(tgid, ev)

            row = dict(raw_feat)
            row["session_id"] = ev.get("session_id", f"session_{tgid}")
            row["label"] = int(ev.get("label", 0))
            feature_rows.append(row)

        return pd.DataFrame(feature_rows)
