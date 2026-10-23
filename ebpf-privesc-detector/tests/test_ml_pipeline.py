"""
tests/test_ml_pipeline.py: Unit tests kiểm thử quy trình nạp telemetry và tính tương thích của mô hình ML
"""

import os
import json
import tempfile
import unittest
import numpy as np

from agent.features import FEATURE_NAMES
from ml.telemetry_loader import TelemetryLoader


class TestMLPipeline(unittest.TestCase):
    def setUp(self):
        self.loader = TelemetryLoader()

    def test_schema_loads_successfully(self):
        """Schema JSON định nghĩa telemetry phải tồn tại và đọc được"""
        schema = self.loader.schema
        self.assertIn("required", schema)
        self.assertIn("properties", schema)
        self.assertIn("tgid", schema["required"])
        self.assertIn("label", schema["required"])

    def test_convert_events_to_features(self):
        """Chuyển đổi chuỗi sự kiện telemetry thành bảng 8 đặc trưng"""
        events = [
            {
                "timestamp_iso": "2026-10-23T10:00:00Z",
                "event_type": 1,
                "tgid": 1001,
                "pid": 1001,
                "ppid": 1000,
                "uid": 1000,
                "euid": 0,
                "comm": "find",
                "filename": "/usr/bin/find",
                "session_id": "test_session_1",
                "label": 1,
            },
            {
                "timestamp_iso": "2026-10-23T10:00:01Z",
                "event_type": 4,
                "tgid": 1001,
                "pid": 1001,
                "ppid": 1000,
                "uid": 1000,
                "euid": 0,
                "comm": "find",
                "filename": "/etc/shadow",
                "session_id": "test_session_1",
                "label": 1,
            },
        ]

        df = self.loader.convert_events_to_features(events)
        self.assertEqual(len(df), 2)
        for fname in FEATURE_NAMES:
            self.assertIn(fname, df.columns)
        self.assertIn("session_id", df.columns)
        self.assertIn("label", df.columns)
        self.assertEqual(df["label"].iloc[0], 1)
        self.assertEqual(df["session_id"].iloc[0], "test_session_1")

    def test_load_jsonl_file(self):
        """Kiểm tra đọc file JSONL mẫu"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8") as f:
            sample_record = {
                "timestamp_iso": "2026-10-23T12:00:00Z",
                "event_type": 1,
                "tgid": 2000,
                "pid": 2000,
                "ppid": 1,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "filename": "/usr/bin/ls",
                "label": 0,
            }
            f.write(json.dumps(sample_record) + "\n")
            tmp_path = f.name

        try:
            records = self.loader.load_jsonl(tmp_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["comm"], "ls")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
