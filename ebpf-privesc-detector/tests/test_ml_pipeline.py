"""
tests/test_ml_pipeline.py: Unit tests kiểm thử quy trình nạp telemetry và tính tương thích của mô hình ML
"""

import os
import json
import tempfile
import unittest
from pathlib import Path
import numpy as np

from agent.features import FEATURE_NAMES
from agent.detector import run_replay
from benchmarks.benchmark_agent_vs_auditd import parse_proc_stat_jiffies
from ml.telemetry_loader import TelemetryLoader, TelemetryValidationError


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
        self.assertIn("session_id", schema["required"])

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

    def test_load_jsonl_file_success(self):
        """Kiểm tra đọc file JSONL hợp lệ theo schema"""
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
                "session_id": "session_valid_01",
                "label": 0,
            }
            f.write(json.dumps(sample_record) + "\n")
            tmp_path = f.name

        try:
            records = self.loader.load_jsonl(tmp_path)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["comm"], "ls")
            self.assertEqual(records[0]["session_id"], "session_valid_01")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validation_error_on_missing_required_field(self):
        """Báo lỗi TelemetryValidationError kèm số dòng và tên trường khi thiếu trường bắt buộc"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8") as f:
            # Dòng 1: Hợp lệ
            valid_rec = {
                "timestamp_iso": "2026-10-23T12:00:00Z",
                "event_type": 1,
                "tgid": 2000,
                "pid": 2000,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "session_id": "sess_01",
                "label": 0,
            }
            # Dòng 2: Thiếu trường bắt buộc 'session_id'
            invalid_rec = {
                "timestamp_iso": "2026-10-23T12:00:01Z",
                "event_type": 1,
                "tgid": 2001,
                "pid": 2001,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "label": 0,
            }
            f.write(json.dumps(valid_rec) + "\n")
            f.write(json.dumps(invalid_rec) + "\n")
            tmp_path = f.name

        try:
            with self.assertRaises(TelemetryValidationError) as ctx:
                self.loader.load_jsonl(tmp_path)
            self.assertEqual(ctx.exception.line_number, 2)
            self.assertEqual(ctx.exception.field, "session_id")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validation_error_on_alert_log_passed_as_telemetry(self):
        """Từ chối rõ ràng và báo lỗi khi người dùng truyền nhầm file log cảnh báo thay vì telemetry có nhãn"""
        for alert_rec in (
            {"timestamp": "2026-10-23T12:00:00Z", "threat_score": 85, "matched_rules": ["PRIVESC-001"]},
            {"timestamp": "2026-10-23T12:00:00Z", "triggered_rule": {"rule_id": "PRIVESC-002"}},
        ):
            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8") as f:
                f.write(json.dumps(alert_rec) + "\n")
                tmp_path = f.name

            try:
                with self.assertRaises(TelemetryValidationError) as ctx:
                    self.loader.load_jsonl(tmp_path)
                self.assertEqual(ctx.exception.line_number, 1)
                self.assertEqual(ctx.exception.field, "format")
                self.assertIn("Alert Log", ctx.exception.message)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    def test_validation_error_on_invalid_event_type(self):
        """Từ chối event_type không thuộc miền [1, 2, 3, 4]"""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w", encoding="utf-8") as f:
            bad_rec = {
                "timestamp_iso": "2026-10-23T12:00:00Z",
                "event_type": 99,
                "tgid": 2000,
                "pid": 2000,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "session_id": "sess_01",
                "label": 0,
            }
            f.write(json.dumps(bad_rec) + "\n")
            tmp_path = f.name

        try:
            with self.assertRaises(TelemetryValidationError) as ctx:
                self.loader.load_jsonl(tmp_path)
            self.assertEqual(ctx.exception.line_number, 1)
            self.assertEqual(ctx.exception.field, "event_type")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_validation_rejects_boolean_as_int_and_preserves_input(self):
        """Từ chối kiểu bool dùng nhầm cho trường số nguyên và không làm biến đổi dict đầu vào"""
        original = {
            "timestamp_iso": "2026-10-23T12:00:00Z",
            "event_type": "1",
            "tgid": 2000,
            "pid": 2000,
            "uid": "1000",
            "euid": 1000,
            "comm": "ls",
            "session_id": "sess_01",
            "label": 0,
        }
        validated = self.loader.validate_record(original, 1)
        self.assertEqual(validated["event_type"], 1)
        self.assertEqual(validated["uid"], 1000)
        # Dict gốc không bị ép kiểu
        self.assertIsInstance(original["event_type"], str)
        self.assertIsInstance(original["uid"], str)

        bad_bool = dict(original)
        bad_bool["label"] = True
        with self.assertRaises(TelemetryValidationError) as ctx:
            self.loader.validate_record(bad_bool, 1)
        self.assertEqual(ctx.exception.field, "label")

    def test_cross_session_pid_isolation_no_leakage(self):
        """Hai phiên khác nhau trùng TGID (pid=1001) không được rò rỉ cửa sổ trượt hay exe_path"""
        events = [
            {
                "timestamp": 100.0,
                "event_type": 1,
                "tgid": 1001,
                "pid": 1001,
                "ppid": 1,
                "uid": 1000,
                "euid": 0,
                "comm": "sudo",
                "filename": "/usr/bin/sudo",
                "session_id": "sess_a",
                "label": 0,
            },
            {
                "timestamp": 100.5,
                "event_type": 1,
                "tgid": 1001,
                "pid": 1001,
                "ppid": 1,
                "uid": 1000,
                "euid": 0,
                "comm": "find",
                "filename": "/usr/bin/find",
                "session_id": "sess_b",
                "label": 1,
            },
        ]
        df = self.loader.convert_events_to_features(events)
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["exec_count"], 1)
        self.assertEqual(df.iloc[0]["is_whitelisted_bin"], 1)
        # Session B có TGID=1001 riêng biệt -> exec_count == 1 (không cộng dồn thành 2) và không lây whitelist sudo
        self.assertEqual(df.iloc[1]["exec_count"], 1)
        self.assertEqual(df.iloc[1]["is_whitelisted_bin"], 0)

    def test_sample_telemetry_and_offline_replay(self):
        """Kiểm chứng bộ sample_telemetry.jsonl hợp lệ và luồng --replay đạt Precision/Recall chuẩn xác"""
        sample_path = Path(__file__).resolve().parent.parent / "ml" / "data" / "sample_telemetry.jsonl"
        self.assertTrue(sample_path.exists())

        records = self.loader.load_jsonl(str(sample_path))
        self.assertEqual(len(records), 24)

        summary = run_replay(str(sample_path), alert_log_path=None, quiet=True)
        self.assertEqual(summary["sessions"], 6)
        self.assertEqual(summary["fp"], 0)
        self.assertEqual(summary["fn"], 0)
        self.assertEqual(summary["tp"], 9)

    def test_benchmark_proc_stat_parser_with_spaces_and_parens(self):
        """Parser /proc/<pid>/stat không bị lệch cột khi tên tiến trình chứa khoảng trắng và ngoặc đơn"""
        fake_stat = "4321 (Isolated Web (1)) R 1000 4321 1000 0 -1 4194304 100 0 0 0 150 25 0 0 20 0 1 0 12345"
        self.assertEqual(parse_proc_stat_jiffies(fake_stat), 175)


if __name__ == "__main__":
    unittest.main()
