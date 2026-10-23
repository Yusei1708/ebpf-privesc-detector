"""
tests/test_alert_logger.py: Unit tests kiểm thử cơ chế ghi log cảnh báo JSONL an toàn
"""

import os
import json
import stat
import tempfile
import unittest

from agent.alert_logger import AlertLogger, sanitize_string
from agent.detector import RuleMatch


class TestAlertLogger(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.log_path = self.temp_file.name
        self.temp_file.close()
        self.logger = AlertLogger(self.log_path)

    def tearDown(self):
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    def test_file_permissions_secure(self):
        """File log phải được thiết lập quyền hạn an toàn 0600 (chỉ chủ sở hữu đọc/ghi)"""
        mode = stat.S_IMODE(os.stat(self.log_path).st_mode)
        # 0o600 = 384 decimal
        self.assertEqual(mode & 0o777, 0o600)

    def test_log_alert_json_structure(self):
        """Kiểm tra cấu trúc và các trường bắt buộc trong bản ghi JSONL"""
        alert_data = {
            "event": {
                "event_type": 1,
                "pid": 1234,
                "tgid": 1230,
                "ppid": 1000,
                "uid": 1000,
                "euid": 0,
                "timestamp_ns": 123456789000,
                "comm": "find",
                "filename": "/usr/bin/find",
                "cgroup_id": 4096,
                "mntns_id": 4026531840,
            },
            "raw_features": {
                "exec_count": 2,
                "uid_change_flag": 1,
                "is_whitelisted_bin": 0,
                "suspicious_path_flag": 0,
                "service_parent_flag": 0,
                "sensitive_file_access": 0,
                "cap_check_count": 0,
                "priv_syscall_rate": 0.67,
            },
            "rule_name": "RULE_GTFOBINS_SUID_ABUSE",
            "rule_sev": "CRITICAL",
            "match": RuleMatch(
                rule_id="PRIVESC-002",
                name="RULE_GTFOBINS_SUID_ABUSE",
                severity="CRITICAL",
                mitre_id="T1548.001",
                description="SUID abuse test",
                rationale="Test rationale",
            ),
            "rf_prob": 0.95,
            "iso_score": -0.12,
            "threat_score": 95,
        }

        success = self.logger.log_alert(alert_data)
        self.assertTrue(success)

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])

        self.assertIn("timestamp", record)
        self.assertEqual(record["event_name"], "EXECVE")
        self.assertEqual(record["threat_score"], 95)
        self.assertEqual(record["rf_score"], 0.95)
        self.assertEqual(record["anomaly_score"], -0.12)
        self.assertEqual(record["triggered_rule"]["rule_id"], "PRIVESC-002")
        self.assertTrue(record["is_container"])

    def test_sanitize_string(self):
        """Khử bỏ null bytes và ký tự điều khiển lạ để tránh Log Injection"""
        dirty = "evil_app\x00\r\ninjected_log"
        clean = sanitize_string(dirty)
        self.assertNotIn("\x00", clean)
        self.assertNotIn("\r", clean)
        self.assertNotIn("\n", clean)

    def test_io_error_graceful_handling(self):
        """Lỗi I/O khi ghi log không được làm sập chương trình (phải trả về False)"""
        # Trỏ logger vào đường dẫn không thể ghi
        bad_logger = AlertLogger("/invalid_directory_path/never_exist.jsonl")
        success = bad_logger.log_alert({"event": {}, "raw_features": {}})
        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
