"""
tests/test_alert_logger.py: Unit tests kiểm thử cơ chế ghi log cảnh báo JSONL an toàn,
quyền 0600, chống symlink (O_NOFOLLOW), xoay vòng kích thước và khử injection.
"""

import io
import os
import sys
import json
import stat
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stderr
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.alert_logger import AlertLogger, sanitize_string, is_container_event
from agent.detector import RuleMatch


class TestAlertLogger(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = str(Path(self.temp_dir.name) / "alerts.jsonl")
        self.host_pidns = 4026531836
        self.host_mntns = 4026531840
        self.logger = AlertLogger(
            self.log_path,
            host_mntns_id=self.host_mntns,
            host_pidns_id=self.host_pidns,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_file_permissions_new_and_tightened_0600(self):
        """File mới tạo phải có quyền 0600 và file sẵn có 0644 phải bị siết chặt về 0600."""
        fresh_path = Path(self.temp_dir.name) / "nested" / "fresh_alerts.jsonl"
        AlertLogger(str(fresh_path))
        self.assertTrue(fresh_path.exists())
        self.assertEqual(stat.S_IMODE(os.stat(fresh_path).st_mode), 0o600)

        loose_path = Path(self.temp_dir.name) / "loose.jsonl"
        loose_path.write_text("", encoding="utf-8")
        os.chmod(loose_path, 0o644)
        AlertLogger(str(loose_path))
        self.assertEqual(stat.S_IMODE(os.stat(loose_path).st_mode), 0o600)

    def test_symlink_log_path_rejected(self):
        """Từ chối ghi vào symbolic link nhờ cờ O_NOFOLLOW."""
        real_target = Path(self.temp_dir.name) / "real_target.txt"
        real_target.write_text("KEEP", encoding="utf-8")
        link_path = Path(self.temp_dir.name) / "symlink_alerts.jsonl"
        os.symlink(real_target, link_path)

        with redirect_stderr(io.StringIO()):
            sym_logger = AlertLogger(str(link_path))
            ok = sym_logger.log_alert({"event": {"event_type": 1}, "raw_features": {}, "threat_score": 80})

        self.assertFalse(ok)
        self.assertEqual(real_target.read_text(encoding="utf-8"), "KEEP")

    def test_log_rotation_and_backup_permissions(self):
        """Xoay vòng file log khi vượt max_bytes, giữ tối đa backup_count và bảo toàn quyền 0600."""
        rot_path = Path(self.temp_dir.name) / "rot_alerts.jsonl"
        rot_logger = AlertLogger(
            str(rot_path),
            host_mntns_id=self.host_mntns,
            host_pidns_id=self.host_pidns,
            max_bytes=450,
            backup_count=2,
        )
        for idx in range(4):
            self.assertTrue(
                rot_logger.log_alert(
                    {
                        "event": {"event_type": 1, "pid": 100 + idx, "tgid": 100 + idx, "comm": "find", "filename": "/usr/bin/find"},
                        "raw_features": {"exec_count": 1},
                        "threat_score": 95,
                    }
                )
            )

        self.assertTrue(rot_path.exists())
        self.assertTrue(Path(f"{rot_path}.1").exists())
        self.assertTrue(Path(f"{rot_path}.2").exists())
        self.assertFalse(Path(f"{rot_path}.3").exists())
        self.assertEqual(stat.S_IMODE(os.stat(rot_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(f"{rot_path}.1").st_mode), 0o600)

    def test_log_alert_json_structure_and_new_fields(self):
        """Kiểm tra đầy đủ schema JSONL bao gồm cap, cap_name, flags, lineage, highest_severity, is_ml_anomaly, description/rationale."""
        alert_data = {
            "event": {
                "event_type": 3,
                "pid": 1234,
                "tgid": 1230,
                "ppid": 1000,
                "uid": 1000,
                "euid": 1000,
                "cap": 7,
                "flags": 0,
                "timestamp_ns": 123456789000,
                "comm": "exploit",
                "filename": "/tmp/exploit",
                "cgroup_id": 4096,
                "pidns_id": self.host_pidns + 250,
                "mntns_id": self.host_mntns + 250,
            },
            "raw_features": {
                "exec_count": 2,
                "uid_change_flag": 0,
                "is_whitelisted_bin": 0,
                "suspicious_path_flag": 1,
                "service_parent_flag": 0,
                "sensitive_file_access": 1,
                "cap_check_count": 1,
                "priv_syscall_rate": 0.6667,
            },
            "rule_name": "RULE_PRIVILEGED_CAPABILITY_PROBE",
            "rule_sev": "MEDIUM",
            "highest_severity": "MEDIUM",
            "is_ml_anomaly": True,
            "lineage": ["bash(1000)", "exploit(1230)"],
            "matched_rules": ["PRIVESC-006"],
            "match": RuleMatch(
                rule_id="PRIVESC-006",
                name="RULE_PRIVILEGED_CAPABILITY_PROBE",
                severity="MEDIUM",
                mitre_id="T1548",
                description="Cap probe desc",
                rationale="Cap probe rationale",
            ),
            "rf_prob": 0.85,
            "iso_score": -0.15,
            "threat_score": 85,
        }

        self.assertTrue(self.logger.log_alert(alert_data))
        record = json.loads(Path(self.log_path).read_text(encoding="utf-8").splitlines()[0])

        self.assertIn("timestamp", record)
        self.assertEqual(record["event_name"], "CAP_CHECK")
        self.assertEqual(record["cap"], 7)
        self.assertEqual(record["cap_name"], "CAP_SETUID")
        self.assertEqual(record["flags"], 0)
        self.assertEqual(record["lineage"], ["bash(1000)", "exploit(1230)"])
        self.assertEqual(record["highest_severity"], "MEDIUM")
        self.assertTrue(record["is_ml_anomaly"])
        self.assertTrue(record["is_container"])
        self.assertEqual(record["triggered_rule"]["rule_id"], "PRIVESC-006")
        self.assertEqual(record["triggered_rule"]["description"], "Cap probe desc")
        self.assertEqual(record["triggered_rule"]["rationale"], "Cap probe rationale")

    def test_container_detection_pidns_and_pid_host(self):
        """Phân biệt Host vs Container và nhận diện container chạy --pid=host (pidns trùng nhưng mntns khác)."""
        self.assertFalse(
            is_container_event(
                {"pidns_id": self.host_pidns, "mntns_id": self.host_mntns},
                host_mntns_id=self.host_mntns,
                host_pidns_id=self.host_pidns,
            )
        )
        self.assertTrue(
            is_container_event(
                {"pidns_id": self.host_pidns + 400},
                host_mntns_id=self.host_mntns,
                host_pidns_id=self.host_pidns,
            )
        )
        self.assertTrue(
            is_container_event(
                {"pidns_id": self.host_pidns, "mntns_id": self.host_mntns + 100},
                host_mntns_id=self.host_mntns,
                host_pidns_id=self.host_pidns,
            )
        )

    def test_nan_inf_missing_uid_non_dict_and_ansi_sanitization(self):
        """Khử ANSI CSI/OSC, từ chối NaN/Inf trong JSON, đặt uid/euid thiếu thành None và từ chối non-dict."""
        self.assertFalse(self.logger.log_alert("not-a-dict"))  # type: ignore[arg-type]

        dirty = "\x1b[31mred\x1b[0m\x1b]0;title\x07evil\x00\r\ninjected"
        clean = sanitize_string(dirty)
        self.assertEqual(clean, "redevil  injected")
        self.assertEqual(len(sanitize_string("A" * 500)), 256)

        alert_data = {
            "event": {
                "event_type": 6,
                "pid": None,
                "tgid": None,
                "ppid": None,
                "comm": dirty,
                "filename": None,
            },
            "raw_features": {
                "exec_count": np.int64(3),
                "priv_syscall_rate": float("nan"),
                "cap_check_count": float("inf"),
            },
            "rule_name": None,
            "rf_prob": float("nan"),
            "iso_score": float("-inf"),
            "threat_score": 88,
        }
        self.assertTrue(self.logger.log_alert(alert_data))
        record = json.loads(Path(self.log_path).read_text(encoding="utf-8").splitlines()[0])

        self.assertEqual(record["event_name"], "PROCESS_FORK")
        self.assertIsNone(record["uid"])
        self.assertIsNone(record["euid"])
        self.assertEqual(record["rf_score"], 0.0)
        self.assertEqual(record["anomaly_score"], 0.0)
        self.assertEqual(record["features"]["exec_count"], 3)
        self.assertEqual(record["features"]["priv_syscall_rate"], 0.0)
        self.assertEqual(record["features"]["cap_check_count"], 0.0)
        self.assertNotIn("\x1b", record["comm"])

    def test_io_error_graceful_handling_root_safe(self):
        """Lỗi I/O dùng regular file làm parent đảm bảo thất bại ngay cả khi chạy bằng root và không đụng root FS."""
        blocker_file = Path(self.temp_dir.name) / "regular_file_blocker"
        blocker_file.write_text("x", encoding="utf-8")
        bad_path = str(blocker_file / "never_exist.jsonl")

        with redirect_stderr(io.StringIO()):
            bad_logger = AlertLogger(bad_path)
            success = bad_logger.log_alert({"event": {}, "raw_features": {}})

        self.assertFalse(success)


if __name__ == "__main__":
    unittest.main()
