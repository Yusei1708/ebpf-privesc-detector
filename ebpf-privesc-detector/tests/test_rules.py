"""
tests/test_rules.py: Unit tests kiểm thử tính chính xác của các luật phát hiện (Rule Engine)
Đảm bảo:
  - Bắt đúng các kỹ thuật tấn công leo quyền (True Positives)
  - Không cảnh báo nhầm các hành vi quản trị/người dùng hợp lệ (False Positives)
"""

import unittest
import numpy as np

from agent.detector import PrivEscDetector


class TestDetectionRules(unittest.TestCase):
    def setUp(self):
        # Khởi tạo detector ở chế độ không ghi file log
        self.detector = PrivEscDetector()

    def test_rule_commit_creds_euid_jump(self):
        """PRIVESC-001: Bắt việc nhảy EUID=0 qua commit_creds từ nhị phân unwhitelisted"""
        event = {
            "event_type": 2,  # commit_creds
            "uid": 1000,
            "euid": 0,
            "comm": "bad_binary",
            "filename": "/usr/local/bin/bad_binary",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertIsNotNone(match)
        self.assertEqual(match.rule_id, "PRIVESC-001")
        self.assertEqual(match.severity, "CRITICAL")

    def test_rule_gtfobins_suid_abuse(self):
        """PRIVESC-002: Bắt lạm dụng nhị phân không thuộc whitelist (find, python) với EUID=0"""
        event = {
            "event_type": 1,
            "uid": 1000,
            "euid": 0,
            "comm": "find",
            "filename": "/usr/bin/find",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-002")
        self.assertEqual(match.severity, "CRITICAL")

    def test_rule_suspicious_path_root_exec(self):
        """PRIVESC-003: Bắt thực thi mã từ /tmp với quyền root"""
        event = {
            "event_type": 1,
            "uid": 0,
            "euid": 0,
            "comm": "exploit",
            "filename": "/tmp/cve_2024.elf",
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-003")
        self.assertEqual(match.severity, "HIGH")

    def test_rule_service_spawned_root_shell(self):
        """PRIVESC-004: Bắt tiến trình con của web service leo quyền root"""
        event = {
            "event_type": 1,
            "uid": 33,
            "euid": 0,
            "comm": "sh",
            "filename": "/bin/sh",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 1,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-004")
        self.assertEqual(match.severity, "CRITICAL")

    def test_rule_sensitive_file_access_attempt(self):
        """PRIVESC-005: Bắt nỗ lực mở /etc/shadow từ tiến trình trong /tmp hoặc con của service"""
        event = {
            "event_type": 4,  # openat
            "uid": 1000,
            "euid": 0,
            "comm": "stealer",
            "filename": "/etc/shadow",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-005")

    def test_benign_admin_sudo_no_false_positive(self):
        """Hành vi admin dùng sudo hợp lệ KHÔNG ĐƯỢC kích hoạt cảnh báo sai"""
        event = {
            "event_type": 1,
            "uid": 1000,
            "euid": 0,
            "comm": "sudo",
            "filename": "/usr/bin/sudo",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 1,  # 1: Sudo là nhị phân trong whitelist
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)

    def test_benign_normal_user_command_no_false_positive(self):
        """Người dùng thông thường chạy lệnh không đặc quyền KHÔNG ĐƯỢC báo động"""
        event = {
            "event_type": 1,
            "uid": 1000,
            "euid": 1000,
            "comm": "python",
            "filename": "/usr/bin/python3",
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)


if __name__ == "__main__":
    unittest.main()
