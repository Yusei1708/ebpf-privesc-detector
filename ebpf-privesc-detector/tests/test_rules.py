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

    def test_rule_privileged_capability_probe_correlated(self):
        """PRIVESC-006: Bắt kiểm tra CAP_SETUID (cap=7) khi có tín hiệu rủi ro ngữ cảnh (ví dụ: chạy từ /tmp)"""
        event = {
            "event_type": 3,  # cap_capable
            "uid": 1000,
            "euid": 1000,
            "comm": "exploit",
            "cap": 7,  # CAP_SETUID theo Linux UAPI
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,  # Ngữ cảnh nghi vấn: thực thi từ thư mục tạm
            "service_parent_flag": 0,
            "priv_syscall_rate": 0.5,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-006")
        self.assertEqual(match.severity, "MEDIUM")

    def test_cap_net_bind_service_10_not_treated_as_setuid(self):
        """Giá trị cap=10 (CAP_NET_BIND_SERVICE) không bị nhầm là CAP_SETUID (7)"""
        event = {
            "event_type": 3,
            "uid": 1000,
            "euid": 1000,
            "comm": "server",
            "cap": 10,
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)

    def test_rule_privileged_capability_probe_benign_no_context(self):
        """PRIVESC-006: cap_capable thông thường không có ngữ cảnh rủi ro KHÔNG ĐƯỢC báo động giả"""
        event = {
            "event_type": 3,  # cap_capable
            "uid": 1000,
            "euid": 1000,
            "comm": "systemd",
            "cap": 21,  # CAP_SYS_ADMIN
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "priv_syscall_rate": 0.5,  # Tần suất thấp, đường dẫn sạch
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)

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

    def test_benign_root_daemon_cap_checks_no_false_positive(self):
        """Daemon chạy sẵn dưới quyền root (uid=0) kiểm tra CAP_SYS_ADMIN nhiều lần KHÔNG bị cảnh báo sai"""
        event = {
            "event_type": 3,
            "uid": 0,
            "euid": 0,
            "comm": "systemd",
            "cap": 21,
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "cap_check_count": 10,
            "sensitive_file_access": 2,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)

    def test_unprivileged_cap_checks_only_no_alert(self):
        """Chỉ gọi cap_capable lặp lại mà không có sự kiện/ngữ cảnh rủi ro liên quan KHÔNG phát cảnh báo kết luận"""
        event = {
            "event_type": 3,
            "uid": 1000,
            "euid": 1000,
            "comm": "chromium",
            "cap": 21,
        }
        raw_feat = {
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "cap_check_count": 8,
            "sensitive_file_access": 0,
        }
        hit, match = self.detector.evaluate_rules(event, raw_feat)
        self.assertFalse(hit)
        self.assertIsNone(match)

    def test_no_rule_shadowing_evaluate_all_rules(self):
        """Các luật đặc hiệu (PRIVESC-005, 004, 003) không bị PRIVESC-002 che khuất và trả đủ matched_rules"""
        event = {
            "event_type": 4,
            "uid": 33,
            "euid": 0,
            "comm": "exploit",
            "filename": "/etc/shadow",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 1,
        }
        matches = self.detector.evaluate_all_rules(event, raw_feat)
        rule_ids = [m.rule_id for m in matches]
        self.assertEqual(rule_ids[0], "PRIVESC-005")
        self.assertIn("PRIVESC-004", rule_ids)
        self.assertIn("PRIVESC-003", rule_ids)
        self.assertIn("PRIVESC-002", rule_ids)

    def test_spoofed_tmp_sudo_cannot_bypass_rules(self):
        """Nhị phân giả mạo /tmp/sudo vẫn phải kích hoạt luật dù raw_features không truyền sẵn is_whitelisted_bin"""
        event = {
            "event_type": 1,
            "uid": 1000,
            "euid": 0,
            "comm": "sudo",
            "filename": "/tmp/sudo",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
        }
        matches = self.detector.evaluate_all_rules(event, raw_feat)
        rule_ids = [m.rule_id for m in matches]
        self.assertEqual(rule_ids[0], "PRIVESC-003")
        self.assertIn("PRIVESC-002", rule_ids)

    def test_alert_cooldown_suppresses_duplicates(self):
        """Chống bão cảnh báo (cooldown) cho cùng (tgid, rule_id) trong khoảng thời gian cấu hình"""
        cooldown_detector = PrivEscDetector(alert_cooldown_seconds=5.0, quiet=True)
        feat_vec = np.array([4, 1, 0, 0, 0, 1, 1, 2.0], dtype=np.float32)
        raw_feat = {
            "exec_count": 4,
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "sensitive_file_access": 1,
            "cap_check_count": 1,
            "priv_syscall_rate": 2.0,
        }

        ev1 = {"event_type": 1, "tgid": 999, "pid": 999, "uid": 1000, "euid": 0, "comm": "find", "filename": "/usr/bin/find", "timestamp": 100.0}
        ev2 = {**ev1, "timestamp": 101.5}  # Trong khoảng cooldown 5s -> bị triệt tiêu
        ev3 = {**ev1, "timestamp": 106.0}  # Sau 5s -> cảnh báo lại bình thường

        self.assertIsNotNone(cooldown_detector.analyze(ev1, feat_vec, raw_feat))
        self.assertIsNone(cooldown_detector.analyze(ev2, feat_vec, raw_feat))
        self.assertEqual(cooldown_detector.suppressed_alerts, 1)
        self.assertIsNotNone(cooldown_detector.analyze(ev3, feat_vec, raw_feat))

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
