"""
tests/test_features.py: Unit tests kiểm thử trích xuất 8 đặc trưng, sliding window và xử lý PID reuse
"""

import time
import unittest
import numpy as np

from agent.features import FeatureExtractor, FEATURE_NAMES, WHITELISTED_SUID_BINS


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_size_seconds=3.0)

    def test_feature_names_order(self):
        """Kiểm tra danh sách 8 đặc trưng chuẩn hóa"""
        self.assertEqual(len(FEATURE_NAMES), 8)
        self.assertIn("exec_count", FEATURE_NAMES)
        self.assertIn("uid_change_flag", FEATURE_NAMES)
        self.assertIn("is_whitelisted_bin", FEATURE_NAMES)
        self.assertIn("suspicious_path_flag", FEATURE_NAMES)
        self.assertIn("service_parent_flag", FEATURE_NAMES)
        self.assertIn("sensitive_file_access", FEATURE_NAMES)
        self.assertIn("cap_check_count", FEATURE_NAMES)
        self.assertIn("priv_syscall_rate", FEATURE_NAMES)

    def test_whitelisted_binary_semantics(self):
        """1 nếu nằm trong whitelist hợp lệ, 0 nếu không thuộc whitelist"""
        # Sudo hợp lệ
        ev_sudo = {"event_type": 1, "tgid": 100, "comm": "sudo", "filename": "/usr/bin/sudo"}
        _, feat_sudo = self.extractor.extract_features(100, ev_sudo)
        self.assertEqual(feat_sudo["is_whitelisted_bin"], 1)

        # Find (unwhitelisted)
        ev_find = {"event_type": 1, "tgid": 101, "comm": "find", "filename": "/usr/bin/find"}
        _, feat_find = self.extractor.extract_features(101, ev_find)
        self.assertEqual(feat_find["is_whitelisted_bin"], 0)

    def test_uid_change_flag(self):
        """Phát hiện chuyển quyền từ UID != 0 sang EUID == 0"""
        tgid = 200
        # Ban đầu là user thường (UID 1000)
        self.extractor.update_process(pid=tgid, ppid=1, comm="bash", uid=1000, euid=1000, cgroup_id=0, mntns_id=0)

        # Chưa chuyển quyền
        ev1 = {"event_type": 1, "tgid": tgid, "uid": 1000, "euid": 1000, "comm": "id"}
        _, f1 = self.extractor.extract_features(tgid, ev1)
        self.assertEqual(f1["uid_change_flag"], 0)

        # Chuyển quyền sang root (EUID 0) qua commit_creds
        ev_priv = {"event_type": 2, "tgid": tgid, "uid": 1000, "euid": 0, "comm": "exploit"}
        self.extractor.add_event(ev_priv)
        self.extractor.update_process(pid=tgid, ppid=1, comm="exploit", uid=1000, euid=0, cgroup_id=0, mntns_id=0)

        _, f2 = self.extractor.extract_features(tgid, ev_priv)
        self.assertEqual(f2["uid_change_flag"], 1)

    def test_suspicious_path_flag(self):
        """Phát hiện thực thi từ /tmp, /dev/shm, /var/tmp với kiểm tra ranh giới thư mục chính xác"""
        tgid = 300
        ev_tmp = {"event_type": 1, "tgid": tgid, "filename": "/tmp/payload.elf", "comm": "payload"}
        _, f_tmp = self.extractor.extract_features(tgid, ev_tmp)
        self.assertEqual(f_tmp["suspicious_path_flag"], 1)

        # Tránh dương tính giả: /tmpfoo không phải là /tmp/
        ev_false_prefix = {"event_type": 1, "tgid": 302, "filename": "/tmpfoo/innocent", "comm": "innocent"}
        _, f_false = self.extractor.extract_features(302, ev_false_prefix)
        self.assertEqual(f_false["suspicious_path_flag"], 0)

        ev_normal = {"event_type": 1, "tgid": 301, "filename": "/usr/bin/git", "comm": "git"}
        _, f_normal = self.extractor.extract_features(301, ev_normal)
        self.assertEqual(f_normal["suspicious_path_flag"], 0)

    def test_service_parent_lineage(self):
        """Phát hiện tiến trình cha hoặc tổ tiên là web/network daemon"""
        parent_tgid = 400
        child_tgid = 401

        # Tiến trình cha là nginx
        self.extractor.update_process(pid=parent_tgid, ppid=1, comm="nginx", uid=33, euid=33, cgroup_id=0, mntns_id=0)
        # Tiến trình con sinh ra từ nginx
        self.extractor.update_process(pid=child_tgid, ppid=parent_tgid, comm="sh", uid=33, euid=33, cgroup_id=0, mntns_id=0)

        ev_child = {"event_type": 1, "tgid": child_tgid, "comm": "sh", "filename": "/bin/sh"}
        _, f_child = self.extractor.extract_features(child_tgid, ev_child)
        self.assertEqual(f_child["service_parent_flag"], 1)

    def test_sensitive_file_access_count(self):
        """Đếm số lần yêu cầu mở /etc/shadow hoặc /etc/sudoers"""
        tgid = 500
        for _ in range(3):
            self.extractor.add_event({"event_type": 4, "tgid": tgid, "filename": "/etc/shadow"})
        _, f = self.extractor.extract_features(tgid)
        self.assertEqual(f["sensitive_file_access"], 3)

    def test_cap_check_count(self):
        """Đếm số lần kiểm tra capability"""
        tgid = 600
        for cap in [10, 21, 1]:
            self.extractor.add_event({"event_type": 3, "tgid": tgid, "cap": cap})
        _, f = self.extractor.extract_features(tgid)
        self.assertEqual(f["cap_check_count"], 3)

    def test_reparenting_vs_pid_reuse(self):
        """Phân biệt an toàn giữa reparenting (tiến trình cha chết) và tái sử dụng PID"""
        tgid = 700

        # Bước 1: Tiến trình khởi tạo bởi cha PPID 500
        self.extractor.update_process(pid=tgid, ppid=500, comm="worker", uid=1000, euid=1000, cgroup_id=0, mntns_id=0, event_time=100.0)
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "comm": "worker", "timestamp": 100.0})
        self.assertEqual(len(self.extractor.event_windows[tgid]), 1)

        # Bước 2: Tiến trình cha PPID 500 chết, Linux reparent tiến trình tgid sang PID 1 (init/systemd)
        # Đây KHÔNG PHẢI là PID reuse, không được xóa event_windows hay đổi initial_uid!
        self.extractor.update_process(pid=tgid, ppid=1, comm="worker", uid=1000, euid=1000, cgroup_id=0, mntns_id=0, event_time=101.0)
        self.assertEqual(self.extractor.initial_uids[tgid], 1000)
        self.assertEqual(len(self.extractor.event_windows[tgid]), 1)

        # Bước 3: Sau đó một tiến trình mới tái sử dụng PID 700 với UID khác (0) hoặc sau idle kéo dài
        self.extractor.update_process(pid=tgid, ppid=999, comm="root_proc", uid=0, euid=0, cgroup_id=0, mntns_id=0, event_time=120.0)
        self.assertEqual(self.extractor.initial_uids[tgid], 0)
        self.assertEqual(len(self.extractor.event_windows[tgid]), 0)

    def test_sliding_window_event_timestamp_pruning(self):
        """Kiểm tra cơ chế trượt cửa sổ dựa trên event timestamp (không dùng time.time())"""
        tgid = 800
        base_ts = 1000.0

        # Thêm sự kiện t=1000.0
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "timestamp": base_ts})
        # Thêm sự kiện t=1001.0
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "timestamp": base_ts + 1.0})
        # Thêm sự kiện đến trễ t=1000.5
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "timestamp": base_ts + 0.5})

        # Danh sách cửa sổ phải được sắp xếp theo thời gian
        timestamps = [t for t, _ in self.extractor.event_windows[tgid]]
        self.assertEqual(timestamps, [1000.0, 1000.5, 1001.0])

        # Khi sự kiện t=1004.0 xuất hiện, sự kiện t=1000.0 và t=1000.5 (cách > 3s) phải bị prune
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "timestamp": base_ts + 4.0})
        self.extractor._prune_window(tgid, current_time=base_ts + 4.0)

        remaining_ts = [t for t, _ in self.extractor.event_windows[tgid]]
        self.assertNotIn(1000.0, remaining_ts)
        self.assertNotIn(1000.5, remaining_ts)
        self.assertIn(1001.0, remaining_ts)
        self.assertIn(1004.0, remaining_ts)

    def test_corrupted_and_missing_data(self):
        """Kiểm tra khả năng chịu lỗi khi dữ liệu khuyết thiếu hoặc None"""
        tgid = 900
        ev_corrupted = {"event_type": None, "comm": None, "filename": None}
        vec, feat = self.extractor.extract_features(tgid, ev_corrupted)
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), 8)
        self.assertEqual(feat["exec_count"], 0)


if __name__ == "__main__":
    unittest.main()
