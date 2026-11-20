"""
tests/test_features.py: Unit tests kiểm thử trích xuất 8 đặc trưng, sliding window,
kế thừa fork(), hoàn tác execve thất bại, chuẩn hóa đường dẫn và xử lý PID reuse.
"""

import sys
import ctypes
import unittest
from pathlib import Path
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.collector import CEvent
from agent.features import (
    FeatureExtractor,
    FEATURE_NAMES,
    FLAG_OPEN_WRITE,
    FLAG_EXEC_FAILED,
    SERVICE_PARENT_NAMES,
    CAP_SETUID,
    is_whitelisted_binary,
    is_suspicious_path,
    is_fileless_exec_path,
    is_sensitive_open_target,
    is_service_comm,
)


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_size_seconds=3.0)

    def test_cevent_abi_alignment_200_bytes(self):
        """Đảm bảo struct CEvent Python khớp chính xác 200 bytes căn chỉnh 8-byte với probes.c."""
        self.assertEqual(ctypes.sizeof(CEvent), 200)

    def test_feature_names_exact_order_and_vector_alignment(self):
        """Kiểm tra chính xác thứ tự 8 đặc trưng và khớp vị trí với vector từ extract_features()."""
        expected_order = [
            "exec_count",
            "uid_change_flag",
            "is_whitelisted_bin",
            "suspicious_path_flag",
            "service_parent_flag",
            "sensitive_file_access",
            "cap_check_count",
            "priv_syscall_rate",
        ]
        self.assertEqual(FEATURE_NAMES, expected_order)

        tgid = 55
        self.extractor.update_process(pid=tgid, ppid=1, comm="nginx", uid=33, euid=33, cgroup_id=0, event_time=10.0)
        child_tgid = 56
        ev_exec = {
            "event_type": 1,
            "tgid": child_tgid,
            "ppid": tgid,
            "uid": 33,
            "euid": 0,
            "comm": "sh",
            "filename": "/tmp/payload",
            "timestamp": 10.5,
        }
        ev_open = {
            "event_type": 4,
            "tgid": child_tgid,
            "ppid": tgid,
            "uid": 33,
            "euid": 0,
            "comm": "sh",
            "filename": "/etc/shadow",
            "timestamp": 11.0,
        }
        self.extractor.add_event(ev_exec)
        self.extractor.add_event(ev_open)
        vec, raw_feat = self.extractor.extract_features(child_tgid, ev_open)

        self.assertEqual(len(vec), len(FEATURE_NAMES))
        for idx, fname in enumerate(FEATURE_NAMES):
            self.assertAlmostEqual(float(vec[idx]), float(raw_feat[fname]), places=5)

    def test_whitelisted_binary_fail_closed_and_deleted_rejected(self):
        """is_whitelisted_binary() fail-closed khi thiếu exe_path và từ chối đường dẫn ' (deleted)'."""
        self.assertFalse(is_whitelisted_binary("", "sudo"))
        self.assertFalse(is_whitelisted_binary("   ", "sudo"))
        self.assertFalse(is_whitelisted_binary("/usr/bin/sudo (deleted)", "sudo"))
        self.assertFalse(is_whitelisted_binary("/tmp/sudo", "sudo"))
        self.assertFalse(is_whitelisted_binary("/usr/bin/../../tmp/sudo", "sudo"))
        self.assertTrue(is_whitelisted_binary("/usr/bin/sudo", "sudo"))

        ev_sudo = {"event_type": 1, "tgid": 100, "comm": "sudo", "filename": "/usr/bin/sudo"}
        _, feat_sudo = self.extractor.extract_features(100, ev_sudo)
        self.assertEqual(feat_sudo["is_whitelisted_bin"], 1)

        ev_no_exe = {"event_type": 2, "tgid": 102, "comm": "sudo", "filename": ""}
        _, feat_no_exe = self.extractor.extract_features(102, ev_no_exe)
        self.assertEqual(feat_no_exe["is_whitelisted_bin"], 0)

        ev_find = {"event_type": 1, "tgid": 101, "comm": "find", "filename": "/usr/bin/find"}
        _, feat_find = self.extractor.extract_features(101, ev_find)
        self.assertEqual(feat_find["is_whitelisted_bin"], 0)

    def test_uid_change_flag(self):
        """Phát hiện chuyển quyền từ UID != 0 sang EUID == 0."""
        tgid = 200
        self.extractor.update_process(pid=tgid, ppid=1, comm="bash", uid=1000, euid=1000, cgroup_id=0, mntns_id=0)

        ev1 = {"event_type": 1, "tgid": tgid, "uid": 1000, "euid": 1000, "comm": "id"}
        _, f1 = self.extractor.extract_features(tgid, ev1)
        self.assertEqual(f1["uid_change_flag"], 0)

        ev_priv = {"event_type": 2, "tgid": tgid, "uid": 1000, "euid": 0, "comm": "exploit"}
        self.extractor.add_event(ev_priv)
        self.extractor.update_process(pid=tgid, ppid=1, comm="exploit", uid=1000, euid=0, cgroup_id=0, mntns_id=0)

        _, f2 = self.extractor.extract_features(tgid, ev_priv)
        self.assertEqual(f2["uid_change_flag"], 1)

    def test_suspicious_and_fileless_paths(self):
        """Kiểm tra thư mục nghi vấn (/tmp, /dev/mqueue, /run/shm, /run/user) và đường dẫn fileless."""
        for p in (
            "/tmp/payload.elf",
            "//tmp/x",
            "/var/tmp/drop",
            "/dev/shm/run",
            "/run/user/1000/x",
            "/run/shm/x",
            "/dev/mqueue/p",
            "/memfd:payload",
            "(execveat:fd)",
            "/proc/self/fd/3",
            "/proc/4321/fd/7",
        ):
            self.assertTrue(is_suspicious_path(p), f"Kỳ vọng nghi vấn cho {p}")

        for p in ("(execveat:fd)", "/memfd:payload", "/proc/self/fd/3", "/proc/4321/fd/7"):
            self.assertTrue(is_fileless_exec_path(p), f"Kỳ vọng fileless cho {p}")
        self.assertFalse(is_fileless_exec_path("/dev/mqueue/p"))
        self.assertFalse(is_suspicious_path("/tmpfoo/innocent"))
        self.assertFalse(is_suspicious_path("/home/user/sudo"))
        self.assertFalse(is_suspicious_path("/usr/bin/git"))

    def test_sensitive_open_target_and_write_filter(self):
        """is_sensitive_open_target() kiểm tra chuẩn hóa POSIX và yêu cầu FLAG_OPEN_WRITE cho /etc/passwd & ld.so.preload."""
        self.assertTrue(is_sensitive_open_target("/etc/shadow"))
        self.assertTrue(is_sensitive_open_target("///etc/shadow"))
        self.assertTrue(is_sensitive_open_target("/etc/../etc/gshadow"))
        self.assertTrue(is_sensitive_open_target("/etc/sudoers"))
        self.assertTrue(is_sensitive_open_target("/etc/sudoers.d/custom"))

        # Write-only targets
        self.assertFalse(is_sensitive_open_target("/etc/ld.so.preload", flags=None))
        self.assertFalse(is_sensitive_open_target("/etc/ld.so.preload", flags=0))
        self.assertTrue(is_sensitive_open_target("/etc/ld.so.preload", flags=FLAG_OPEN_WRITE))
        self.assertFalse(is_sensitive_open_target("/etc/passwd", flags=None))
        self.assertFalse(is_sensitive_open_target("/etc/passwd", flags=0))
        self.assertTrue(is_sensitive_open_target("/etc/passwd", flags=FLAG_OPEN_WRITE))

        tgid = 500
        self.extractor.add_event({"event_type": 4, "tgid": tgid, "filename": "/etc/passwd", "flags": 0, "timestamp": 10.0})
        self.extractor.add_event({"event_type": 4, "tgid": tgid, "filename": "/etc/passwd", "flags": FLAG_OPEN_WRITE, "timestamp": 10.1})
        self.extractor.add_event({"event_type": 4, "tgid": tgid, "filename": "/etc/ld.so.preload", "flags": 0, "timestamp": 10.2})
        self.extractor.add_event({"event_type": 4, "tgid": tgid, "filename": "/etc/ld.so.preload", "flags": FLAG_OPEN_WRITE, "timestamp": 10.3})
        _, feat = self.extractor.extract_features(tgid)
        self.assertEqual(feat["sensitive_file_access"], 2)

    def test_fork_inheritance_and_revert_failed_exec(self):
        """register_fork kế thừa exe_path/lineage; revert_failed_exec hoàn tác exe_path và ever_suspicious_path."""
        self.extractor.add_event({
            "event_type": 1,
            "tgid": 450,
            "ppid": 1,
            "uid": 1000,
            "euid": 1000,
            "comm": "dropper",
            "filename": "/tmp/dropper",
            "timestamp": 10.0,
        })
        self.extractor.add_event({
            "event_type": 6,
            "tgid": 451,
            "ppid": 450,
            "uid": 1000,
            "euid": 1000,
            "comm": "child",
            "timestamp": 10.1,
        })
        child = self.extractor.process_tree[451]
        self.assertEqual(child.exe_path, "/tmp/dropper")
        self.assertTrue(child.ever_suspicious_path)

        # Tiến trình sạch thử execve vào /tmp thất bại -> revert_failed_exec hoàn tác sạch
        self.extractor.add_event({
            "event_type": 1,
            "tgid": 460,
            "ppid": 1,
            "uid": 1000,
            "euid": 1000,
            "comm": "bash",
            "filename": "/usr/bin/bash",
            "timestamp": 20.0,
        })
        self.extractor.add_event({
            "event_type": 1,
            "tgid": 460,
            "ppid": 1,
            "uid": 1000,
            "euid": 1000,
            "comm": "bash",
            "filename": "/tmp/missing_bin",
            "timestamp": 20.1,
        })
        self.assertEqual(self.extractor.process_tree[460].exe_path, "/tmp/missing_bin")
        self.assertTrue(self.extractor.process_tree[460].ever_suspicious_path)

        self.extractor.add_event({
            "event_type": 1,
            "tgid": 460,
            "ppid": 1,
            "flags": FLAG_EXEC_FAILED,
            "timestamp": 20.2,
        })
        self.assertEqual(self.extractor.process_tree[460].exe_path, "/usr/bin/bash")
        self.assertFalse(self.extractor.process_tree[460].ever_suspicious_path)
        _, feat = self.extractor.extract_features(460)
        self.assertEqual(feat["exec_count"], 1)
        self.assertEqual(feat["suspicious_path_flag"], 0)

    def test_lineage_depth_limit_cycles_and_versioned_service_comms(self):
        """get_process_lineage() giới hạn max_depth=5, chống vòng lặp và is_service_comm nhận diện tên theo phiên bản."""
        self.assertTrue(is_service_comm("python3.14"))
        self.assertTrue(is_service_comm("python2.7"))
        self.assertTrue(is_service_comm("php-fpm8.3"))
        self.assertTrue(is_service_comm("php8.2"))
        self.assertTrue(is_service_comm("nodejs"))
        self.assertFalse(is_service_comm("bash"))

        for idx in range(7):
            pid = 5000 + idx
            ppid = 1 if idx == 0 else (pid - 1)
            self.extractor.update_process(
                pid=pid, ppid=ppid, comm=f"p{idx}", uid=1000, euid=1000, cgroup_id=0, event_time=10.0 + idx
            )
        lineage = self.extractor.get_process_lineage(5006, max_depth=5)
        self.assertEqual(lineage, ["p1(5001)", "p2(5002)", "p3(5003)", "p4(5004)", "p5(5005)"])

        # Tạo vòng lặp phả hệ: 6000 <-> 6001
        self.extractor.update_process(pid=6000, ppid=6001, comm="a", uid=1000, euid=1000, cgroup_id=0, event_time=10.0)
        self.extractor.update_process(pid=6001, ppid=6000, comm="b", uid=1000, euid=1000, cgroup_id=0, event_time=10.1)
        self.assertEqual(self.extractor.get_process_lineage(6001, max_depth=5), ["a(6000)"])

    def test_service_parent_lineage_and_original_ppid_across_reparenting(self):
        """original_ppid và service_parent_flag được bảo toàn khi tiến trình bị reparent sang PID 1."""
        self.extractor.update_process(pid=400, ppid=1, comm="python3.14", uid=33, euid=33, cgroup_id=0, event_time=10.0)
        self.extractor.update_process(pid=401, ppid=400, comm="sh", uid=33, euid=33, cgroup_id=0, event_time=10.2)
        # Reparent sang init PID 1
        self.extractor.update_process(pid=401, ppid=1, comm="sh", uid=33, euid=33, cgroup_id=0, event_time=10.4)
        self.assertEqual(self.extractor.process_tree[401].original_ppid, 400)

        ev_child = {"event_type": 1, "tgid": 401, "comm": "sh", "filename": "/bin/sh", "timestamp": 10.5}
        _, f_child = self.extractor.extract_features(401, ev_child)
        self.assertEqual(f_child["service_parent_flag"], 1)

    def test_cap_check_count_and_unified_priv_syscall_rate(self):
        """cap_check_count và priv_syscall_rate = round(n / window_size, 4) đồng nhất giữa raw_features & vector[7]."""
        tgid = 600
        for idx, cap in enumerate([CAP_SETUID, 21]):
            self.extractor.add_event({"event_type": 3, "tgid": tgid, "cap": cap, "timestamp": 10.0 + idx * 0.1})
        vec, f = self.extractor.extract_features(tgid)
        self.assertEqual(f["cap_check_count"], 2)
        expected_rate = round(2 / 3.0, 4)
        self.assertEqual(f["priv_syscall_rate"], expected_rate)
        self.assertAlmostEqual(float(vec[7]), expected_rate, places=4)

    def test_spoofed_whitelisted_bin_and_sticky_suspicious_path(self):
        """Giả mạo /tmp/sudo bị từ chối và suspicious_path_flag dính suốt vòng đời ngay cả sau khi chạy binary khác."""
        ev_tmp_sudo = {
            "event_type": 1,
            "tgid": 610,
            "comm": "sudo",
            "filename": "/tmp/sudo",
            "timestamp": 100.0,
        }
        self.extractor.add_event(ev_tmp_sudo)
        _, f1 = self.extractor.extract_features(610, ev_tmp_sudo)
        self.assertEqual(f1["is_whitelisted_bin"], 0)
        self.assertEqual(f1["suspicious_path_flag"], 1)

        # Ngủ >3s rồi mở /etc/shadow vẫn giữ sticky suspicious_path_flag == 1
        ev_later = {
            "event_type": 4,
            "tgid": 610,
            "uid": 1000,
            "euid": 0,
            "comm": "sudo",
            "filename": "/etc/shadow",
            "timestamp": 105.0,
        }
        self.extractor.add_event(ev_later)
        _, feat = self.extractor.extract_features(610, ev_later)
        self.assertEqual(feat["suspicious_path_flag"], 1)
        self.assertEqual(feat["is_whitelisted_bin"], 0)

    def test_interactive_shell_and_container_runtime_not_service_parents(self):
        """sh/bash/dockerd/containerd không kích hoạt nhầm service_parent_flag, nhưng nginx -> bash -> sh vẫn bắt được."""
        for non_svc in ("sh", "bash", "dockerd", "containerd"):
            self.assertNotIn(non_svc, SERVICE_PARENT_NAMES)

        self.extractor.update_process(pid=640, ppid=1, comm="bash", uid=1000, euid=1000, cgroup_id=0, event_time=10.0)
        self.extractor.update_process(pid=641, ppid=640, comm="sh", uid=1000, euid=1000, cgroup_id=0, event_time=10.5)
        _, f_user = self.extractor.extract_features(641, {"event_type": 1, "tgid": 641, "comm": "sh", "filename": "/bin/sh", "timestamp": 10.5})
        self.assertEqual(f_user["service_parent_flag"], 0)

        self.extractor.update_process(pid=650, ppid=1, comm="nginx", uid=33, euid=33, cgroup_id=0, event_time=10.0)
        self.extractor.update_process(pid=651, ppid=650, comm="bash", uid=33, euid=33, cgroup_id=0, event_time=10.2)
        self.extractor.update_process(pid=652, ppid=651, comm="sh", uid=33, euid=0, cgroup_id=0, event_time=10.4)
        _, f_web = self.extractor.extract_features(652, {"event_type": 1, "tgid": 652, "comm": "sh", "filename": "/bin/sh", "timestamp": 10.4})
        self.assertEqual(f_web["service_parent_flag"], 1)

    def test_cleanup_exited_ttl_and_max_processes_cap(self):
        """exited_ttl_seconds=15.0 dọn node đã thoát đúng hạn và max_processes giới hạn bộ nhớ."""
        self.extractor.add_event({"event_type": 1, "tgid": 701, "comm": "a", "filename": "/usr/bin/ls", "timestamp": 100.0})
        self.extractor.add_event({"event_type": 5, "tgid": 701, "comm": "a", "timestamp": 101.0})
        self.extractor.add_event({"event_type": 1, "tgid": 702, "comm": "b", "filename": "/usr/bin/ls", "timestamp": 105.0})

        # Tại t=111.0 (sau thoát 10s <= 15s), node 701 vẫn còn để con truy vết
        self.extractor.cleanup_old_processes(reference_time=111.0)
        self.assertIn(701, self.extractor.process_tree)
        self.assertIn(702, self.extractor.process_tree)

        # Tại t=117.0 (sau thoát 16s > 15s), node 701 bị dọn nhưng node đang chạy 702 vẫn còn
        self.extractor.cleanup_old_processes(reference_time=117.0)
        self.assertNotIn(701, self.extractor.process_tree)
        self.assertIn(702, self.extractor.process_tree)

        capped = FeatureExtractor(max_processes=2)
        capped.add_event({"event_type": 1, "tgid": 1, "comm": "p1", "filename": "/bin/ls", "timestamp": 1.0})
        capped.add_event({"event_type": 5, "tgid": 1, "comm": "p1", "timestamp": 2.0})
        capped.add_event({"event_type": 1, "tgid": 2, "comm": "p2", "filename": "/bin/ls", "timestamp": 3.0})
        capped.add_event({"event_type": 1, "tgid": 3, "comm": "p3", "filename": "/bin/ls", "timestamp": 4.0})
        self.assertEqual(len(capped.process_tree), 2)
        self.assertNotIn(1, capped.process_tree)

    def test_add_event_live_vs_replay_parity(self):
        """Đường chạy replay (chỉ gọi add_event) và live (update_process + add_event) cho vector đặc trưng đồng nhất."""
        events = [
            {"event_type": 1, "tgid": 801, "ppid": 1, "uid": 1000, "euid": 1000, "comm": "find", "filename": "/usr/bin/find", "timestamp": 10.0},
            {"event_type": 2, "tgid": 801, "ppid": 1, "uid": 1000, "euid": 0, "comm": "find", "timestamp": 10.2},
            {"event_type": 4, "tgid": 801, "ppid": 1, "uid": 1000, "euid": 0, "comm": "find", "filename": "/etc/shadow", "timestamp": 10.4},
        ]
        ext_replay = FeatureExtractor(window_size_seconds=3.0)
        ext_live = FeatureExtractor(window_size_seconds=3.0)

        for ev in events:
            ext_replay.add_event(ev)

            ext_live.update_process(
                pid=ev["tgid"],
                ppid=ev["ppid"],
                comm=ev["comm"],
                uid=ev["uid"],
                euid=ev["euid"],
                cgroup_id=0,
                event_time=ev["timestamp"],
                exe_path=ev.get("filename") if ev["event_type"] == 1 else None,
                event_type=ev["event_type"],
            )
            ext_live.add_event(ev)

        vec_r, raw_r = ext_replay.extract_features(801, events[-1])
        vec_l, raw_l = ext_live.extract_features(801, events[-1])
        self.assertEqual(raw_r, raw_l)
        self.assertTrue(np.allclose(vec_r, vec_l))

    def test_reparenting_vs_pid_reuse_and_window_pruning(self):
        """Phân biệt reparenting ngắn hạn với idle >300s và kiểm tra sliding window pruning."""
        tgid = 700
        self.extractor.update_process(pid=tgid, ppid=500, comm="worker", uid=1000, euid=1000, cgroup_id=0, event_time=100.0)
        self.extractor.add_event({"event_type": 1, "tgid": tgid, "comm": "worker", "timestamp": 100.0})
        self.extractor.update_process(pid=tgid, ppid=1, comm="worker", uid=1000, euid=1000, cgroup_id=0, event_time=120.0)
        self.assertEqual(self.extractor.initial_uids[tgid], 1000)

        self.extractor.update_process(pid=tgid, ppid=999, comm="root_proc", uid=0, euid=0, cgroup_id=0, event_time=450.0)
        self.assertEqual(self.extractor.initial_uids[tgid], 0)
        self.assertNotIn(tgid, self.extractor.event_windows)

        # Sliding window pruning theo event timestamp
        w_tgid = 800
        self.extractor.add_event({"event_type": 1, "tgid": w_tgid, "timestamp": 1000.0})
        self.extractor.add_event({"event_type": 1, "tgid": w_tgid, "timestamp": 1001.0})
        self.extractor.add_event({"event_type": 1, "tgid": w_tgid, "timestamp": 1000.5})
        self.assertEqual([t for t, _ in self.extractor.event_windows[w_tgid]], [1000.0, 1000.5, 1001.0])

        self.extractor.add_event({"event_type": 1, "tgid": w_tgid, "timestamp": 1004.0})
        remaining_ts = [t for t, _ in self.extractor.event_windows[w_tgid]]
        self.assertEqual(remaining_ts, [1001.0, 1004.0])

    def test_max_window_events_cap_and_corrupted_data(self):
        """max_window_events chặn tràn RAM và dữ liệu khuyết thiếu không gây crash."""
        capped_ext = FeatureExtractor(window_size_seconds=10.0, max_window_events=4)
        for i in range(10):
            capped_ext.add_event({"event_type": 1, "tgid": 910, "timestamp": 100.0 + i * 0.1})
        self.assertEqual(len(capped_ext.event_windows[910]), 4)

        vec, feat = self.extractor.extract_features(900, {"event_type": None, "comm": None, "filename": None})
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), 8)
        self.assertEqual(feat["exec_count"], 0)


if __name__ == "__main__":
    unittest.main()
