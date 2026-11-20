"""
tests/test_rules.py: Unit tests kiểm thử 8 luật phát hiện (PRIVESC-001..008),
Tầng 2 ML (classify_ml_tier2, evaluate_ml, _load_models checksum/n_features_in_),
và LRU cooldown cache.
"""

import io
import os
import sys
import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from contextlib import redirect_stderr
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.detector import (
    PrivEscDetector,
    classify_ml_tier2,
    COOLDOWN_CACHE_MAX_SIZE,
)
from agent.features import (
    FeatureExtractor,
    FLAG_OPEN_WRITE,
    FLAG_CRED_CAP_GAIN,
    FLAG_CAP_USERNS,
    CAP_DAC_OVERRIDE,
    CAP_SETUID,
    CAP_SYS_MODULE,
    CAP_SYS_ADMIN,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestDetectionRules(unittest.TestCase):
    def setUp(self):
        self._empty_models_dir = tempfile.TemporaryDirectory()
        self.host_pidns = 4026531836
        self.host_mntns = 4026531840
        self.detector = PrivEscDetector(
            models_dir=self._empty_models_dir.name,
            quiet=True,
            host_pidns_id=self.host_pidns,
            host_mntns_id=self.host_mntns,
        )

    def tearDown(self):
        self._empty_models_dir.cleanup()

    def test_privesc_001_euid_jump_and_cap_only_gain(self):
        """PRIVESC-001: Bắt commit_creds EUID=0 hoặc cap-only gain (FLAG_CRED_CAP_GAIN)."""
        ev_uid = {"event_type": 2, "uid": 1000, "euid": 0, "comm": "bad_bin", "filename": "/usr/local/bin/bad_bin"}
        hit, match = self.detector.evaluate_rules(ev_uid, {"uid_change_flag": 1, "is_whitelisted_bin": 0})
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-001")
        self.assertEqual(match.severity, "CRITICAL")

        ev_cap = {
            "event_type": 2,
            "uid": 1000,
            "euid": 1000,
            "flags": FLAG_CRED_CAP_GAIN,
            "comm": "cap_raise",
            "filename": "/usr/local/bin/cap_raise",
        }
        hit2, match2 = self.detector.evaluate_rules(ev_cap, {"uid_change_flag": 0, "is_whitelisted_bin": 0})
        self.assertTrue(hit2)
        self.assertEqual(match2.rule_id, "PRIVESC-001")

    def test_privesc_002_and_003_suid_and_suspicious_path(self):
        """PRIVESC-002 (GTFOBins SUID) & PRIVESC-003 (thực thi từ /tmp với đặc quyền)."""
        ev_gtfo = {"event_type": 1, "uid": 1000, "euid": 0, "comm": "find", "filename": "/usr/bin/find"}
        hit2, match2 = self.detector.evaluate_rules(
            ev_gtfo, {"uid_change_flag": 1, "is_whitelisted_bin": 0, "suspicious_path_flag": 0}
        )
        self.assertTrue(hit2)
        self.assertEqual(match2.rule_id, "PRIVESC-002")

        ev_tmp = {"event_type": 1, "uid": 0, "euid": 0, "comm": "exploit", "filename": "/tmp/cve.elf"}
        hit3, match3 = self.detector.evaluate_rules(
            ev_tmp, {"uid_change_flag": 0, "is_whitelisted_bin": 0, "suspicious_path_flag": 1}
        )
        self.assertTrue(hit3)
        self.assertEqual(match3.rule_id, "PRIVESC-003")
        self.assertEqual(match3.severity, "HIGH")

    def test_privesc_004_webshell_vs_root_daemon_zero_fp(self):
        """PRIVESC-004: Webshell (kể cả gọi sudo whitelist) bị bắt; root daemon bình thường không FP."""
        ev_web_sudo = {"event_type": 1, "uid": 33, "euid": 0, "comm": "sudo", "filename": "/usr/bin/sudo"}
        hit, match = self.detector.evaluate_rules(
            ev_web_sudo, {"uid_change_flag": 1, "is_whitelisted_bin": 1, "service_parent_flag": 1}
        )
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-004")

        ev_root_child = {"event_type": 1, "uid": 0, "euid": 0, "comm": "nginx", "filename": "/usr/sbin/nginx"}
        hit_fp, match_fp = self.detector.evaluate_rules(
            ev_root_child, {"uid_change_flag": 0, "is_whitelisted_bin": 0, "service_parent_flag": 1}
        )
        self.assertFalse(hit_fp)
        self.assertIsNone(match_fp)

    def test_privesc_005_normalization_write_filter_and_auth_daemon_exemption(self):
        """PRIVESC-005: Chuẩn hóa đường dẫn, write-only cho ld.so.preload/passwd, miễn trừ auth daemon root."""
        ev_norm = {"event_type": 4, "uid": 1000, "euid": 0, "comm": "cat", "filename": "///etc/../etc/shadow"}
        hit, match = self.detector.evaluate_rules(ev_norm, {"uid_change_flag": 1, "is_whitelisted_bin": 0})
        self.assertTrue(hit)
        self.assertEqual(match.rule_id, "PRIVESC-005")
        self.assertEqual(match.mitre_id, "T1003.008")

        # Read-only /etc/ld.so.preload -> không cảnh báo; Write -> PRIVESC-005 T1574.006
        ev_preload_read = {"event_type": 4, "uid": 1000, "euid": 1000, "flags": 0, "comm": "ld", "filename": "/etc/ld.so.preload"}
        hit_r, _ = self.detector.evaluate_rules(ev_preload_read, {"suspicious_path_flag": 1, "is_whitelisted_bin": 0})
        self.assertFalse(hit_r)

        ev_preload_write = {
            "event_type": 4,
            "uid": 1000,
            "euid": 1000,
            "flags": FLAG_OPEN_WRITE,
            "comm": "ld",
            "filename": "/etc/ld.so.preload",
        }
        hit_w, match_w = self.detector.evaluate_rules(ev_preload_write, {"suspicious_path_flag": 0, "is_whitelisted_bin": 0})
        self.assertTrue(hit_w)
        self.assertEqual(match_w.rule_id, "PRIVESC-005")
        self.assertEqual(match_w.mitre_id, "T1574.006")

        # Trusted root auth daemon (/usr/sbin/sshd đọc /etc/shadow) -> miễn trừ
        ext = FeatureExtractor()
        ext.update_process(pid=777, ppid=1, comm="sshd", uid=0, euid=0, cgroup_id=0, exe_path="/usr/sbin/sshd")
        ev_sshd = {"event_type": 4, "tgid": 777, "uid": 0, "euid": 0, "flags": 0, "comm": "sshd", "filename": "/etc/shadow"}
        hit_auth, _ = self.detector.evaluate_rules(ev_sshd, {"is_whitelisted_bin": 0}, extractor=ext)
        self.assertFalse(hit_auth)

    def test_privesc_006_correlated_dac_override_and_userns_suppression(self):
        """PRIVESC-006: Bắt correlated_cap_probe, CAP_DAC_OVERRIDE và bỏ qua khi có FLAG_CAP_USERNS."""
        ev_corr = {"event_type": 3, "uid": 1000, "euid": 1000, "comm": "probe", "cap": CAP_SYS_ADMIN, "flags": 0}
        hit_corr, match_corr = self.detector.evaluate_rules(
            ev_corr, {"cap_check_count": 5, "sensitive_file_access": 1, "is_whitelisted_bin": 0}
        )
        self.assertTrue(hit_corr)
        self.assertEqual(match_corr.rule_id, "PRIVESC-006")

        ev_dac = {"event_type": 3, "uid": 1000, "euid": 1000, "comm": "reader", "cap": CAP_DAC_OVERRIDE, "flags": 0}
        hit_dac, match_dac = self.detector.evaluate_rules(
            ev_dac, {"sensitive_file_access": 1, "is_whitelisted_bin": 0}
        )
        self.assertTrue(hit_dac)
        self.assertEqual(match_dac.rule_id, "PRIVESC-006")

        ev_userns = {
            "event_type": 3,
            "uid": 1000,
            "euid": 1000,
            "comm": "unshare",
            "cap": CAP_SETUID,
            "flags": FLAG_CAP_USERNS,
        }
        hit_uns, _ = self.detector.evaluate_rules(ev_userns, {"suspicious_path_flag": 1, "is_whitelisted_bin": 0})
        self.assertFalse(hit_uns)

        # Kiểm tra không false positive khi thiếu ngữ cảnh rủi ro hoặc là cap=10 / uid=0
        hit_cap10, _ = self.detector.evaluate_rules(
            {"event_type": 3, "uid": 1000, "euid": 1000, "comm": "srv", "cap": 10}, {"suspicious_path_flag": 1}
        )
        self.assertFalse(hit_cap10)
        hit_nocapctx, _ = self.detector.evaluate_rules(
            {"event_type": 3, "uid": 1000, "euid": 1000, "comm": "chromium", "cap": CAP_SYS_ADMIN},
            {"cap_check_count": 8, "sensitive_file_access": 0},
        )
        self.assertFalse(hit_nocapctx)

    def test_privesc_007_container_escape_and_pid_host(self):
        """PRIVESC-007: Bắt CAP_SYS_MODULE/CAP_SYS_ADMIN trong container (kể cả --pid=host), bỏ qua ở host/userns."""
        ev_mod = {
            "event_type": 3,
            "uid": 0,
            "euid": 0,
            "cap": CAP_SYS_MODULE,
            "flags": 0,
            "pidns_id": self.host_pidns + 999,
            "comm": "sh",
        }
        hit_mod, match_mod = self.detector.evaluate_rules(ev_mod, {"is_whitelisted_bin": 0})
        self.assertTrue(hit_mod)
        self.assertEqual(match_mod.rule_id, "PRIVESC-007")
        self.assertEqual(match_mod.mitre_id, "T1611")

        # Container dùng --pid=host (pidns trùng host nhưng mntns khác host)
        ev_pidhost = {
            "event_type": 3,
            "uid": 0,
            "euid": 0,
            "cap": CAP_SYS_ADMIN,
            "flags": 0,
            "pidns_id": self.host_pidns,
            "mntns_id": self.host_mntns + 500,
            "comm": "esc",
        }
        hit_ph, match_ph = self.detector.evaluate_rules(ev_pidhost, {"suspicious_path_flag": 1, "is_whitelisted_bin": 0})
        self.assertTrue(hit_ph)
        self.assertEqual(match_ph.rule_id, "PRIVESC-007")

        # Trên Host thực tế -> không kích hoạt PRIVESC-007
        ev_host = {**ev_mod, "pidns_id": self.host_pidns, "mntns_id": self.host_mntns}
        hit_host, _ = self.detector.evaluate_rules(ev_host, {"is_whitelisted_bin": 0})
        self.assertFalse(hit_host)

    def test_privesc_008_fileless_exec(self):
        """PRIVESC-008: Bắt thực thi fileless qua memfd, execveat(fd), /proc/*/fd/*."""
        for fpath in ("/memfd:payload", "(execveat:fd)", "/proc/self/fd/3"):
            ev = {"event_type": 1, "uid": 1000, "euid": 1000, "comm": "loader", "filename": fpath}
            hit, match = self.detector.evaluate_rules(ev, {"is_whitelisted_bin": 0})
            self.assertTrue(hit)
            self.assertEqual(match.rule_id, "PRIVESC-008")
            self.assertEqual(match.severity, "HIGH")
            self.assertEqual(match.mitre_id, "T1620")

    def test_highest_severity_across_multiple_matches(self):
        """matches[0] giữ luật đặc hiệu nhất (PRIVESC-005 HIGH) nhưng rule_sev/highest_severity phải là CRITICAL."""
        event = {
            "event_type": 4,
            "tgid": 444,
            "uid": 33,
            "euid": 0,
            "flags": 0,
            "pidns_id": self.host_pidns,
            "comm": "exploit",
            "filename": "/etc/shadow",
        }
        raw_feat = {
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 1,
        }
        res = self.detector.analyze(event, np.zeros(8, dtype=np.float32), raw_feat)
        self.assertIsNotNone(res)
        self.assertEqual(res["matched_rules"][0], "PRIVESC-005")
        self.assertIn("PRIVESC-004", res["matched_rules"])
        self.assertEqual(res["rule_sev"], "CRITICAL")
        self.assertEqual(res["highest_severity"], "CRITICAL")
        self.assertGreaterEqual(res["threat_score"], 95)

    def test_classify_ml_tier2_evaluate_ml_classes_nan_and_errors(self):
        """Kiểm tra classify_ml_tier2, classes_ đảo thứ tự, NaN/Inf sanitization và ml_errors counter."""
        self.assertTrue(classify_ml_tier2(0.65, 0.1, False))
        self.assertFalse(classify_ml_tier2(0.64, 0.1, False))
        self.assertTrue(classify_ml_tier2(0.40, -0.05, True))
        self.assertTrue(classify_ml_tier2(0.20, -0.18, True))
        self.assertFalse(classify_ml_tier2(0.19, -0.25, True))

        # Thiếu model -> (0.0, 0.0, False)
        self.assertEqual(self.detector.evaluate_ml(np.zeros(8, dtype=np.float32)), (0.0, 0.0, False))

        # Mock models với classes_ = [1, 0] (nhãn 1 ở cột 0)
        self.detector.scaler = MagicMock()
        self.detector.scaler.transform.side_effect = lambda x: x
        self.detector.rf_model = MagicMock()
        self.detector.rf_model.classes_ = np.array([1, 0])
        self.detector.rf_model.predict_proba.return_value = np.array([[0.25, 0.75]])
        self.detector.iso_model = MagicMock()
        self.detector.iso_model.decision_function.return_value = np.array([-0.25])
        self.detector.iso_model.predict.return_value = np.array([-1])

        nan_vec = np.array([np.nan, np.inf, -np.inf, 0, 0, 0, 0, 1.0], dtype=np.float32)
        rf_prob, iso_score, is_anom = self.detector.evaluate_ml(nan_vec)
        self.assertAlmostEqual(rf_prob, 0.25, places=5)
        self.assertAlmostEqual(iso_score, -0.25, places=5)
        self.assertTrue(is_anom)
        self.assertEqual(self.detector.ml_errors, 0)

        # ML-only path khi không khớp rule nhưng Tầng 2 kích hoạt
        ml_res = self.detector.analyze(
            {"event_type": 1, "tgid": 888, "uid": 1000, "euid": 1000, "comm": "weird", "filename": "/usr/bin/weird"},
            nan_vec,
            {"uid_change_flag": 0, "is_whitelisted_bin": 0, "suspicious_path_flag": 0, "service_parent_flag": 0},
        )
        self.assertIsNotNone(ml_res)
        self.assertTrue(ml_res["is_ml_anomaly"])
        self.assertEqual(ml_res["rule_name"], "N/A")
        self.assertGreaterEqual(ml_res["threat_score"], 60)

        # Ngoại lệ trong suy luận ML tăng ml_errors
        self.detector.rf_model.predict_proba.side_effect = RuntimeError("bad shape")
        with redirect_stderr(io.StringIO()):
            res_err = self.detector.evaluate_ml(np.zeros(8, dtype=np.float32))
        self.assertEqual(res_err, (0.0, 0.0, False))
        self.assertEqual(self.detector.ml_errors, 1)

    def test_cooldown_per_ruleset_clear_and_lru_eviction(self):
        """Cooldown tách biệt theo tập rule, dọn qua clear_process_cooldown/exit và giới hạn 4096 mục."""
        cd_det = PrivEscDetector(
            models_dir=self._empty_models_dir.name,
            alert_cooldown_seconds=5.0,
            quiet=True,
            host_pidns_id=self.host_pidns,
            host_mntns_id=self.host_mntns,
        )
        vec = np.zeros(8, dtype=np.float32)
        raw = {"uid_change_flag": 1, "is_whitelisted_bin": 0, "suspicious_path_flag": 0, "service_parent_flag": 0}
        ev_exec = {"event_type": 1, "tgid": 999, "uid": 1000, "euid": 0, "comm": "find", "filename": "/usr/bin/find", "timestamp": 100.0}
        ev_open = {"event_type": 4, "tgid": 999, "uid": 1000, "euid": 0, "comm": "find", "filename": "/etc/shadow", "timestamp": 101.0}

        # PRIVESC-002 tại t=100, rồi PRIVESC-005+002 tại t=101 -> không bị triệt tiêu vì tập rule khác
        self.assertIsNotNone(cd_det.analyze(ev_exec, vec, raw))
        self.assertIsNotNone(cd_det.analyze(ev_open, vec, raw))
        # Lặp lại chính PRIVESC-005+002 trong cooldown -> bị triệt tiêu
        self.assertIsNone(cd_det.analyze({**ev_open, "timestamp": 102.0}, vec, raw))
        self.assertEqual(cd_det.suppressed_alerts, 1)

        # EVENT_PROCESS_EXIT xóa cooldown của tgid=999
        self.assertIsNone(cd_det.analyze({"event_type": 5, "tgid": 999, "timestamp": 102.5}, vec, raw))
        self.assertIsNotNone(cd_det.analyze({**ev_open, "timestamp": 103.0}, vec, raw))

        # Vượt ngưỡng COOLDOWN_CACHE_MAX_SIZE (4096) -> cắt theo LRU
        for pid_i in range(2000, 2000 + COOLDOWN_CACHE_MAX_SIZE + 50):
            cd_det.analyze(
                {"event_type": 1, "tgid": pid_i, "uid": 1000, "euid": 0, "comm": "find", "filename": "/usr/bin/find", "timestamp": 200.0},
                vec,
                raw,
            )
        self.assertEqual(len(cd_det._last_alert_ts), COOLDOWN_CACHE_MAX_SIZE)

    def test_load_models_checksum_legacy_and_shape_validation(self):
        """Kiểm tra _load_models(): cảnh báo artifact thiếu checksum, fail khi sai SHA-256 hoặc sai n_features_in_."""
        rng = np.random.default_rng(0)
        X8 = rng.normal(size=(20, 8))
        y8 = np.array([0] * 10 + [1] * 10)
        scaler = StandardScaler().fit(X8)
        rf = RandomForestClassifier(n_estimators=5, random_state=0).fit(scaler.transform(X8), y8)
        iso = IsolationForest(n_estimators=5, random_state=0).fit(scaler.transform(X8[:10]))

        with tempfile.TemporaryDirectory() as tmp_dir:
            mdir = Path(tmp_dir)
            os.chmod(mdir, 0o755)
            for name, obj in (("scaler.joblib", scaler), ("random_forest.joblib", rf), ("isolation_forest.joblib", iso)):
                p = mdir / name
                joblib.dump(obj, p)
                os.chmod(p, 0o644)

            # 1. Legacy summary không có model_checksums -> nạp được kèm cảnh báo stderr
            summary_path = mdir / "dataset_summary.json"
            summary_path.write_text(json.dumps({"n_samples": 20}), encoding="utf-8")
            os.chmod(summary_path, 0o644)
            err_buf = io.StringIO()
            with redirect_stderr(err_buf):
                det_legacy = PrivEscDetector(models_dir=tmp_dir, quiet=False, allow_untrusted_models=True)
            self.assertIsNotNone(det_legacy.rf_model)
            self.assertFalse(det_legacy.checksum_verified)

            # 2. Checksum SHA-256 hợp lệ -> checksum_verified == True
            checksums = {
                fn: _sha256_file(mdir / fn)
                for fn in ("scaler.joblib", "random_forest.joblib", "isolation_forest.joblib")
            }
            summary_path.write_text(json.dumps({"model_checksums": checksums}), encoding="utf-8")
            det_ok = PrivEscDetector(models_dir=tmp_dir, quiet=True, allow_untrusted_models=True)
            self.assertIsNotNone(det_ok.rf_model)
            self.assertTrue(det_ok.checksum_verified)

            # 3. Sai SHA-256 -> từ chối nạp toàn bộ mô hình
            bad_checksums = dict(checksums)
            bad_checksums["random_forest.joblib"] = "0" * 64
            summary_path.write_text(json.dumps({"model_checksums": bad_checksums}), encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                det_bad = PrivEscDetector(models_dir=tmp_dir, quiet=True, allow_untrusted_models=True)
            self.assertIsNone(det_bad.scaler)
            self.assertIsNone(det_bad.rf_model)
            self.assertIsNone(det_bad.iso_model)
            self.assertFalse(det_bad.checksum_verified)

            # 4. Sai n_features_in_ (4 thay vì 8) dù checksum khớp -> từ chối nạp
            X4 = rng.normal(size=(20, 4))
            bad_scaler = StandardScaler().fit(X4)
            joblib.dump(bad_scaler, mdir / "scaler.joblib")
            os.chmod(mdir / "scaler.joblib", 0o644)
            checksums["scaler.joblib"] = _sha256_file(mdir / "scaler.joblib")
            summary_path.write_text(json.dumps({"model_checksums": checksums}), encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                det_shape = PrivEscDetector(models_dir=tmp_dir, quiet=True, allow_untrusted_models=True)
            self.assertIsNone(det_shape.scaler)
            self.assertIsNone(det_shape.rf_model)


if __name__ == "__main__":
    unittest.main()
