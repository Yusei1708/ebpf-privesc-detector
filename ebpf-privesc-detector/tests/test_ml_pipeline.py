"""
tests/test_ml_pipeline.py: Unit tests kiểm thử quy trình nạp telemetry (JSONL/CSV),
sắp xếp theo phiên, replay ngoại tuyến, benchmark parser và huấn luyện ml/train.py.
"""

import io
import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import FEATURE_NAMES, extract_explicit_timestamp
from agent.detector import PrivEscDetector, run_replay
from benchmarks.benchmark_agent_vs_auditd import parse_proc_stat_jiffies, parse_proc_stat_fields
from ml.telemetry_loader import TelemetryLoader, TelemetryValidationError
from ml.train import train_models


class TestMLPipeline(unittest.TestCase):
    def setUp(self):
        self.loader = TelemetryLoader()

    def test_schema_loads_successfully(self):
        """Schema JSON định nghĩa telemetry phải tồn tại và đọc được."""
        schema = self.loader.schema
        self.assertIn("required", schema)
        self.assertIn("properties", schema)
        self.assertIn("tgid", schema["required"])
        self.assertIn("label", schema["required"])
        self.assertIn("session_id", schema["required"])
        self.assertEqual(schema["properties"]["event_type"]["enum"], [1, 2, 3, 4, 5, 6])

    def test_convert_events_to_features_values(self):
        """Chuyển đổi chuỗi sự kiện telemetry thành bảng 8 đặc trưng với giá trị tính toán chính xác."""
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
        self.assertEqual(df["exec_count"].iloc[1], 1)
        self.assertEqual(df["uid_change_flag"].iloc[1], 1)
        self.assertEqual(df["is_whitelisted_bin"].iloc[1], 0)
        self.assertEqual(df["sensitive_file_access"].iloc[1], 1)
        self.assertAlmostEqual(float(df["priv_syscall_rate"].iloc[1]), round(2 / 3.0, 4), places=4)
        self.assertEqual(df["label"].iloc[0], 1)
        self.assertEqual(df["session_id"].iloc[0], "test_session_1")

    def test_load_jsonl_comments_and_malformed_json(self):
        """load_jsonl bỏ qua dòng trống/# comment và báo lỗi JSONDecodeError kèm số dòng."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test.jsonl"
            valid_rec = {
                "timestamp_iso": "2026-10-23T12:00:00Z",
                "event_type": 6,
                "tgid": 2000,
                "pid": 2000,
                "ppid": 1,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "session_id": "session_valid_01",
                "label": 0,
            }
            p.write_text("# comment\n" + json.dumps(valid_rec) + "\n{bad json\n", encoding="utf-8")

            with self.assertRaises(TelemetryValidationError) as ctx:
                self.loader.load_jsonl(str(p))
            self.assertEqual(ctx.exception.line_number, 3)
            self.assertEqual(ctx.exception.field, "json_syntax")

            # Unlabeled replay (require_label=False)
            p_unlabeled = Path(tmp) / "unlabeled.jsonl"
            unlabeled_rec = {k: v for k, v in valid_rec.items() if k != "label"}
            p_unlabeled.write_text(json.dumps(unlabeled_rec) + "\n", encoding="utf-8")
            unlabeled_loader = TelemetryLoader(require_label=False)
            records = unlabeled_loader.load_jsonl(str(p_unlabeled))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["event_type"], 6)

    def test_load_csv_precision_blanks_and_error_cases(self):
        """load_csv bảo toàn số nguyên >53-bit timestamp_ns, bỏ qua blank optionals và bắt lỗi CSV rỗng/sai cột/UTF-8."""
        with tempfile.TemporaryDirectory() as tmp:
            csv_ok = Path(tmp) / "valid.csv"
            csv_ok.write_text(
                "timestamp_ns,event_type,tgid,pid,ppid,uid,euid,cap,flags,comm,filename,session_id,label\n"
                "1700000000123456789,1,2000,2000,1,1000,1000,,,ls,/usr/bin/ls,sess_csv,0\n",
                encoding="utf-8",
            )
            recs = self.loader.load_csv(str(csv_ok))
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["timestamp_ns"], 1700000000123456789)
            self.assertNotIn("cap", recs[0])
            self.assertNotIn("flags", recs[0])

            csv_empty = Path(tmp) / "empty.csv"
            csv_empty.write_text("", encoding="utf-8")
            with self.assertRaises(TelemetryValidationError) as ctx_e:
                self.loader.load_csv(str(csv_empty))
            self.assertEqual(ctx_e.exception.field, "csv_format")

            csv_bad_cols = Path(tmp) / "badcols.csv"
            csv_bad_cols.write_text(
                "timestamp_ns,event_type,tgid,pid,uid,euid,comm,session_id,label\n"
                "1700000000000000000,1,2000,2000,1000,1000,ls,sess_csv,0,EXTRA\n",
                encoding="utf-8",
            )
            with self.assertRaises(TelemetryValidationError) as ctx_c:
                self.loader.load_csv(str(csv_bad_cols))
            self.assertEqual(ctx_c.exception.field, "csv_format")

            csv_bad_utf8 = Path(tmp) / "bad_utf8.csv"
            csv_bad_utf8.write_bytes(b"timestamp_ns,event_type\n\xff\xfe,1\n")
            with self.assertRaises(TelemetryValidationError) as ctx_u:
                self.loader.load_csv(str(csv_bad_utf8))
            self.assertEqual(ctx_u.exception.field, "csv_encoding")

    def test_validation_rules_ids_lengths_timestamps_and_alerts(self):
        """Kiểm tra từ chối alert log, event_type sai (miền [1..6]), tgid=0, độ dài chuỗi và mọi timestamp có mặt."""
        base = {
            "timestamp_iso": "2026-10-23T12:00:00Z",
            "event_type": 1,
            "tgid": 2000,
            "pid": 2000,
            "uid": 1000,
            "euid": 1000,
            "comm": "ls",
            "filename": "/usr/bin/ls",
            "session_id": "sess_01",
            "label": 0,
        }

        with self.assertRaises(TelemetryValidationError) as ctx_al:
            self.loader.validate_record({"threat_score": 85, "matched_rules": ["PRIVESC-001"]}, 1)
        self.assertEqual(ctx_al.exception.field, "format")

        for field, bad_val in (
            ("event_type", 99),
            ("tgid", 0),
            ("pid", 0),
            ("uid", -1),
            ("flags", -5),
            ("label", True),
            ("comm", "x" * 17),
            ("filename", "y" * 257),
            ("filename", 12345),
            ("timestamp_ns", "not_int"),
            ("timestamp", float("nan")),
            ("timestamp_iso", "not-iso"),
        ):
            rec = dict(base)
            rec[field] = bad_val
            with self.assertRaises(TelemetryValidationError, msg=f"Kỳ vọng lỗi cho {field}={bad_val}") as ctx:
                self.loader.validate_record(rec, 1)
            self.assertEqual(ctx.exception.field, field)

        # Kiểm tra thứ tự ưu tiên timestamp: timestamp_ns -> timestamp -> timestamp_iso
        ts_multi = {"timestamp_ns": 5_000_000_000, "timestamp": 100.0, "timestamp_iso": "2026-10-23T12:00:00Z"}
        self.assertAlmostEqual(extract_explicit_timestamp(ts_multi), 5.0, places=6)
        self.assertAlmostEqual(extract_explicit_timestamp({"timestamp": 100.0, "timestamp_iso": "2026-10-23T12:00:00Z"}), 100.0, places=6)

    def test_iter_session_features_sorting_fork_first_exit_last(self):
        """iter_session_features sắp xếp cùng timestamp đặt PROCESS_FORK(6) đầu tiên và PROCESS_EXIT(5) cuối cùng."""
        exited = []
        # Truyền đảo thứ tự tại cùng timestamp=100.0: OPENAT -> EXECVE -> EXIT -> FORK
        events = [
            {
                "timestamp": 100.0,
                "event_type": 4,
                "tgid": 4001,
                "pid": 4001,
                "ppid": 4000,
                "uid": 33,
                "euid": 33,
                "comm": "sh",
                "filename": "/etc/shadow",
                "session_id": "sess_sort",
                "label": 1,
            },
            {
                "timestamp": 100.0,
                "event_type": 5,
                "tgid": 4001,
                "pid": 4001,
                "ppid": 4000,
                "uid": 33,
                "euid": 33,
                "comm": "sh",
                "session_id": "sess_sort",
                "label": 0,
            },
            {
                "timestamp": 100.0,
                "event_type": 6,
                "tgid": 4001,
                "pid": 4001,
                "ppid": 4000,
                "uid": 33,
                "euid": 33,
                "comm": "sh",
                "session_id": "sess_sort",
                "label": 0,
            },
            {
                "timestamp": 99.0,
                "event_type": 1,
                "tgid": 4000,
                "pid": 4000,
                "ppid": 1,
                "uid": 33,
                "euid": 33,
                "comm": "nginx",
                "filename": "/usr/sbin/nginx",
                "session_id": "sess_sort",
                "label": 0,
            },
        ]
        yielded = list(self.loader.iter_session_features(events, on_exit=exited.append))
        # Chỉ có nginx(1) và sh openat(4); fork(6) & exit(5) không yield
        self.assertEqual(len(yielded), 2)
        self.assertEqual(yielded[0][1]["event_type"], 1)
        self.assertEqual(yielded[1][1]["event_type"], 4)
        self.assertEqual(yielded[1][3]["service_parent_flag"], 1)
        self.assertEqual(exited, [4001])

    def test_cross_session_pid_isolation_no_leakage(self):
        """Hai phiên khác nhau trùng TGID (pid=1001) không được rò rỉ cửa sổ trượt hay exe_path."""
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
        self.assertEqual(df.iloc[1]["exec_count"], 1)
        self.assertEqual(df.iloc[1]["is_whitelisted_bin"], 0)

    def test_sample_telemetry_rules_only_replay(self):
        """sample_telemetry.jsonl (31 dòng, 8 session, 30 sự kiện phân tích) đạt TP=10, FP=0, TN=20, FN=0 với rules-only."""
        sample_path = PROJECT_ROOT / "ml" / "data" / "sample_telemetry.jsonl"
        self.assertTrue(sample_path.exists())

        records = self.loader.load_jsonl(str(sample_path))
        self.assertEqual(len(records), 31)

        with tempfile.TemporaryDirectory() as empty_models, redirect_stdout(io.StringIO()):
            summary = run_replay(
                str(sample_path),
                alert_log_path=None,
                quiet=True,
                models_dir=empty_models,
                host_pidns_id=4026531836,
                host_mntns_id=4026531840,
            )

        self.assertEqual(summary["sessions"], 8)
        self.assertEqual(summary["evaluated_events"], 30)
        self.assertEqual(summary["tp"], 10)
        self.assertEqual(summary["fp"], 0)
        self.assertEqual(summary["tn"], 20)
        self.assertEqual(summary["fn"], 0)

    def test_train_models_validation_errors_and_hermetic_ml_replay(self):
        """Kiểm thử train.py (--check-only, dữ liệu nhỏ/thiếu lớp/thiếu session, đuôi sai) và replay ML hermetic."""
        sample_path = PROJECT_ROOT / "ml" / "data" / "sample_telemetry.jsonl"

        with redirect_stdout(io.StringIO()):
            # --check-only trả về None và không ghi đè model
            self.assertIsNone(train_models(telemetry_file=str(sample_path), check_only=True))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Unsupported extension
            bad_ext = tmp_path / "data.txt"
            bad_ext.write_text("hi", encoding="utf-8")
            with self.assertRaises(ValueError):
                train_models(telemetry_file=str(bad_ext))

            base_rec = {
                "timestamp_iso": "2026-10-23T12:00:00Z",
                "event_type": 1,
                "tgid": 2000,
                "pid": 2000,
                "uid": 1000,
                "euid": 1000,
                "comm": "ls",
                "session_id": "s1",
                "label": 0,
            }

            # <10 mẫu
            small_f = tmp_path / "small.jsonl"
            small_f.write_text("\n".join(json.dumps(base_rec) for _ in range(5)) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                train_models(telemetry_file=str(small_f))

            # <2 sessions
            one_sess = tmp_path / "one_sess.jsonl"
            one_sess.write_text("\n".join(json.dumps(base_rec) for _ in range(12)) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                train_models(telemetry_file=str(one_sess))

            # Chỉ có 1 nhãn
            single_lbl = tmp_path / "single_lbl.jsonl"
            rows = [json.dumps({**base_rec, "session_id": f"s{i % 3}"}) for i in range(12)]
            single_lbl.write_text("\n".join(rows) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                train_models(telemetry_file=str(single_lbl))

            # <5 benign trong tập train (ngay cả khi có >=4 sessions)
            few_benign = tmp_path / "few_benign.jsonl"
            fb_rows = [json.dumps({**base_rec, "session_id": "benign_s1", "label": 0}) for _ in range(2)]
            fb_rows += [json.dumps({**base_rec, "session_id": "benign_s2", "label": 0}) for _ in range(2)]
            fb_rows += [json.dumps({**base_rec, "session_id": "atk_s1", "label": 1}) for _ in range(5)]
            fb_rows += [json.dumps({**base_rec, "session_id": "atk_s2", "label": 1}) for _ in range(5)]
            few_benign.write_text("\n".join(fb_rows) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                train_models(telemetry_file=str(few_benign))

            # Huấn luyện hermetic vào out_dir rồi replay bằng model mới huấn luyện
            out_dir = tmp_path / "hermetic_models"
            with redirect_stdout(io.StringIO()):
                train_summary = train_models(output_dir=str(out_dir))
                self.assertIsNotNone(train_summary)
                self.assertIn("combined_tier2_metrics", train_summary)
                self.assertIn("model_checksums", train_summary)
                self.assertEqual(len(train_summary["model_checksums"]), 3)
                self.assertTrue((out_dir / "dataset_summary.json").exists())

                det = PrivEscDetector(
                    models_dir=str(out_dir),
                    quiet=True,
                    allow_untrusted_models=True,
                    host_pidns_id=4026531836,
                    host_mntns_id=4026531840,
                )
                self.assertTrue(det.checksum_verified)
                self.assertIsNotNone(det.rf_model)

                ml_replay = run_replay(
                    str(sample_path),
                    alert_log_path=None,
                    quiet=True,
                    models_dir=str(out_dir),
                    host_pidns_id=4026531836,
                    host_mntns_id=4026531840,
                    allow_untrusted_models=True,
                )

            self.assertEqual(ml_replay["evaluated_events"], 30)
            self.assertEqual(ml_replay["tp"], 10)
            self.assertEqual(ml_replay["fn"], 0)
            self.assertEqual(ml_replay["fp"], 0)

    def test_benchmark_proc_stat_parser_with_spaces_and_parens(self):
        """Parser /proc/<pid>/stat lấy đúng jiffies và starttime (field 22) khi comm chứa dấu ngoặc & khoảng trắng."""
        fake_stat = "4321 (Isolated Web (1)) R 1000 4321 1000 0 -1 4194304 100 0 0 0 150 25 0 0 20 0 1 0 12345"
        self.assertEqual(parse_proc_stat_jiffies(fake_stat), 175)
        self.assertEqual(parse_proc_stat_fields(fake_stat), (175, 12345))


if __name__ == "__main__":
    unittest.main()
