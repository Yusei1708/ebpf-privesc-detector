"""
tests/test_collector.py: Unit tests cho BPFCollector, ABI struct CEvent (200B),
xử lý sự kiện từ Ring Buffer, quyền CapEff và cơ chế cleanup idempotent.
"""

import io
import sys
import ctypes
import signal
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch
from contextlib import redirect_stdout, redirect_stderr

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.collector import CEvent, BPFCollector
from agent.features import FLAG_EXEC_FAILED


class _FakePerCpuMap:
    """Giả lập BPF_PERCPU_ARRAY map chấp nhận key ctypes.c_uint32(0)."""

    def __init__(self, values):
        self.values = values

    def __getitem__(self, key):
        idx = int(getattr(key, "value", key))
        if idx == 0:
            return self.values
        raise KeyError(idx)


class TestBPFCollector(unittest.TestCase):
    def test_cevent_size_and_exact_field_offsets(self):
        """CEvent phải khớp chính xác 200 bytes và offset từng trường với struct event_t trong probes.c."""
        self.assertEqual(ctypes.sizeof(CEvent), 200)
        self.assertEqual(CEvent.event_type.offset, 0)
        self.assertEqual(CEvent.pid.offset, 4)
        self.assertEqual(CEvent.tgid.offset, 8)
        self.assertEqual(CEvent.ppid.offset, 12)
        self.assertEqual(CEvent.uid.offset, 16)
        self.assertEqual(CEvent.euid.offset, 20)
        self.assertEqual(CEvent.cap.offset, 24)
        self.assertEqual(CEvent.flags.offset, 28)
        self.assertEqual(CEvent.cgroup_id.offset, 32)
        self.assertEqual(CEvent.pidns_id.offset, 40)
        self.assertEqual(CEvent.timestamp_ns.offset, 48)
        self.assertEqual(CEvent.comm.offset, 56)
        self.assertEqual(CEvent.filename.offset, 72)

    def test_init_does_not_clobber_signal_handlers_and_validates_pages(self):
        """__init__ không ghi đè signal handler toàn cục và kiểm tra ringbuf_pages lũy thừa của 2."""
        orig_int = signal.getsignal(signal.SIGINT)
        orig_term = signal.getsignal(signal.SIGTERM)

        collector = BPFCollector(perf_page_cnt=128)
        self.assertEqual(collector.ringbuf_pages, 128)
        self.assertEqual(signal.getsignal(signal.SIGINT), orig_int)
        self.assertEqual(signal.getsignal(signal.SIGTERM), orig_term)

        with self.assertRaises(ValueError):
            BPFCollector(ringbuf_pages=0)
        with self.assertRaises(ValueError):
            BPFCollector(ringbuf_pages=3)

    def test_process_event_execve_and_callback_stats(self):
        """_process_event xử lý EVENT_EXECVE, cập nhật exe_path và tăng alerts_triggered khi callback trả kết quả."""
        seen = []

        def on_event(ev, vec, raw, ext):
            seen.append((ev, vec, raw))
            return {"rule_name": "TEST_RULE"}

        collector = BPFCollector(event_callback=on_event)
        cev = CEvent(
            event_type=1,
            pid=1001,
            tgid=1001,
            ppid=1000,
            uid=1000,
            euid=1000,
            cap=0,
            flags=0,
            cgroup_id=4096,
            pidns_id=4026531836,
            timestamp_ns=10_000_000_000,
            comm=b"payload",
            filename=b"/tmp/payload",
        )
        collector._process_event(None, ctypes.pointer(cev), ctypes.sizeof(CEvent))

        self.assertEqual(collector.stats["events_processed"], 1)
        self.assertEqual(collector.stats["alerts_triggered"], 1)
        self.assertEqual(collector.stats["callback_errors"], 0)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][2]["suspicious_path_flag"], 1)
        self.assertEqual(collector.extractor.process_tree[1001].exe_path, "/tmp/payload")

    def test_process_event_failed_exec_reverts_exe_path(self):
        """FLAG_EXEC_FAILED trên sys_exit_execve phải hoàn tác exe_path đầu cơ và không gọi callback."""
        cb_calls = []
        collector = BPFCollector(event_callback=lambda *args: cb_calls.append(args) or None)

        ev_base = CEvent(
            event_type=1,
            pid=1002,
            tgid=1002,
            ppid=1000,
            uid=1000,
            euid=1000,
            timestamp_ns=10_000_000_000,
            comm=b"bash",
            filename=b"/usr/bin/bash",
        )
        ev_spec = CEvent(
            event_type=1,
            pid=1002,
            tgid=1002,
            ppid=1000,
            uid=1000,
            euid=1000,
            timestamp_ns=10_100_000_000,
            comm=b"evil",
            filename=b"/tmp/nonexistent",
        )
        ev_fail = CEvent(
            event_type=1,
            pid=1002,
            tgid=1002,
            ppid=1000,
            uid=1000,
            euid=1000,
            flags=FLAG_EXEC_FAILED,
            timestamp_ns=10_200_000_000,
            comm=b"bash",
            filename=b"",
        )

        collector._process_event(None, ctypes.pointer(ev_base), ctypes.sizeof(CEvent))
        collector._process_event(None, ctypes.pointer(ev_spec), ctypes.sizeof(CEvent))
        self.assertEqual(collector.extractor.process_tree[1002].exe_path, "/tmp/nonexistent")

        collector._process_event(None, ctypes.pointer(ev_fail), ctypes.sizeof(CEvent))
        self.assertEqual(len(cb_calls), 2)
        node = collector.extractor.process_tree[1002]
        self.assertEqual(node.exe_path, "/usr/bin/bash")
        self.assertFalse(node.ever_suspicious_path)
        self.assertEqual(len(collector.extractor.event_windows[1002]), 1)

    def test_process_event_fork_and_exit_callbacks(self):
        """EVENT_PROCESS_FORK kế thừa lineage/exe_path và EVENT_PROCESS_EXIT gọi exit_callback."""
        exited_pids = []
        collector = BPFCollector(exit_callback=exited_pids.append)

        ev_parent = CEvent(
            event_type=1,
            pid=2000,
            tgid=2000,
            ppid=1,
            uid=33,
            euid=33,
            timestamp_ns=20_000_000_000,
            comm=b"nginx",
            filename=b"/usr/sbin/nginx",
        )
        ev_fork = CEvent(
            event_type=6,
            pid=2001,
            tgid=2001,
            ppid=2000,
            uid=33,
            euid=33,
            timestamp_ns=20_100_000_000,
            comm=b"nginx",
            filename=b"",
        )
        ev_exit = CEvent(
            event_type=5,
            pid=2001,
            tgid=2001,
            ppid=2000,
            uid=33,
            euid=33,
            timestamp_ns=21_000_000_000,
            comm=b"nginx",
            filename=b"",
        )

        collector._process_event(None, ctypes.pointer(ev_parent), ctypes.sizeof(CEvent))
        collector._process_event(None, ctypes.pointer(ev_fork), ctypes.sizeof(CEvent))

        child = collector.extractor.process_tree[2001]
        self.assertEqual(child.ppid, 2000)
        self.assertEqual(child.exe_path, "/usr/sbin/nginx")
        self.assertTrue(child.has_service_ancestor)
        self.assertEqual(collector.extractor.get_process_lineage(2001), ["nginx(2000)"])

        collector._process_event(None, ctypes.pointer(ev_exit), ctypes.sizeof(CEvent))
        self.assertTrue(collector.extractor.process_tree[2001].exited)
        self.assertEqual(exited_pids, [2001])

    def test_process_event_guards_short_buffer_bad_utf8_and_callback_exception(self):
        """Kiểm tra short-buffer guard, decode UTF-8 lỗi an toàn và cô lập ngoại lệ callback."""
        def failing_cb(*args):
            raise RuntimeError("boom")

        collector = BPFCollector(event_callback=failing_cb)
        cev = CEvent(
            event_type=1,
            pid=3001,
            tgid=3001,
            ppid=1,
            uid=1000,
            euid=1000,
            timestamp_ns=30_000_000_000,
            comm=b"bad\xff\xfe",
            filename=b"/tmp/\x80\xffbin",
        )

        # Short buffer bị bỏ qua ngay
        collector._process_event(None, ctypes.pointer(cev), ctypes.sizeof(CEvent) - 1)
        self.assertEqual(collector.stats["events_processed"], 0)

        # Buffer hợp lệ với UTF-8 lỗi + callback ném exception -> không làm sập agent
        with redirect_stderr(io.StringIO()):
            collector._process_event(None, ctypes.pointer(cev), ctypes.sizeof(CEvent))

        self.assertEqual(collector.stats["events_processed"], 1)
        self.assertEqual(collector.stats["callback_errors"], 1)
        self.assertIn("\ufffd", collector.extractor.process_tree[3001].comm)

    def test_has_bpf_privileges_root_and_capeff(self):
        """Kiểm tra _has_bpf_privileges cho EUID==0, CAP_BPF+CAP_PERFMON, CAP_SYS_ADMIN và thiếu quyền."""
        collector = BPFCollector()

        with patch("agent.collector.os.geteuid", return_value=0):
            self.assertTrue(collector._has_bpf_privileges())

        # CAP_PERFMON (bit 38) + CAP_BPF (bit 39) = 0xc000000000
        with patch("agent.collector.os.geteuid", return_value=1000), patch(
            "builtins.open", mock_open(read_data="Name:\tpython\nCapEff:\t000000c000000000\n")
        ):
            self.assertTrue(collector._has_bpf_privileges())

        # CAP_SYS_ADMIN (bit 21) = 0x200000
        with patch("agent.collector.os.geteuid", return_value=1000), patch(
            "builtins.open", mock_open(read_data="CapEff:\t0000000000200000\n")
        ):
            self.assertTrue(collector._has_bpf_privileges())

        # Chỉ có CAP_BPF (thiếu CAP_PERFMON) -> từ chối
        with patch("agent.collector.os.geteuid", return_value=1000), patch(
            "builtins.open", mock_open(read_data="CapEff:\t0000008000000000\n")
        ):
            self.assertFalse(collector._has_bpf_privileges())

        # start() trả về False khi không đủ quyền
        with patch.object(collector, "_has_bpf_privileges", return_value=False), redirect_stderr(io.StringIO()):
            self.assertFalse(collector.start())

    def test_cleanup_drop_rate_logging_and_idempotency(self):
        """cleanup() đồng bộ dropped_events, in drop-rate chính xác và an toàn khi gọi nhiều lần."""
        collector = BPFCollector()
        collector.running = True
        collector.stats["events_processed"] = 95

        mock_bpf = MagicMock()
        mock_bpf.__getitem__.return_value = _FakePerCpuMap([ctypes.c_uint64(2), ctypes.c_uint64(3)])
        collector.bpf = mock_bpf

        buf = io.StringIO()
        with redirect_stdout(buf):
            collector.cleanup()
            collector.cleanup()

        output = buf.getvalue()
        mock_bpf.cleanup.assert_called_once()
        self.assertIsNone(collector.bpf)
        self.assertFalse(collector.running)
        self.assertEqual(collector.stats["events_lost"], 5)
        self.assertIn("processed=95", output)
        self.assertIn("lost=5 (5.00% drop)", output)


if __name__ == "__main__":
    unittest.main()
