"""
ml/train.py: Huấn luyện mô hình Machine Learning phát hiện tấn công leo thang đặc quyền
Sử dụng kết hợp:
  1. Isolation Forest: Unsupervised Anomaly Detection (Phát hiện kỹ thuật zero-day / hành vi lạ)
  2. Random Forest: Supervised Classification (Phát hiện chính xác các mẫu tấn công đã biết)
Đảm bảo:
  - Sinh dữ liệu mô phỏng dạng event-stream và đi qua TelemetryLoader -> FeatureExtractor để xóa bỏ train-serving skew
  - Tách train/test theo session_id (GroupShuffleSplit) để chống rò rỉ dữ liệu (Data Leakage)
  - Đánh giá cả Random Forest lẫn ngưỡng kết hợp Tầng 2 (classify_ml_tier2)
  - Ghi model + dataset_summary.json nguyên tử (tempfile + os.replace) kèm SHA-256 model_checksums
"""

import os
import sys
import json
import hashlib
import tempfile
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import (
    FEATURE_NAMES,
    FLAG_OPEN_WRITE,
    FLAG_CRED_UID_GAIN,
    CAP_DAC_OVERRIDE,
    CAP_SETUID,
    CAP_NET_ADMIN,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_ADMIN,
)

MODELS_DIR = PROJECT_ROOT / "ml" / "models"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _atomic_joblib_dump(obj: Any, dest_path: Path) -> str:
    """Lưu tệp .joblib nguyên tử qua tệp tạm cùng thư mục và trả về SHA-256 hex digest."""
    fd, tmp_name = tempfile.mkstemp(dir=dest_path.parent, prefix=f".{dest_path.name}.", suffix=".tmp")
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        joblib.dump(obj, tmp_path)
        os.chmod(tmp_path, 0o644)
        digest = _sha256_file(tmp_path)
        os.replace(tmp_path, dest_path)
        return digest
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _atomic_json_dump(data: Dict[str, Any], dest_path: Path) -> None:
    """Lưu tệp JSON nguyên tử qua tệp tạm cùng thư mục."""
    fd, tmp_name = tempfile.mkstemp(dir=dest_path.parent, prefix=f".{dest_path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, allow_nan=False)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, dest_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _make_event(
    ts: float,
    ev_type: int,
    tgid: int,
    ppid: int,
    uid: int,
    euid: int,
    comm: str,
    filename: str,
    session_id: str,
    label: int,
    cap: Optional[int] = None,
    flags: int = 0,
    cgroup_id: int = 4096,
    pidns_id: int = 4026531836,
    mntns_id: int = 4026531840,
) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        "timestamp": round(float(ts), 6),
        "event_type": int(ev_type),
        "tgid": int(tgid),
        "pid": int(tgid),
        "ppid": int(ppid),
        "uid": int(uid),
        "euid": int(euid),
        "flags": int(flags),
        "cgroup_id": int(cgroup_id),
        "pidns_id": int(pidns_id),
        "mntns_id": int(mntns_id),
        "comm": comm[:16],
        "filename": filename[:256],
        "session_id": session_id,
        "label": int(label),
    }
    if cap is not None:
        ev["cap"] = int(cap)
    return ev


def generate_synthetic_telemetry(n_sessions: int = 600) -> pd.DataFrame:
    """
    Sinh tập sự kiện telemetry thô theo từng phiên làm việc (event-stream),
    bao gồm các ca hard-negative thực tế (cat /etc/passwd, sudo hợp lệ, daemon root/worker,
    script /tmp không đặc quyền) và 5 nhóm tấn công leo thang đặc quyền, rồi đưa qua
    TelemetryLoader.convert_events_to_features() để bảo đảm đồng nhất 100% với FeatureExtractor.
    """
    from ml.telemetry_loader import TelemetryLoader

    rng = np.random.default_rng(42)
    events: List[Dict[str, Any]] = []
    base_ts = 1700000000.0
    host_pidns = 4026531836
    host_mntns = 4026531840

    benign_tools = [
        ("ls", "/usr/bin/ls"),
        ("git", "/usr/bin/git"),
        ("grep", "/usr/bin/grep"),
        ("cat", "/usr/bin/cat"),
        ("make", "/usr/bin/make"),
        ("id", "/usr/bin/id"),
        ("awk", "/usr/bin/awk"),
    ]
    whitelisted_suid = [
        ("sudo", "/usr/bin/sudo", "/etc/sudoers"),
        ("su", "/usr/bin/su", "/etc/shadow"),
        ("passwd", "/usr/bin/passwd", "/etc/shadow"),
        ("pkexec", "/usr/bin/pkexec", "/etc/shadow"),
    ]
    service_daemons = [
        ("nginx", "/usr/sbin/nginx", 33),
        ("python3", "/usr/bin/python3", 1000),
        ("node", "/usr/bin/node", 1000),
        ("apache2", "/usr/sbin/apache2", 33),
        ("php-fpm", "/usr/sbin/php-fpm", 33),
    ]
    auth_daemons = [
        ("sshd", "/usr/sbin/sshd"),
        ("unix_chkpwd", "/usr/sbin/unix_chkpwd"),
        ("cron", "/usr/sbin/cron"),
    ]
    gtfo_bins = [
        ("find", "/usr/bin/find"),
        ("vim", "/usr/bin/vim"),
        ("python3", "/usr/bin/python3"),
        ("awk", "/usr/bin/awk"),
        ("env", "/usr/bin/env"),
    ]

    for sid in range(n_sessions):
        session_id = f"session_{sid:04d}"
        t = base_ts + sid * 30.0
        base_pid = 10000 + sid * 50

        if sid == 0:
            is_attack_session = False
        elif sid == 1:
            is_attack_session = True
        else:
            is_attack_session = bool(rng.random() < 0.22)

        if not is_attack_session:
            kind = str(rng.choice(["user_dev", "admin_sudo", "root_daemon", "tmp_script"], p=[0.38, 0.20, 0.22, 0.20]))

            if kind == "user_dev":
                shell_pid = base_pid + 1
                events.append(_make_event(t, 1, shell_pid, base_pid, 1000, 1000, "bash", "/usr/bin/bash", session_id, 0))
                n_cmds = int(rng.integers(3, 10))
                for k in range(n_cmds):
                    t += float(rng.uniform(0.02, 0.9))
                    cmd_pid = base_pid + 2 + k
                    tool_comm, tool_path = benign_tools[int(rng.integers(0, len(benign_tools)))]
                    events.append(_make_event(t, 1, cmd_pid, shell_pid, 1000, 1000, tool_comm, tool_path, session_id, 0))
                    if tool_comm == "cat" and rng.random() < 0.65:
                        t += float(rng.uniform(0.005, 0.08))
                        events.append(_make_event(t, 4, cmd_pid, shell_pid, 1000, 1000, tool_comm, "/etc/passwd", session_id, 0, flags=0))
                    elif rng.random() < 0.25:
                        t += float(rng.uniform(0.005, 0.05))
                        events.append(_make_event(t, 4, cmd_pid, shell_pid, 1000, 1000, tool_comm, "/etc/ld.so.preload", session_id, 0, flags=0))
                    if rng.random() < 0.4:
                        t += 0.05
                        events.append(_make_event(t, 5, cmd_pid, shell_pid, 1000, 1000, tool_comm, "", session_id, 0))

            elif kind == "admin_sudo":
                shell_pid = base_pid + 1
                sudo_pid = base_pid + 2
                suid_comm, suid_path, target_file = whitelisted_suid[int(rng.integers(0, len(whitelisted_suid)))]
                events.append(_make_event(t, 1, shell_pid, base_pid, 1000, 1000, "bash", "/usr/bin/bash", session_id, 0))
                t += float(rng.uniform(0.1, 0.8))
                events.append(_make_event(t, 1, sudo_pid, shell_pid, 1000, 1000, suid_comm, suid_path, session_id, 0))
                t += float(rng.uniform(0.01, 0.15))
                events.append(_make_event(t, 2, sudo_pid, shell_pid, 1000, 0, suid_comm, "", session_id, 0, flags=FLAG_CRED_UID_GAIN))
                if rng.random() < 0.5:
                    t += 0.02
                    events.append(_make_event(t, 3, sudo_pid, shell_pid, 1000, 0, suid_comm, "", session_id, 0, cap=CAP_SETUID))
                t += float(rng.uniform(0.02, 0.2))
                events.append(_make_event(t, 4, sudo_pid, shell_pid, 1000, 0, suid_comm, target_file, session_id, 0, flags=0))
                t += 0.1
                events.append(_make_event(t, 5, sudo_pid, shell_pid, 1000, 0, suid_comm, "", session_id, 0))

            elif kind == "root_daemon":
                if rng.random() < 0.30:
                    auth_comm, auth_path = auth_daemons[int(rng.integers(0, len(auth_daemons)))]
                    auth_pid = base_pid + 1
                    events.append(_make_event(t, 1, auth_pid, 1, 0, 0, auth_comm, auth_path, session_id, 0))
                    t += float(rng.uniform(0.02, 0.3))
                    events.append(_make_event(t, 4, auth_pid, 1, 0, 0, auth_comm, "/etc/shadow", session_id, 0, flags=0))
                    t += 0.1
                    events.append(_make_event(t, 4, auth_pid, 1, 0, 0, auth_comm, "/etc/ld.so.preload", session_id, 0, flags=0))
                else:
                    srv_comm, srv_path, worker_uid = service_daemons[int(rng.integers(0, len(service_daemons)))]
                    master_pid = base_pid + 1
                    events.append(_make_event(t, 1, master_pid, 1, 0, 0, srv_comm, srv_path, session_id, 0))
                    # Root child (không leo thang)
                    t += float(rng.uniform(0.05, 0.4))
                    root_child_pid = base_pid + 2
                    events.append(_make_event(t, 1, root_child_pid, master_pid, 0, 0, srv_comm, srv_path, session_id, 0))
                    t += 0.03
                    events.append(_make_event(t, 4, root_child_pid, master_pid, 0, 0, srv_comm, "/etc/ld.so.preload", session_id, 0, flags=0))
                    # Unprivileged worker + cap_capable thông thường
                    t += float(rng.uniform(0.1, 0.5))
                    worker_pid = base_pid + 3
                    events.append(_make_event(t, 1, worker_pid, master_pid, worker_uid, worker_uid, srv_comm, srv_path, session_id, 0))
                    t += float(rng.uniform(0.02, 0.2))
                    cap_code = CAP_NET_ADMIN if rng.random() < 0.75 else CAP_DAC_OVERRIDE
                    events.append(_make_event(t, 3, worker_pid, master_pid, worker_uid, worker_uid, srv_comm, "", session_id, 0, cap=cap_code))
                    # Normal root shell trong container
                    if rng.random() < 0.25:
                        t += 0.2
                        sh_pid = base_pid + 4
                        events.append(
                            _make_event(
                                t, 1, sh_pid, base_pid, 0, 0, "sh", "/bin/sh", session_id, 0,
                                cgroup_id=16384, pidns_id=4026539999, mntns_id=4026539998,
                            )
                        )

            else:  # tmp_script (benign non-root hard negative)
                shell_pid = base_pid + 1
                script_pid = base_pid + 2
                tmp_path = str(rng.choice(["/tmp/build.sh", "/var/tmp/test_runner", "/dev/shm/check_env"]))
                events.append(_make_event(t, 1, shell_pid, base_pid, 1000, 1000, "bash", "/usr/bin/bash", session_id, 0))
                t += float(rng.uniform(0.1, 0.6))
                events.append(_make_event(t, 1, script_pid, shell_pid, 1000, 1000, "build", tmp_path, session_id, 0))
                if rng.random() < 0.4:
                    t += 0.05
                    events.append(_make_event(t, 4, script_pid, shell_pid, 1000, 1000, "build", "/etc/passwd", session_id, 0, flags=0))
                if rng.random() < 0.25:
                    t += 0.05
                    events.append(_make_event(t, 3, script_pid, shell_pid, 1000, 1000, "build", "", session_id, 0, cap=CAP_NET_ADMIN))
                t += 0.1
                events.append(_make_event(t, 5, script_pid, shell_pid, 1000, 1000, "build", "", session_id, 0))

        else:
            attack_kind = str(
                rng.choice(
                    ["suid_abuse", "tmp_exploit", "webshell", "fileless_preload", "container_escape"],
                    p=[0.26, 0.26, 0.23, 0.10, 0.15],
                )
            )

            if attack_kind == "suid_abuse":
                shell_pid = base_pid + 1
                recon_pid = base_pid + 2
                gtfo_pid = base_pid + 3
                g_comm, g_path = gtfo_bins[int(rng.integers(0, len(gtfo_bins)))]
                events.append(_make_event(t, 1, shell_pid, base_pid, 1000, 1000, "bash", "/usr/bin/bash", session_id, 0, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.1, 0.6))
                events.append(_make_event(t, 1, recon_pid, shell_pid, 1000, 1000, "id", "/usr/bin/id", session_id, 0, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.2, 0.8))
                events.append(_make_event(t, 1, gtfo_pid, shell_pid, 1000, 1000, g_comm, g_path, session_id, 0, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.01, 0.15))
                events.append(_make_event(t, 2, gtfo_pid, shell_pid, 1000, 0, g_comm, "", session_id, 1, flags=FLAG_CRED_UID_GAIN, cgroup_id=8192, pidns_id=4026532250))
                if rng.random() < 0.5:
                    t += 0.03
                    events.append(_make_event(t, 3, gtfo_pid, shell_pid, 1000, 0, g_comm, "", session_id, 1, cap=CAP_SETUID, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.02, 0.2))
                target = str(rng.choice(["/etc/shadow", "/etc/gshadow", "/etc/sudoers"]))
                events.append(_make_event(t, 4, gtfo_pid, shell_pid, 1000, 0, g_comm, target, session_id, 1, flags=0, cgroup_id=8192, pidns_id=4026532250))

            elif attack_kind == "tmp_exploit":
                recon_pid = base_pid + 1
                exp_pid = base_pid + 2
                spoof_comm = str(rng.choice(["sudo", "exploit", "pwn"]))
                exp_path = str(rng.choice(["/tmp/sudo", "/tmp/exploit", "/dev/shm/pwn", "/var/tmp/drop"]))
                events.append(_make_event(t, 1, recon_pid, base_pid, 1000, 1000, "ls", "/usr/bin/ls", session_id, 0))
                t += float(rng.uniform(0.1, 0.6))
                events.append(_make_event(t, 1, exp_pid, recon_pid, 1000, 1000, spoof_comm, exp_path, session_id, 0))
                t += float(rng.uniform(0.01, 0.12))
                events.append(_make_event(t, 3, exp_pid, recon_pid, 1000, 1000, spoof_comm, "", session_id, 1, cap=int(rng.choice([CAP_SETUID, CAP_SYS_ADMIN]))))
                t += float(rng.uniform(0.02, 0.2))
                events.append(_make_event(t, 2, exp_pid, recon_pid, 1000, 0, spoof_comm, "", session_id, 1, flags=FLAG_CRED_UID_GAIN))
                t += float(rng.uniform(0.02, 0.2))
                if rng.random() < 0.7:
                    events.append(_make_event(t, 4, exp_pid, recon_pid, 1000, 0, spoof_comm, "/etc/shadow", session_id, 1, flags=0))
                else:
                    events.append(_make_event(t, 4, exp_pid, recon_pid, 1000, 0, spoof_comm, "/etc/passwd", session_id, 1, flags=FLAG_OPEN_WRITE))

            elif attack_kind == "webshell":
                srv_comm, srv_path, srv_uid = service_daemons[int(rng.integers(0, len(service_daemons)))]
                if srv_uid == 1000:
                    srv_uid = 33
                srv_pid = base_pid + 1
                sh_pid = base_pid + 2
                events.append(_make_event(t, 1, srv_pid, 1, srv_uid, srv_uid, srv_comm, srv_path, session_id, 0, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.1, 0.7))
                events.append(_make_event(t, 1, sh_pid, srv_pid, srv_uid, srv_uid, "sh", "/bin/sh", session_id, 0, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.02, 0.2))
                events.append(_make_event(t, 2, sh_pid, srv_pid, srv_uid, 0, "sh", "", session_id, 1, flags=FLAG_CRED_UID_GAIN, cgroup_id=8192, pidns_id=4026532250))
                t += float(rng.uniform(0.02, 0.25))
                if rng.random() < 0.75:
                    events.append(_make_event(t, 4, sh_pid, srv_pid, srv_uid, 0, "sh", "/etc/shadow", session_id, 1, flags=0, cgroup_id=8192, pidns_id=4026532250))
                else:
                    events.append(_make_event(t, 4, sh_pid, srv_pid, srv_uid, 0, "sh", "/etc/sudoers.d/pwn", session_id, 1, flags=FLAG_OPEN_WRITE, cgroup_id=8192, pidns_id=4026532250))

            elif attack_kind == "fileless_preload":
                loader_pid = base_pid + 1
                f_path = str(rng.choice(["(execveat:fd)", "/memfd:payload", "/proc/self/fd/3"]))
                events.append(_make_event(t, 1, loader_pid, base_pid, 1000, 1000, "loader", f_path, session_id, 1, pidns_id=host_pidns, mntns_id=host_mntns))
                t += float(rng.uniform(0.02, 0.2))
                events.append(_make_event(t, 4, loader_pid, base_pid, 1000, 1000, "loader", "/etc/ld.so.preload", session_id, 1, flags=FLAG_OPEN_WRITE, pidns_id=host_pidns, mntns_id=host_mntns))
                if rng.random() < 0.5:
                    t += float(rng.uniform(0.02, 0.2))
                    events.append(_make_event(t, 2, loader_pid, base_pid, 1000, 0, "loader", "", session_id, 1, flags=FLAG_CRED_UID_GAIN))

            else:  # container_escape
                sh_pid = base_pid + 1
                events.append(
                    _make_event(
                        t, 1, sh_pid, base_pid, 0, 0, "sh", "/bin/sh", session_id, 0,
                        cgroup_id=16384, pidns_id=4026539999, mntns_id=4026539998,
                    )
                )
                t += float(rng.uniform(0.05, 0.3))
                esc_cap = int(rng.choice([CAP_SYS_MODULE, CAP_SYS_ADMIN, CAP_SYS_PTRACE]))
                if esc_cap != CAP_SYS_MODULE:
                    events.append(
                        _make_event(
                            t, 1, sh_pid, base_pid, 0, 0, "esc", "/tmp/escape", session_id, 1,
                            cgroup_id=16384, pidns_id=4026539999, mntns_id=4026539998,
                        )
                    )
                    t += 0.05
                events.append(
                    _make_event(
                        t, 3, sh_pid, base_pid, 0, 0, "sh", "", session_id, 1,
                        cap=esc_cap, flags=0, cgroup_id=16384, pidns_id=4026539999, mntns_id=4026539998,
                    )
                )
                if rng.random() < 0.4:
                    t += 0.05
                    events.append(
                        _make_event(
                            t, 4, sh_pid, base_pid, 0, 0, "sh", "/etc/shadow", session_id, 1,
                            flags=0, cgroup_id=16384, pidns_id=4026539999, mntns_id=4026539998,
                        )
                    )

    loader = TelemetryLoader()
    return loader.convert_events_to_features(events)


def train_models(
    telemetry_file: Optional[str] = None,
    check_only: bool = False,
    output_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    print("[*] Đang khởi tạo quy trình huấn luyện Machine Learning phát hiện Privilege Escalation...")

    if telemetry_file:
        print(f"[*] Đang nạp dữ liệu telemetry thực tế từ: {telemetry_file}")
        from ml.telemetry_loader import TelemetryLoader
        loader = TelemetryLoader()
        lower_path = telemetry_file.lower()
        if lower_path.endswith(".jsonl"):
            events = loader.load_jsonl(telemetry_file)
        elif lower_path.endswith(".csv"):
            events = loader.load_csv(telemetry_file)
        else:
            raise ValueError("Định dạng file không được hỗ trợ. Vui lòng cung cấp file .jsonl hoặc .csv")
        df = loader.convert_events_to_features(events)
        data_source = f"Real Telemetry File: {telemetry_file}"
    else:
        print("[*] Sử dụng tập dữ liệu mô phỏng event-stream baseline (Synthetic Telemetry Sessions)...")
        df = generate_synthetic_telemetry(n_sessions=600)
        data_source = "Synthetic Event-Stream Baseline Simulation (Grouped Sessions)"

    print(f"[+] Tổng số mẫu dữ liệu: {len(df)} (Bình thường: {int((df['label'] == 0).sum())}, Tấn công: {int((df['label'] == 1).sum())})")
    n_sessions = int(df["session_id"].nunique())
    print(f"[+] Số phiên (sessions): {n_sessions}")

    # 1. Kiểm tra tính toàn vẹn và cân bằng dữ liệu đầu vào
    if len(df) < 10:
        raise ValueError(f"Tập dữ liệu quá nhỏ ({len(df)} mẫu). Cần tối thiểu 10 mẫu để huấn luyện và kiểm thử.")

    if n_sessions < 2:
        raise ValueError(
            f"Tập dữ liệu cần ít nhất 2 session_id độc lập để phân chia train/test theo nhóm (GroupShuffleSplit). "
            f"Hiện tại chỉ có {n_sessions} session."
        )

    unique_labels = set(df["label"].unique())
    if unique_labels != {0, 1}:
        raise ValueError(
            f"Tập dữ liệu phải chứa đầy đủ cả 2 lớp nhãn: 0 (Benign) và 1 (Attack). "
            f"Các nhãn hiện có trong dữ liệu: {sorted(list(unique_labels))}."
        )

    if check_only:
        print("[✓] Kiểm tra cú pháp và tính hợp lệ dữ liệu hoàn tất (Check-only mode).")
        return None

    # 2. Phân chia train/test theo GroupShuffleSplit dựa trên session_id nhằm chống rò rỉ dữ liệu (Data Leakage)
    gss = GroupShuffleSplit(n_splits=25, test_size=0.25, random_state=42)
    train_idx, test_idx = None, None
    for tr_idx, te_idx in gss.split(df, groups=df["session_id"]):
        tr_df = df.iloc[tr_idx]
        te_df = df.iloc[te_idx]
        if (
            tr_df["label"].nunique() >= 2
            and te_df["label"].nunique() >= 2
            and int((tr_df["label"] == 0).sum()) >= 5
        ):
            train_idx, test_idx = tr_idx, te_idx
            break

    if train_idx is None:
        raise ValueError(
            "Không thể phân chia tập dữ liệu thành train và test có đầy đủ cả 2 lớp (Benign >= 5 mẫu trong train và Attack) "
            "dựa trên các session_id hiện có. Vui lòng cung cấp thêm các session chứa tấn công và session bình thường độc lập."
        )

    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]

    X_train = train_df[FEATURE_NAMES].values
    y_train = train_df["label"].values
    X_test = test_df[FEATURE_NAMES].values
    y_test = test_df["label"].values

    print(f"[*] Tập huấn luyện: {len(train_df)} mẫu | Tập kiểm thử độc lập: {len(test_df)} mẫu")

    # 3. Chuẩn hóa dữ liệu bằng StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 4. Huấn luyện Random Forest Classifier (Supervised)
    print("\n[*] Đang huấn luyện Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=8,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf_model.fit(X_train_scaled, y_train)

    rf_pred = rf_model.predict(X_test_scaled)
    rf_proba_matrix = rf_model.predict_proba(X_test_scaled)
    classes = list(getattr(rf_model, "classes_", [0, 1]))
    pos_col = classes.index(1) if 1 in classes else -1
    rf_proba = rf_proba_matrix[:, pos_col]

    if len(np.unique(y_test)) >= 2 and rf_proba.ndim == 1:
        rf_auc = float(roc_auc_score(y_test, rf_proba))
    else:
        rf_auc = 0.0

    cm = confusion_matrix(y_test, rf_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0
    fnr = float(fn) / float(fn + tp) if (fn + tp) > 0 else 0.0
    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    if telemetry_file is None:
        print(
            "\n[!] LƯU Ý QUAN TRỌNG: Kết quả đánh giá dưới đây được tính toán trên dữ liệu MÔ PHỎNG (Synthetic Baseline) "
            "phục vụ cold-start. Đây KHÔNG phải là bằng chứng hiệu quả trên hệ thống production thực tế."
        )

    print("\n--- KẾT QUẢ ĐÁNH GIÁ RANDOM FOREST TRÊN TẬP KIỂM THỬ ĐỘC LẬP ---")
    print(classification_report(y_test, rf_pred, target_names=["Benign", "Attack"], labels=[0, 1], zero_division=0))
    print(f"ROC-AUC Score:          {rf_auc:.4f}")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR): {fnr * 100:.2f}%")
    print("Confusion Matrix:")
    print(cm)

    importances = rf_model.feature_importances_
    print("\n--- ĐỘ QUAN TRỌNG CỦA CÁC ĐẶC TRƯNG ---")
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {name:<25}: {imp * 100:.2f}%")

    # 5. Huấn luyện Isolation Forest (Unsupervised Anomaly Detection)
    print("\n[*] Đang huấn luyện Isolation Forest (Anomaly Detection)...")
    X_train_benign = X_train_scaled[y_train == 0]
    if len(X_train_benign) < 5:
        raise ValueError(
            f"Tập huấn luyện cần tối thiểu 5 mẫu bình thường (Benign, label=0) cho Isolation Forest. "
            f"Hiện tại chỉ có {len(X_train_benign)} mẫu."
        )

    iso_model = IsolationForest(
        n_estimators=120,
        contamination=0.03,
        random_state=42,
        n_jobs=-1,
    )
    iso_model.fit(X_train_benign)

    iso_scores = iso_model.decision_function(X_test_scaled)
    iso_pred = iso_model.predict(X_test_scaled)
    benign_mask = y_test == 0
    attack_mask = y_test == 1
    iso_benign_fpr = float(np.mean(iso_pred[benign_mask] == -1)) if np.any(benign_mask) else 0.0
    iso_attack_rate = float(np.mean(iso_pred[attack_mask] == -1)) if np.any(attack_mask) else 0.0
    print(f"Isolation Forest - Benign Outlier Rate (FPR): {iso_benign_fpr * 100:.2f}% | Attack Anomaly Rate: {iso_attack_rate * 100:.2f}%")

    # 6. Đánh giá chính xác ngưỡng phục vụ Tầng 2 (classify_ml_tier2)
    from agent.detector import (
        RF_ATTACK_THRESHOLD,
        RF_ISO_COMBO_THRESHOLD,
        ISO_SEVERE_OUTLIER_THRESHOLD,
        ISO_SEVERE_RF_FLOOR,
        classify_ml_tier2,
    )

    tier2_pred = np.array(
        [
            1 if classify_ml_tier2(float(p), float(s), bool(ip == -1)) else 0
            for p, s, ip in zip(rf_proba, iso_scores, iso_pred)
        ],
        dtype=int,
    )
    cm_t2 = confusion_matrix(y_test, tier2_pred, labels=[0, 1])
    tn_t2, fp_t2, fn_t2, tp_t2 = cm_t2.ravel()
    fpr_t2 = float(fp_t2) / float(fp_t2 + tn_t2) if (fp_t2 + tn_t2) > 0 else 0.0
    fnr_t2 = float(fn_t2) / float(fn_t2 + tp_t2) if (fn_t2 + tp_t2) > 0 else 0.0
    prec_t2 = float(tp_t2) / float(tp_t2 + fp_t2) if (tp_t2 + fp_t2) > 0 else 0.0
    rec_t2 = float(tp_t2) / float(tp_t2 + fn_t2) if (tp_t2 + fn_t2) > 0 else 0.0
    f1_t2 = 2 * (prec_t2 * rec_t2) / (prec_t2 + rec_t2) if (prec_t2 + rec_t2) > 0 else 0.0
    print(f"Combined Tier 2 (Serving Thresholds) - Precision={prec_t2:.4f}, Recall={rec_t2:.4f}, F1={f1_t2:.4f}, FPR={fpr_t2 * 100:.2f}%")

    # 7. Lưu nguyên tử Models, Scaler, Checksums và Metadata
    target_dir = Path(output_dir) if output_dir else MODELS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    scaler_path = target_dir / "scaler.joblib"
    rf_path = target_dir / "random_forest.joblib"
    iso_path = target_dir / "isolation_forest.joblib"
    summary_path = target_dir / "dataset_summary.json"

    scaler_sha = _atomic_joblib_dump(scaler, scaler_path)
    rf_sha = _atomic_joblib_dump(rf_model, rf_path)
    iso_sha = _atomic_joblib_dump(iso_model, iso_path)

    summary = {
        "disclaimer": (
            "CHÚ Ý VỀ DỮ LIỆU ĐÁNH GIÁ: Các chỉ số dưới đây được đánh giá trên tập dữ liệu mô phỏng "
            "hoặc telemetry ban đầu dùng để thiết lập trọng số khởi động (cold-start). "
            "Hiệu năng phát hiện trong môi trường sản xuất thực tế phụ thuộc vào việc nạp và tinh chỉnh "
            "thêm với telemetry có nhãn từ hệ thống mục tiêu."
        ),
        "data_source": data_source,
        "split_method": "GroupShuffleSplit (grouped by session_id to prevent data leakage)",
        "n_samples": int(len(df)),
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "n_sessions_total": int(n_sessions),
        "n_sessions_train": int(train_df["session_id"].nunique()),
        "n_sessions_test": int(test_df["session_id"].nunique()),
        "features": list(FEATURE_NAMES),
        "serving_thresholds": {
            "rf_attack": RF_ATTACK_THRESHOLD,
            "rf_iso_combo": RF_ISO_COMBO_THRESHOLD,
            "iso_severe_outlier": ISO_SEVERE_OUTLIER_THRESHOLD,
            "iso_severe_rf_floor": ISO_SEVERE_RF_FLOOR,
        },
        "evaluation_metrics": {
            "roc_auc": round(float(rf_auc), 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp),
            },
        },
        "combined_tier2_metrics": {
            "precision": round(prec_t2, 4),
            "recall": round(rec_t2, 4),
            "f1_score": round(f1_t2, 4),
            "false_positive_rate": round(fpr_t2, 4),
            "false_negative_rate": round(fnr_t2, 4),
            "confusion_matrix": {
                "true_negative": int(tn_t2),
                "false_positive": int(fp_t2),
                "false_negative": int(fn_t2),
                "true_positive": int(tp_t2),
            },
        },
        "isolation_forest_metrics": {
            "benign_fpr": round(iso_benign_fpr, 4),
            "attack_detection_rate": round(iso_attack_rate, 4),
        },
        "feature_importances": {name: round(float(imp), 4) for name, imp in zip(FEATURE_NAMES, importances)},
        "model_checksums": {
            "scaler.joblib": scaler_sha,
            "random_forest.joblib": rf_sha,
            "isolation_forest.joblib": iso_sha,
        },
    }

    _atomic_json_dump(summary, summary_path)

    print(f"\n[✓] Huấn luyện và xuất chỉ số hoàn tất! Các artifact:")
    print(f"    - Scaler:           {scaler_path}")
    print(f"    - Random Forest:    {rf_path}")
    print(f"    - Isolation Forest: {iso_path}")
    print(f"    - Summary Metrics:  {summary_path}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Huấn luyện mô hình Machine Learning phát hiện Privilege Escalation")
    parser.add_argument("--telemetry-file", type=str, default=None, help="Đường dẫn file telemetry gán nhãn thực tế (.jsonl hoặc .csv)")
    parser.add_argument("--check-only", action="store_true", help="Chỉ kiểm tra tính hợp lệ của dữ liệu mà không ghi đè model")
    parser.add_argument("--output-dir", type=str, default=None, help="Thư mục đầu ra lưu mô hình .joblib và dataset_summary.json (mặc định: ml/models)")
    args = parser.parse_args()

    from ml.telemetry_loader import TelemetryValidationError

    try:
        train_models(
            telemetry_file=args.telemetry_file,
            check_only=args.check_only,
            output_dir=args.output_dir,
        )
    except FileNotFoundError as e:
        print(f"\n[!] LỖI TỆP TIN: {e}", file=sys.stderr)
        sys.exit(1)
    except TelemetryValidationError as e:
        print(f"\n[!] LỖI XÁC THỰC TELEMETRY (Dòng {e.line_number}, Trường '{e.field}'): {e.message}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\n[!] LỖI DỮ LIỆU HUẤN LUYỆN: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] LỖI TRONG QUÁ TRÌNH HUẤN LUYỆN: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
