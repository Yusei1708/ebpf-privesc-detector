"""
agent/detector.py: Công cụ phân tích và cảnh báo tấn công leo thang đặc quyền 2 tầng
  - Tầng 1 (Rule-based Fast Path): 8 luật phát hiện (PRIVESC-001..008) theo độ đặc hiệu giảm dần
  - Tầng 2 (ML-based Scoring): Chấm điểm kết hợp Random Forest & Isolation Forest (classify_ml_tier2)
  - Bảo mật nạp model (lstat ownership/mode/symlink guard + SHA-256 checksum manifest)
  - Tích hợp AlertLogger xuất file JSONL an toàn kèm Process Lineage
"""

import os
import sys
import stat
import time
import math
import hmac
import hashlib
import argparse
import tempfile
import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import (
    FEATURE_NAMES,
    FLAG_OPEN_WRITE,
    FLAG_CRED_UID_GAIN,
    FLAG_CRED_CAP_GAIN,
    FLAG_CAP_USERNS,
    FLAG_EXEC_FAILED,
    TRUSTED_BIN_DIRS,
    TRUSTED_AUTH_DAEMON_PATHS,
    SUSPICIOUS_DIRECTORIES,
    HIGH_RISK_CAPS,
    CAP_NAME_MAP,
    CAP_DAC_OVERRIDE,
    CAP_SETGID,
    CAP_SETUID,
    CAP_NET_ADMIN,
    CAP_SYS_MODULE,
    CAP_SYS_PTRACE,
    CAP_SYS_ADMIN,
    FeatureExtractor,
    is_suspicious_path,
    is_fileless_exec_path,
    is_whitelisted_binary,
    is_sensitive_open_target,
    is_service_comm,
    _normalize_posix_path,
    extract_explicit_timestamp,
)
from agent.alert_logger import (
    AlertLogger,
    get_host_mntns_id,
    get_host_pidns_id,
    is_container_event,
    sanitize_string,
)

# Sử dụng Rich để in giao diện cảnh báo đẹp mắt trên Terminal
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.markup import escape as rich_escape
    console = Console()
except ImportError:
    console = None

    def rich_escape(value: str) -> str:
        return value


SEVERITY_BASE_SCORE: Dict[str, int] = {
    "CRITICAL": 95,
    "HIGH": 85,
    "MEDIUM": 68,
    "LOW": 45,
    "INFO": 20,
}

RF_ATTACK_THRESHOLD = 0.65
RF_ISO_COMBO_THRESHOLD = 0.40
ISO_SEVERE_OUTLIER_THRESHOLD = -0.18
ISO_SEVERE_RF_FLOOR = 0.20
COOLDOWN_CACHE_MAX_SIZE = 4096

MODEL_FILENAMES = (
    "scaler.joblib",
    "random_forest.joblib",
    "isolation_forest.joblib",
)


def classify_ml_tier2(rf_prob: float, iso_score: float, is_iso_outlier: bool) -> bool:
    """Quy tắc quyết định Tầng 2 thống nhất giữa huấn luyện (ml/train.py) và phục vụ (detector.py)."""
    return (
        (rf_prob >= RF_ATTACK_THRESHOLD)
        or (is_iso_outlier and rf_prob >= RF_ISO_COMBO_THRESHOLD)
        or (is_iso_outlier and iso_score <= ISO_SEVERE_OUTLIER_THRESHOLD and rf_prob >= ISO_SEVERE_RF_FLOOR)
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class RuleMatch:
    """Đại diện cho một luật phát hiện được kích hoạt"""
    rule_id: str
    name: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    mitre_id: str
    description: str
    rationale: str


class PrivEscDetector:
    """
    Hệ thống phát hiện tấn công tích hợp Rule-based Engine, Machine Learning và JSONL Alert Logging
    """
    def __init__(
        self,
        models_dir: Optional[str] = None,
        alert_log_path: Optional[str] = None,
        alert_cooldown_seconds: float = 0.0,
        quiet: bool = False,
        allow_untrusted_models: bool = False,
        max_log_bytes: int = 50 * 1024 * 1024,
        log_backup_count: int = 5,
        host_mntns_id: Optional[int] = None,
        host_pidns_id: Optional[int] = None,
    ):
        cd_val = float(alert_cooldown_seconds)
        if not math.isfinite(cd_val):
            raise ValueError(f"alert_cooldown_seconds phải là số hữu hạn, nhận được {alert_cooldown_seconds}")

        self.models_dir = Path(models_dir) if models_dir else (PROJECT_ROOT / "ml" / "models")
        self.scaler = None
        self.rf_model = None
        self.iso_model = None
        self.checksum_verified: bool = False
        self.alert_cooldown_seconds = max(0.0, cd_val)
        self.quiet = bool(quiet)
        self.allow_untrusted_models = bool(allow_untrusted_models)
        self.host_mntns_id = host_mntns_id if host_mntns_id is not None else get_host_mntns_id()
        self.host_pidns_id = host_pidns_id if host_pidns_id is not None else get_host_pidns_id()
        self.logger = (
            AlertLogger(
                alert_log_path,
                host_mntns_id=self.host_mntns_id,
                host_pidns_id=self.host_pidns_id,
                max_bytes=max_log_bytes,
                backup_count=log_backup_count,
            )
            if alert_log_path
            else None
        )
        self._last_alert_ts: OrderedDict[Tuple[int, str], float] = OrderedDict()
        self.suppressed_alerts: int = 0
        self.ml_errors: int = 0
        self._load_models()

    def _validate_model_path_trust(self, path: Path, is_root: bool) -> Optional[str]:
        """Kiểm tra symlink, quyền sở hữu root và permission bits trước khi unpickle model."""
        try:
            st = os.lstat(path)
        except OSError as e:
            return f"Không thể truy cập {path}: {e}"

        if stat.S_ISLNK(st.st_mode):
            return f"Từ chối nạp {path}: phát hiện symbolic link không an toàn"

        if is_root:
            if st.st_uid != 0:
                return (
                    f"Từ chối nạp {path} dưới quyền root: tệp/thư mục thuộc UID {st.st_uid} != 0. "
                    f"Hãy chown root hoặc truyền --allow-untrusted-models nếu chủ ý kiểm thử."
                )
            if (st.st_mode & 0o022) != 0:
                return (
                    f"Từ chối nạp {path} dưới quyền root: quyền ghi group/other quá rộng "
                    f"(mode={oct(stat.S_IMODE(st.st_mode))})."
                )
        return None

    def _load_models(self):
        self.scaler = None
        self.rf_model = None
        self.iso_model = None
        self.checksum_verified = False

        scaler_file = self.models_dir / "scaler.joblib"
        rf_file = self.models_dir / "random_forest.joblib"
        iso_file = self.models_dir / "isolation_forest.joblib"
        summary_file = self.models_dir / "dataset_summary.json"

        if not (scaler_file.exists() and rf_file.exists() and iso_file.exists()):
            if not self.quiet:
                if console:
                    console.print(
                        f"[bold yellow][!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}. "
                        f"Hãy chạy 'python ml/train.py' trước.[/bold yellow]"
                    )
                else:
                    print(f"[!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}")
            return

        if not self.allow_untrusted_models:
            is_root = os.geteuid() == 0
            paths_to_check = [self.models_dir, scaler_file, rf_file, iso_file]
            if os.path.lexists(summary_file):
                paths_to_check.append(summary_file)
            for p in paths_to_check:
                err = self._validate_model_path_trust(p, is_root=is_root)
                if err is not None:
                    print(f"[!] Cảnh báo bảo mật ML: {err}", file=sys.stderr)
                    return

        try:
            # Kiểm tra SHA-256 checksum manifest nếu có trong dataset_summary.json
            if summary_file.exists():
                with open(summary_file, "r", encoding="utf-8") as f:
                    summary = json.load(f)
                if not isinstance(summary, dict):
                    raise ValueError("dataset_summary.json không phải JSON object hợp lệ")

                checksums = summary.get("model_checksums")
                if checksums is not None:
                    if not isinstance(checksums, dict):
                        raise ValueError("Trường 'model_checksums' trong dataset_summary.json không hợp lệ")
                    for fname in MODEL_FILENAMES:
                        fpath = self.models_dir / fname
                        expected_hash = checksums.get(fname)
                        if not isinstance(expected_hash, str) or len(expected_hash.strip()) != 64:
                            raise ValueError(f"Thiếu hoặc sai định dạng SHA-256 cho '{fname}' trong model_checksums")
                        actual_hash = _sha256_file(fpath)
                        if not hmac.compare_digest(actual_hash.lower(), expected_hash.strip().lower()):
                            raise ValueError(
                                f"Sai lệch SHA-256 cho '{fname}' (expected={expected_hash.strip()[:12]}..., "
                                f"actual={actual_hash[:12]}...)"
                            )
                    self.checksum_verified = True
                else:
                    if not self.quiet:
                        print(
                            f"[!] Cảnh báo: {summary_file} chưa có 'model_checksums' (artifact cũ) — "
                            f"bỏ qua kiểm tra SHA-256.",
                            file=sys.stderr,
                        )
            else:
                if not self.quiet:
                    print(
                        f"[!] Cảnh báo: Không tìm thấy {summary_file} — bỏ qua kiểm tra SHA-256.",
                        file=sys.stderr,
                    )

            # Nạp vào biến cục bộ trước, kiểm tra shape đặc trưng rồi mới gán đồng bộ
            scaler = joblib.load(scaler_file)
            rf_model = joblib.load(rf_file)
            iso_model = joblib.load(iso_file)

            expected_n_features = len(FEATURE_NAMES)
            for label_name, model_obj in (
                ("scaler", scaler),
                ("random_forest", rf_model),
                ("isolation_forest", iso_model),
            ):
                n_in = getattr(model_obj, "n_features_in_", None)
                if n_in is not None and int(n_in) != expected_n_features:
                    raise ValueError(
                        f"Mô hình {label_name} yêu cầu {n_in} đặc trưng nhưng FEATURE_NAMES có {expected_n_features}"
                    )

            if not hasattr(scaler, "transform"):
                raise ValueError("scaler thiếu phương thức transform()")
            if not hasattr(rf_model, "predict_proba"):
                raise ValueError("random_forest thiếu phương thức predict_proba()")
            if not hasattr(iso_model, "decision_function") or not hasattr(iso_model, "predict"):
                raise ValueError("isolation_forest thiếu phương thức decision_function()/predict()")

            self.scaler = scaler
            self.rf_model = rf_model
            self.iso_model = iso_model

            if not self.quiet:
                if console:
                    console.print(f"[bold green][✓] Đã nạp thành công mô hình ML từ {self.models_dir}[/bold green]")
                else:
                    print(f"[✓] Đã nạp thành công mô hình ML từ {self.models_dir}")
        except Exception as e:
            self.scaler = None
            self.rf_model = None
            self.iso_model = None
            self.checksum_verified = False
            print(f"[!] Cảnh báo: Lỗi nạp mô hình ML: {e}", file=sys.stderr)

    def evaluate_all_rules(
        self,
        event: Dict[str, Any],
        raw_features: Dict[str, Any],
        extractor: Optional[FeatureExtractor] = None,
    ) -> List[RuleMatch]:
        """
        Tầng 1: Đánh giá toàn bộ 8 luật theo thứ tự độ đặc hiệu giảm dần
        (matches[0] là luật đặc hiệu nhất; severity tổng hợp lấy mức cao nhất trong các luật khớp).
        """
        matches: List[RuleMatch] = []
        e_type = int(event.get("event_type") or 0)
        euid = 1000 if event.get("euid") is None else int(event.get("euid"))
        uid = 1000 if event.get("uid") is None else int(event.get("uid"))
        tgid = int(event.get("tgid") or 0)
        comm = str(event.get("comm") or "")
        filename = str(event.get("filename") or "")
        flags = int(event.get("flags") or 0)

        uid_change = int(raw_features.get("uid_change_flag", 0) or 0)
        suspicious_path = int(
            raw_features.get(
                "suspicious_path_flag",
                1 if (e_type == 1 and is_suspicious_path(filename)) else 0,
            )
            or 0
        )
        service_parent = int(raw_features.get("service_parent_flag", 0) or 0)

        verified_exe = ""
        if extractor is not None and tgid in extractor.process_tree:
            verified_exe = extractor.process_tree[tgid].exe_path or ""
        if not verified_exe and isinstance(event.get("exe_path"), str):
            verified_exe = event["exe_path"]
        if not verified_exe and e_type == 1:
            verified_exe = filename

        default_wl = 1 if (suspicious_path == 0 and is_whitelisted_binary(verified_exe, comm)) else 0
        is_whitelisted = int(raw_features.get("is_whitelisted_bin", default_wl) or 0)
        if suspicious_path == 1:
            is_whitelisted = 0

        bin_name = filename.split("/")[-1] if (e_type == 1 and filename) else (comm or filename.split("/")[-1])
        is_container = is_container_event(
            event,
            host_mntns_id=self.host_mntns_id,
            host_pidns_id=self.host_pidns_id,
        )

        # 1. PRIVESC-001 (CRITICAL, T1548.001): commit_creds leo thang đặc quyền / capability ngoài whitelist
        if (
            e_type == 2
            and is_whitelisted == 0
            and ((uid != 0 and euid == 0) or (flags & (FLAG_CRED_UID_GAIN | FLAG_CRED_CAP_GAIN)) != 0)
        ):
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-001",
                    name="RULE_COMMIT_CREDS_EUID_JUMP",
                    severity="CRITICAL",
                    mitre_id="T1548.001",
                    description="Tiến trình ngoài whitelist gọi commit_creds để leo thang đặc quyền (UID/EUID=0 hoặc CAP gain)",
                    rationale="Tiến trình không được phép tự nâng quyền/capability trừ khi qua nhị phân SUID chuẩn tại thư mục hệ thống tin cậy.",
                )
            )

        # 2. PRIVESC-008 (HIGH, T1620): Thực thi fileless qua memfd / execveat(fd) / /proc/*/fd/*
        if e_type == 1 and is_fileless_exec_path(filename) and is_whitelisted == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-008",
                    name="RULE_FILELESS_EXEC_ATTEMPT",
                    severity="HIGH",
                    mitre_id="T1620",
                    description=f"Phát hiện thực thi fileless từ bộ nhớ hoặc file descriptor ({filename})",
                    rationale="Kẻ tấn công sử dụng memfd_create, execveat(AT_EMPTY_PATH) hoặc /proc/self/fd để chạy payload mà không ghi file xuống đĩa.",
                )
            )

        # 3. PRIVESC-005 (HIGH, T1574.006 / T1003.008): Mở file nhạy cảm (chuẩn hóa đường dẫn & phân biệt cờ ghi)
        if e_type == 4 and is_sensitive_open_target(filename, flags) and is_whitelisted == 0:
            verified_exe_clean = verified_exe.strip()
            verified_exe_norm = (
                _normalize_posix_path(verified_exe_clean)
                if verified_exe_clean.startswith("/") and not verified_exe_clean.endswith(" (deleted)")
                else ""
            )
            trusted_root_auth_daemon = (
                bool(verified_exe_norm)
                and verified_exe_norm in TRUSTED_AUTH_DAEMON_PATHS
                and uid == 0
                and euid == 0
                and suspicious_path == 0
                and service_parent == 0
                and uid_change == 0
                and (flags & FLAG_OPEN_WRITE) == 0
            )
            if not trusted_root_auth_daemon and (
                euid == 0
                or suspicious_path == 1
                or service_parent == 1
                or uid_change == 1
                or (flags & FLAG_OPEN_WRITE) != 0
            ):
                norm_target = _normalize_posix_path(filename.strip()) if filename.strip().startswith("/") else ""
                mitre_id = "T1574.006" if norm_target == "/etc/ld.so.preload" else "T1003.008"
                matches.append(
                    RuleMatch(
                        rule_id="PRIVESC-005",
                        name="RULE_SENSITIVE_FILE_ACCESS_ATTEMPT",
                        severity="HIGH",
                        mitre_id=mitre_id,
                        description=f"Yêu cầu truy cập file nhạy cảm ({filename}) trong bối cảnh đáng ngờ",
                        rationale="Quan sát thấy syscall openat nhắm vào /etc/shadow, /etc/gshadow, /etc/sudoers hoặc ghi vào /etc/ld.so.preload, /etc/passwd.",
                    )
                )

        # 4. PRIVESC-007 (HIGH, T1611): Dò/sử dụng capability thoát Container
        cap = event.get("cap")
        if (
            e_type == 3
            and is_container
            and (flags & FLAG_CAP_USERNS) == 0
            and is_whitelisted == 0
            and (
                cap == CAP_SYS_MODULE
                or (
                    cap in {CAP_SYS_ADMIN, CAP_SYS_PTRACE}
                    and (
                        suspicious_path == 1
                        or service_parent == 1
                        or uid_change == 1
                        or raw_features.get("sensitive_file_access", 0) >= 1
                    )
                )
            )
        ):
            cap_label = CAP_NAME_MAP.get(cap, str(cap))
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-007",
                    name="RULE_CONTAINER_ESCAPE_CAP_PROBE",
                    severity="HIGH",
                    mitre_id="T1611",
                    description=f"Tiến trình trong Container ({comm}) kiểm tra capability thoát ly ({cap_label}={cap})",
                    rationale="Kiểm tra CAP_SYS_MODULE hoặc CAP_SYS_ADMIN/CAP_SYS_PTRACE trong ngữ cảnh rủi ro ở init user_ns là dấu hiệu thoát container.",
                )
            )

        # 5. PRIVESC-006 (MEDIUM, T1548): Kiểm tra Capability đặc quyền ở init user_ns trong bối cảnh rủi ro
        if e_type == 3 and uid != 0 and is_whitelisted == 0 and (flags & FLAG_CAP_USERNS) == 0:
            correlated_cap_probe = (
                raw_features.get("cap_check_count", 0) >= 5
                and raw_features.get("sensitive_file_access", 0) >= 1
            )
            high_risk_match = cap in HIGH_RISK_CAPS and (
                suspicious_path == 1
                or service_parent == 1
                or uid_change == 1
                or correlated_cap_probe
            )
            dac_override_match = cap == CAP_DAC_OVERRIDE and (
                suspicious_path == 1
                or raw_features.get("sensitive_file_access", 0) >= 1
            )
            if high_risk_match or dac_override_match:
                cap_label = CAP_NAME_MAP.get(cap, str(cap))
                matches.append(
                    RuleMatch(
                        rule_id="PRIVESC-006",
                        name="RULE_PRIVILEGED_CAPABILITY_PROBE",
                        severity="MEDIUM",
                        mitre_id="T1548",
                        description=f"Tiến trình không đặc quyền ({comm}) kiểm tra capability đặc quyền ({cap_label}={cap}) trong bối cảnh rủi ro",
                        rationale="Quan sát thấy kiểm tra capability nhạy cảm kết hợp với thư mục tạm, phả hệ service, nhảy quyền hoặc truy cập file nhạy cảm.",
                    )
                )

        # 6. PRIVESC-004 (CRITICAL, T1068): Tiến trình con của service leo thang từ non-root sang root (không miễn trừ whitelist)
        if service_parent == 1 and (uid_change == 1 or (uid != 0 and euid == 0)):
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-004",
                    name="RULE_SERVICE_SPAWNED_ROOT_SHELL",
                    severity="CRITICAL",
                    mitre_id="T1068",
                    description="Tiến trình bắt nguồn từ web/network service leo thang lên đặc quyền root",
                    rationale="Dấu hiệu điển hình của Web Shell hoặc RCE leo quyền cục bộ từ worker không đặc quyền lên EUID=0.",
                )
            )

        # 7. PRIVESC-003 (HIGH, T1059): Thực thi mã từ thư mục tạm (/tmp, /dev/shm, memfd) với đặc quyền root hoặc nhảy quyền
        if suspicious_path == 1 and (euid == 0 or uid_change == 1) and is_whitelisted == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-003",
                    name="RULE_SUSPICIOUS_PATH_PRIV_EXEC",
                    severity="HIGH",
                    mitre_id="T1059",
                    description=f"Thực thi mã từ thư mục tạm ({filename or comm}) với đặc quyền quản trị viên",
                    rationale="Kẻ tấn công thường biên dịch hoặc tải exploit payload vào /tmp, /dev/shm hoặc memfd rồi chạy với quyền root.",
                )
            )

        # 8. PRIVESC-002 (CRITICAL, T1548.001): Lạm dụng nhị phân SUID ngoài whitelist (GTFOBins)
        if uid_change == 1 and is_whitelisted == 0 and euid == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-002",
                    name="RULE_GTFOBINS_SUID_ABUSE",
                    severity="CRITICAL",
                    mitre_id="T1548.001",
                    description=f"Nhị phân ngoài whitelist ({bin_name}) được thực thi và xác lập quyền root (EUID=0)",
                    rationale="Khai thác các nhị phân có SUID bit hoặc cấu hình sai để thoát shell root.",
                )
            )

        return matches

    def evaluate_rules(
        self,
        event: Dict[str, Any],
        raw_features: Dict[str, Any],
        extractor: Optional[FeatureExtractor] = None,
    ) -> Tuple[bool, Optional[RuleMatch]]:
        """
        Tầng 1: Rule-based Fast Path trả về luật đặc hiệu nhất được kích hoạt.
        Trả về: (is_attack, RuleMatch hoặc None)
        """
        matches = self.evaluate_all_rules(event, raw_features, extractor=extractor)
        if matches:
            return True, matches[0]
        return False, None

    def _evaluate_ml_detailed(self, feature_vector: np.ndarray) -> Tuple[float, float, bool, bool]:
        """Chạy suy luận Tầng 2 trả về (rf_prob, iso_score, is_iso_outlier, is_ml_anomaly)."""
        if self.scaler is None or self.rf_model is None or self.iso_model is None:
            return 0.0, 0.0, False, False

        arr = np.asarray(feature_vector, dtype=np.float64).reshape(1, -1)
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        try:
            feat_scaled = self.scaler.transform(arr)

            proba_row = self.rf_model.predict_proba(feat_scaled)[0]
            classes = list(getattr(self.rf_model, "classes_", [0, 1]))
            if 1 in classes:
                rf_prob = float(proba_row[classes.index(1)])
            else:
                rf_prob = float(proba_row[-1])

            iso_score = float(self.iso_model.decision_function(feat_scaled)[0])
            is_iso_outlier = bool(self.iso_model.predict(feat_scaled)[0] == -1)
            is_ml_anomaly = classify_ml_tier2(rf_prob, iso_score, is_iso_outlier)
            return rf_prob, iso_score, is_iso_outlier, is_ml_anomaly
        except Exception as e:
            self.ml_errors += 1
            if self.ml_errors <= 3 or (self.ml_errors % 100) == 0:
                print(f"[!] Cảnh báo lỗi suy luận ML (#{self.ml_errors}): {e}", file=sys.stderr)
            return 0.0, 0.0, False, False

    def evaluate_ml(self, feature_vector: np.ndarray) -> Tuple[float, float, bool]:
        """
        Tầng 2: Machine Learning Anomaly & Classification
        Trả về: (rf_attack_probability, anomaly_score, is_ml_anomaly)
        """
        rf_prob, iso_score, _, is_ml_anomaly = self._evaluate_ml_detailed(feature_vector)
        return rf_prob, iso_score, is_ml_anomaly

    def clear_process_cooldown(self, tgid: int) -> None:
        """Xóa cache cooldown của tiến trình đã thoát nhằm tránh ức chế nhầm khi PID bị tái sử dụng."""
        tgid_int = int(tgid)
        to_delete = [key for key in self._last_alert_ts if key[0] == tgid_int]
        for key in to_delete:
            self._last_alert_ts.pop(key, None)

    def analyze(
        self,
        event: Dict[str, Any],
        feature_vector: np.ndarray,
        raw_features: Dict[str, Any],
        extractor: Optional[FeatureExtractor] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Kết hợp 2 tầng phân tích để đưa ra quyết định cảnh báo toàn diện.
        Hỗ trợ chống lặp cảnh báo (LRU cooldown) theo tập (tgid, rule_id) và dọn cache khi process exit.
        """
        if int(event.get("event_type") or 0) == 5:
            self.clear_process_cooldown(int(event.get("tgid") or 0))
            return None

        matches = self.evaluate_all_rules(event, raw_features, extractor=extractor)
        rule_hit = len(matches) > 0
        match = matches[0] if rule_hit else None
        matched_rule_ids = [m.rule_id for m in matches]

        rf_prob, iso_score, is_iso_outlier, ml_hit = self._evaluate_ml_detailed(feature_vector)

        # Hiệu chỉnh ml_score để mọi phát hiện ML hợp lệ (bao gồm outlier Isolation Forest nghiêm trọng) đạt >= 60
        iso_bonus = 0.0
        if ml_hit:
            iso_bonus = 20.0 + (min(20.0, max(0.0, (-iso_score) * 80.0)) if is_iso_outlier else 0.0)
        ml_score = int(round(rf_prob * 80.0 + iso_bonus))
        if ml_hit:
            ml_score = max(60, min(100, ml_score))
        else:
            ml_score = min(59, ml_score)

        rule_name = match.name if match else "N/A"
        if rule_hit:
            highest_severity = max(matches, key=lambda m: SEVERITY_BASE_SCORE.get(m.severity, 0)).severity
        else:
            highest_severity = "HIGH" if ml_score >= 85 else ("MEDIUM" if ml_score >= 60 else "LOW")
        rule_sev = highest_severity

        if rule_hit and match:
            base_rule_score = max(SEVERITY_BASE_SCORE.get(m.severity, 60) for m in matches)
            threat_score = min(100, max(base_rule_score, ml_score))
        else:
            threat_score = min(100, ml_score)

        if rule_hit or ml_hit or threat_score >= 60:
            if self.alert_cooldown_seconds > 0:
                tgid_key = int(event.get("tgid") or 0)
                rule_keys = matched_rule_ids if matched_rule_ids else ["ML_ANOMALY"]
                explicit_ts = extract_explicit_timestamp(event)
                now_ts = explicit_ts if explicit_ts is not None else time.monotonic()

                keys_to_update: List[Tuple[int, str]] = []
                for rk in rule_keys:
                    dedup_key = (tgid_key, rk)
                    last_ts = self._last_alert_ts.get(dedup_key)
                    if last_ts is None or abs(now_ts - last_ts) >= self.alert_cooldown_seconds:
                        keys_to_update.append(dedup_key)

                if not keys_to_update:
                    self.suppressed_alerts += 1
                    return None

                for dedup_key in keys_to_update:
                    prev_ts = self._last_alert_ts.get(dedup_key)
                    self._last_alert_ts[dedup_key] = max(prev_ts, now_ts) if prev_ts is not None else now_ts
                    self._last_alert_ts.move_to_end(dedup_key)

                while len(self._last_alert_ts) > COOLDOWN_CACHE_MAX_SIZE:
                    self._last_alert_ts.popitem(last=False)

            tgid_int = int(event.get("tgid") or 0)
            lineage = extractor.get_process_lineage(tgid_int) if extractor is not None else []

            alert_data: Dict[str, Any] = {
                "event": event,
                "raw_features": raw_features,
                "rule_name": rule_name,
                "rule_sev": rule_sev,
                "highest_severity": highest_severity,
                "match": match,
                "matched_rules": matched_rule_ids,
                "rf_prob": rf_prob,
                "iso_score": iso_score,
                "is_ml_anomaly": ml_hit,
                "threat_score": threat_score,
                "lineage": lineage,
            }
            if match is not None:
                alert_data["rule_description"] = match.description
                alert_data["rule_rationale"] = match.rationale

            if not self.quiet:
                self.display_alert(
                    event,
                    raw_features,
                    rule_name,
                    rule_sev,
                    rf_prob,
                    iso_score,
                    threat_score,
                    extractor,
                    match=match,
                    lineage=lineage,
                )

            if self.logger:
                self.logger.log_alert(alert_data)

            return alert_data

        return None

    def display_alert(
        self,
        event: Dict[str, Any],
        raw_features: Dict[str, Any],
        rule_name: str,
        rule_sev: str,
        rf_prob: float,
        iso_score: float,
        threat_score: int,
        extractor: Optional[FeatureExtractor] = None,
        match: Optional[RuleMatch] = None,
        lineage: Optional[List[str]] = None,
    ):
        """Hiển thị bảng cảnh báo chi tiết theo phong cách SOC Dashboard (chống Rich markup/ANSI injection)."""
        is_container = is_container_event(
            event,
            host_mntns_id=self.host_mntns_id,
            host_pidns_id=self.host_pidns_id,
        )
        source_env = "CONTAINER / ISOLATED NS" if is_container else "HOST SYSTEM"
        sev_color = "bold red on black" if threat_score >= 80 else "bold yellow on black"

        safe_comm = sanitize_string(event.get("comm", ""))
        safe_path = sanitize_string(event.get("filename", "")) or "(N/A)"
        safe_rule_name = sanitize_string(rule_name)
        safe_sev = sanitize_string(rule_sev)
        resolved_lineage = (
            lineage
            if lineage is not None
            else (extractor.get_process_lineage(int(event.get("tgid") or 0)) if extractor is not None else [])
        )
        lineage_str = " -> ".join(sanitize_string(item) for item in resolved_lineage if sanitize_string(item)) or "(N/A)"

        e_type = int(event.get("event_type") or 0)
        cap_info = None
        if e_type == 3 and event.get("cap") is not None:
            cap_val = int(event["cap"])
            cap_info = f"{CAP_NAME_MAP.get(cap_val, f'CAP_{cap_val}')} ({cap_val})"

        win_sec = extractor.window_size if extractor is not None else 3.0

        if console:
            console.print()
            title_text = f"🚨 [BÁO ĐỘNG] PHÁT HIỆN TẤN CÔNG LEO THANG ĐẶC QUYỀN (THREAT SCORE: {threat_score}/100) 🚨"
            console.print(Panel(Text(title_text, justify="center", style=sev_color)))

            table = Table(title="Chi Tiết Tiến Trình & Môi Trường Bị Nghi Ngờ", show_header=True, header_style="bold magenta")
            table.add_column("Thuộc Tính", style="cyan", width=24)
            table.add_column("Giá Trị Telemetry eBPF", style="white")

            table.add_row(
                "Môi trường",
                f"[bold yellow]{source_env}[/bold yellow] (Cgroup: {event.get('cgroup_id')}, PidNS: {event.get('pidns_id')}, MntNS: {event.get('mntns_id')})",
            )
            table.add_row("Process / Thread ID", f"TGID={event.get('tgid')} | PID={event.get('pid')} | PPID={event.get('ppid')}")
            table.add_row("Process Lineage", rich_escape(lineage_str))
            table.add_row("Executable (comm)", f"[bold red]{rich_escape(safe_comm)}[/bold red]")
            table.add_row("Path / Target File", rich_escape(safe_path))
            table.add_row("Chuyển quyền (UID -> EUID)", f"UID={event.get('uid')} -> [bold red]EUID={event.get('euid')}[/bold red]")
            if cap_info:
                table.add_row("Capability Probe", rich_escape(cap_info))
            table.add_row("Tầng 1 (Rule-Based)", f"[bold red]{rich_escape(safe_rule_name)}[/bold red] (Severity: {rich_escape(safe_sev)})")
            if match is not None and match.description:
                table.add_row("Mô tả", rich_escape(sanitize_string(match.description, max_len=512)))
            table.add_row("Tầng 2 (Random Forest)", f"[bold green]{rf_prob * 100:.2f}%[/bold green] Xác suất tấn công")
            table.add_row("Tầng 2 (Isolation Forest)", f"Score: [bold cyan]{iso_score:.4f}[/bold cyan] ({'Bất thường' if iso_score < 0 else 'Bình thường'})")

            console.print(table)

            f_table = Table(
                title=f"Vector 8 Đặc Trưng Hành Vi (Sliding Window {win_sec:g}s)",
                show_header=True,
                header_style="bold cyan",
            )
            for fname in FEATURE_NAMES:
                f_table.add_column(fname, justify="center")

            row_cells: List[str] = []
            for name in FEATURE_NAMES:
                val = raw_features.get(name, 0)
                if (name in ("uid_change_flag", "suspicious_path_flag") and val == 1) or (name == "is_whitelisted_bin" and val == 0):
                    row_cells.append(f"[bold red]{rich_escape(str(val))}[/bold red]")
                else:
                    row_cells.append(rich_escape(str(val)))
            f_table.add_row(*row_cells)
            console.print(f_table)
            console.print("-" * 80)
        else:
            print(f"\n[!] BÁO ĐỘNG LEO THANG ĐẶC QUYỀN: {safe_rule_name} ({safe_sev}) | Score: {threat_score}/100")
            print(f"    PID: {event.get('tgid')}, Comm: {safe_comm}, Path: {safe_path}")
            print(f"    Lineage: {lineage_str}")
            print(f"    UID: {event.get('uid')} -> EUID: {event.get('euid')}")
            if cap_info:
                print(f"    Capability: {cap_info}")
            if match is not None and match.description:
                print(f"    Description: {sanitize_string(match.description, max_len=512)}")
            print(f"    RF Prob: {rf_prob * 100:.1f}%, ISO Score: {iso_score:.3f}")
            print(f"    Features: {raw_features}")


def run_replay(
    telemetry_file: str,
    alert_log_path: Optional[str] = None,
    quiet: bool = False,
    models_dir: Optional[str] = None,
    cooldown: float = 0.0,
    host_pidns_id: Optional[int] = None,
    host_mntns_id: Optional[int] = None,
    summary_out: Optional[str] = None,
    allow_untrusted_models: bool = False,
) -> Dict[str, Any]:
    """
    Chạy bộ phát hiện 2 tầng (Rule + ML) ngoại tuyến trên tệp telemetry (.jsonl hoặc .csv).
    Sử dụng TelemetryLoader(require_label=False).iter_session_features() để thống nhất với pipeline ML.
    """
    from ml.telemetry_loader import TelemetryLoader

    loader = TelemetryLoader(require_label=False)
    lower_path = telemetry_file.lower()
    if lower_path.endswith(".jsonl"):
        events = loader.load_jsonl(telemetry_file)
    elif lower_path.endswith(".csv"):
        events = loader.load_csv(telemetry_file)
    else:
        raise ValueError("Định dạng file replay không được hỗ trợ. Vui lòng cung cấp file .jsonl hoặc .csv")

    detector = PrivEscDetector(
        models_dir=models_dir,
        alert_log_path=alert_log_path,
        alert_cooldown_seconds=max(0.0, float(cooldown)),
        quiet=quiet,
        allow_untrusted_models=allow_untrusted_models,
        host_mntns_id=host_mntns_id,
        host_pidns_id=host_pidns_id,
    )

    tp = fp = tn = fn = 0
    evaluated_events = 0
    alerts_count = 0
    sessions_seen = set()

    for sid, ev, feat_vec, raw_feat, ext in loader.iter_session_features(
        events,
        on_exit=detector.clear_process_cooldown,
    ):
        sessions_seen.add(sid)
        alert = detector.analyze(ev, feat_vec, raw_feat, ext)

        predicted_attack = alert is not None
        if predicted_attack:
            alerts_count += 1

        evaluated_events += 1
        if "label" in ev and ev["label"] is not None:
            actual = int(ev["label"])
            if actual == 1 and predicted_attack:
                tp += 1
            elif actual == 0 and predicted_attack:
                fp += 1
            elif actual == 0 and not predicted_attack:
                tn += 1
            elif actual == 1 and not predicted_attack:
                fn += 1

    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0

    summary = {
        "telemetry_file": telemetry_file,
        "sessions": len(sessions_seen),
        "evaluated_events": evaluated_events,
        "alerts_triggered": alerts_count,
        "suppressed_alerts": detector.suppressed_alerts,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }

    if summary_out:
        out_path = Path(summary_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=out_path.parent, prefix=f".{out_path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False, allow_nan=False)
            os.replace(tmp_name, out_path)
        except Exception:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise

    print(f"\n[*] Kết quả Offline Replay ({telemetry_file}):")
    print(f"    Sessions: {len(sessions_seen)} | Sự kiện phân tích: {evaluated_events} | Cảnh báo: {alerts_count}")
    print(f"    TP={tp}, FP={fp}, TN={tn}, FN={fn} | Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}, FPR={fpr:.4f}")
    return summary


def run_test_alert():
    """Hàm tự kiểm thử bộ cảnh báo với dữ liệu giả lập sử dụng Assertion chặt chẽ và kiểm tra AlertLogger"""
    print("[*] Đang chạy kiểm thử bộ phân tích PrivEscDetector với các kịch bản mẫu và kiểm chứng Assertion...")

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_log:
        tmp_log_path = tmp_log.name

    try:
        host_mntns = get_host_mntns_id() or 4026531840
        host_pidns = get_host_pidns_id() or 4026531836
        container_mntns = host_mntns + 200
        detector = PrivEscDetector(
            alert_log_path=tmp_log_path,
            alert_cooldown_seconds=0.0,
            host_mntns_id=host_mntns,
            host_pidns_id=host_pidns,
        )

        # Kịch bản 1: SUID Abuse trên Host (find gán SUID leo lên EUID=0)
        print("\n--- Test Case 1: SUID Abuse (/usr/bin/find spawning shell with EUID=0) ---")
        event_1 = {
            "event_type": 1,
            "pid": 54321,
            "tgid": 54320,
            "ppid": 1000,
            "uid": 1000,
            "euid": 0,
            "cgroup_id": 4096,
            "pidns_id": host_pidns,
            "mntns_id": host_mntns,
            "comm": "find",
            "filename": "/usr/bin/find",
        }
        raw_feat_1 = {
            "exec_count": 4,
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "sensitive_file_access": 1,
            "cap_check_count": 2,
            "priv_syscall_rate": 1.33,
        }
        feat_vec_1 = np.array([4, 1, 0, 0, 0, 1, 2, 1.33], dtype=np.float32)
        res_1 = detector.analyze(event_1, feat_vec_1, raw_feat_1)

        assert res_1 is not None, "Assertion Error: Case 1 không kích hoạt được cảnh báo!"
        assert res_1["rule_name"] == "RULE_GTFOBINS_SUID_ABUSE", f"Sai luật: {res_1['rule_name']}"
        assert res_1["highest_severity"] == "CRITICAL", f"Sai severity: {res_1['highest_severity']}"
        assert res_1["threat_score"] >= 80, f"Threat score quá thấp: {res_1['threat_score']}"

        # Kịch bản 2: Exploit trong Container (/tmp đọc /etc/shadow)
        print("\n--- Test Case 2: Exploit Drop trong Container (/tmp đọc trộm /etc/shadow) ---")
        event_2 = {
            "event_type": 4,
            "pid": 55112,
            "tgid": 55110,
            "ppid": 2040,
            "uid": 1000,
            "euid": 0,
            "flags": 0,
            "cgroup_id": 8192,
            "pidns_id": host_pidns,
            "mntns_id": container_mntns,
            "comm": "exploit",
            "filename": "/etc/shadow",
        }
        raw_feat_2 = {
            "exec_count": 6,
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
            "sensitive_file_access": 2,
            "cap_check_count": 3,
            "priv_syscall_rate": 2.0,
        }
        feat_vec_2 = np.array([6, 1, 0, 1, 0, 2, 3, 2.0], dtype=np.float32)
        res_2 = detector.analyze(event_2, feat_vec_2, raw_feat_2)

        assert res_2 is not None, "Assertion Error: Case 2 không kích hoạt được cảnh báo!"
        assert res_2["rule_name"] == "RULE_SENSITIVE_FILE_ACCESS_ATTEMPT", f"Sai luật: {res_2['rule_name']}"
        assert "PRIVESC-005" in res_2["matched_rules"], f"Thiếu PRIVESC-005 trong matched_rules: {res_2['matched_rules']}"
        assert res_2["highest_severity"] == "CRITICAL", f"Sai severity tổng hợp: {res_2['highest_severity']}"
        assert res_2["threat_score"] >= 80, f"Threat score quá thấp: {res_2['threat_score']}"

        # Kịch bản 3: Benign User Command (ls -la) - Không được kích hoạt cảnh báo sai
        print("\n--- Test Case 3: Benign User Command (ls /home) - Kiểm tra False Positive ---")
        event_3 = {
            "event_type": 1,
            "pid": 56000,
            "tgid": 56000,
            "ppid": 2040,
            "uid": 1000,
            "euid": 1000,
            "cgroup_id": 4096,
            "pidns_id": host_pidns,
            "mntns_id": host_mntns,
            "comm": "ls",
            "filename": "/usr/bin/ls",
        }
        raw_feat_3 = {
            "exec_count": 1,
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "sensitive_file_access": 0,
            "cap_check_count": 0,
            "priv_syscall_rate": 0.33,
        }
        feat_vec_3 = np.array([1, 0, 0, 0, 0, 0, 0, 0.33], dtype=np.float32)
        res_3 = detector.analyze(event_3, feat_vec_3, raw_feat_3)

        assert res_3 is None, f"Assertion Error: Benign command bị cảnh báo sai (False Positive): {res_3}"

        # Kiểm chứng file log JSONL
        with open(tmp_log_path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 2, f"Assertion Error: Mong đợi 2 dòng log cảnh báo JSONL, nhưng tìm thấy {len(lines)}"
        log_entry_1 = json.loads(lines[0])
        log_entry_2 = json.loads(lines[1])
        assert "timestamp" in log_entry_1, "Thiếu trường timestamp trong JSONL"
        assert log_entry_1["threat_score"] >= 80, "Threat score trong log không khớp"
        assert log_entry_1["comm"] == "find", "Comm trong log không khớp"
        assert log_entry_1["is_container"] is False, "Tiến trình Host bị nhận diện nhầm là Container"
        assert log_entry_2["is_container"] is True, "Tiến trình Container (--pid=host/mntns khác) không được nhận diện đúng"

        print("\n[✓] Kiểm thử Assertion thành công 100%! Các luật, ngưỡng điểm và AlertLogger JSONL hoạt động hoàn toàn chính xác.")
    finally:
        if os.path.exists(tmp_log_path):
            os.remove(tmp_log_path)


def main():
    parser = argparse.ArgumentParser(description="Linux eBPF + ML Privilege Escalation Detector")
    parser.add_argument("--test-alert", action="store_true", help="Chạy kiểm thử logic cảnh báo giả lập bằng assertion mà không cần quyền root")
    parser.add_argument("--replay", type=str, default=None, help="Phát lại và đánh giá offline trên tệp telemetry (.jsonl hoặc .csv)")
    parser.add_argument("--alert-log", type=str, default=None, help="Đường dẫn file ghi cảnh báo JSONL (mặc định live: alerts.jsonl; mặc định --replay: tắt trừ khi chỉ định)")
    parser.add_argument("--no-log", action="store_true", help="Vô hiệu hóa việc ghi log ra file")
    parser.add_argument("--cooldown", type=float, default=2.0, help="Thời gian chống lặp cảnh báo cho cùng (tgid, rule) khi chạy (giây, mặc định: 2.0)")
    parser.add_argument("--quiet", action="store_true", help="Ẩn bảng cảnh báo Rich trên Terminal (vẫn ghi file JSONL nếu bật)")
    parser.add_argument("--models-dir", type=str, default=None, help="Thư mục chứa mô hình ML (.joblib) và dataset_summary.json")
    parser.add_argument("--ringbuf-pages", "--perf-pages", dest="ringbuf_pages", type=int, default=256, help="Số trang cho eBPF Ring Buffer (mặc định: 256)")
    parser.add_argument("--max-log-mb", type=float, default=50.0, help="Kích thước tối đa mỗi file log JSONL trước khi xoay vòng (MB, mặc định: 50.0)")
    parser.add_argument("--allow-untrusted-models", action="store_true", help="Cho phép nạp .joblib không thuộc sở hữu root khi chạy ở quyền root (chỉ dùng để kiểm thử)")
    parser.add_argument("--summary-out", type=str, default=None, help="Đường dẫn file JSON xuất kết quả tóm tắt khi chạy --replay")
    args = parser.parse_args()

    if not math.isfinite(args.cooldown) or args.cooldown < 0.0:
        print(f"[!] Lỗi: --cooldown phải là số không âm hữu hạn, nhận được {args.cooldown}", file=sys.stderr)
        sys.exit(1)

    if args.ringbuf_pages <= 0:
        print(f"[!] Lỗi: --ringbuf-pages phải > 0, nhận được {args.ringbuf_pages}", file=sys.stderr)
        sys.exit(1)

    if not math.isfinite(args.max_log_mb) or args.max_log_mb < 0.0:
        print(f"[!] Lỗi: --max-log-mb phải >= 0 và hữu hạn, nhận được {args.max_log_mb}", file=sys.stderr)
        sys.exit(1)

    if args.test_alert:
        run_test_alert()
        return

    if args.no_log:
        log_path = None
    elif args.replay:
        log_path = args.alert_log
    else:
        log_path = args.alert_log if args.alert_log is not None else "alerts.jsonl"

    if args.replay:
        try:
            run_replay(
                telemetry_file=args.replay,
                alert_log_path=log_path,
                quiet=args.quiet,
                models_dir=args.models_dir,
                cooldown=float(args.cooldown),
                summary_out=args.summary_out,
                allow_untrusted_models=args.allow_untrusted_models,
            )
        except Exception as e:
            print(f"\n[!] LỖI REPLAY TELEMETRY: {e}", file=sys.stderr)
            sys.exit(1)
        return

    max_log_bytes = int(args.max_log_mb * 1024 * 1024)
    detector = PrivEscDetector(
        models_dir=args.models_dir,
        alert_log_path=log_path,
        alert_cooldown_seconds=float(args.cooldown),
        quiet=args.quiet,
        allow_untrusted_models=args.allow_untrusted_models,
        max_log_bytes=max_log_bytes,
    )

    from agent.collector import BPFCollector

    def on_event(event_dict, feature_vec, raw_features, extractor):
        return detector.analyze(event_dict, feature_vec, raw_features, extractor)

    collector = BPFCollector(
        event_callback=on_event,
        exit_callback=detector.clear_process_cooldown,
        ringbuf_pages=args.ringbuf_pages,
    )
    if not collector.start():
        print("[!] Không thể khởi động eBPF collector.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
