"""
agent/detector.py: Công cụ phân tích và cảnh báo tấn công leo thang đặc quyền 2 tầng
  - Tầng 1 (Rule-based Fast Path): Bắt ngay lập tức các hành vi nhảy EUID=0, lạm dụng SUID, đọc trộm file nhạy cảm
  - Tầng 2 (ML-based Scoring): Chấm điểm bất thường và xác suất tấn công qua Random Forest & Isolation Forest
  - Tích hợp AlertLogger xuất file JSONL an toàn
"""

import os
import sys
import time
import argparse
import tempfile
import json
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
    WHITELISTED_SUID_BINS,
    SUSPICIOUS_DIRECTORIES,
    SERVICE_PARENT_NAMES,
    HIGH_RISK_CAPS,
    CAP_NAME_MAP,
    FeatureExtractor,
    is_suspicious_path,
    is_whitelisted_binary,
    extract_explicit_timestamp,
)
from agent.alert_logger import (
    AlertLogger,
    get_host_mntns_id,
    get_host_pidns_id,
    is_container_event,
)

# Sử dụng Rich để in giao diện cảnh báo đẹp mắt trên Terminal
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
except ImportError:
    console = None


SEVERITY_BASE_SCORE: Dict[str, int] = {
    "CRITICAL": 95,
    "HIGH": 85,
    "MEDIUM": 68,
    "LOW": 45,
    "INFO": 20,
}

SENSITIVE_OPEN_TARGETS = (
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/gshadow",
    "/etc/ld.so.preload",
)


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
    ):
        self.models_dir = Path(models_dir) if models_dir else (PROJECT_ROOT / "ml" / "models")
        self.scaler = None
        self.rf_model = None
        self.iso_model = None
        self.alert_cooldown_seconds = max(0.0, float(alert_cooldown_seconds))
        self.quiet = bool(quiet)
        self.host_mntns_id = get_host_mntns_id()
        self.host_pidns_id = get_host_pidns_id()
        self.logger = (
            AlertLogger(
                alert_log_path,
                host_mntns_id=self.host_mntns_id,
                host_pidns_id=self.host_pidns_id,
            )
            if alert_log_path
            else None
        )
        self._last_alert_ts: Dict[Tuple[int, str], float] = {}
        self.suppressed_alerts: int = 0
        self._load_models()

    def _load_models(self):
        scaler_file = self.models_dir / "scaler.joblib"
        rf_file = self.models_dir / "random_forest.joblib"
        iso_file = self.models_dir / "isolation_forest.joblib"

        if scaler_file.exists() and rf_file.exists() and iso_file.exists():
            try:
                self.scaler = joblib.load(scaler_file)
                self.rf_model = joblib.load(rf_file)
                self.iso_model = joblib.load(iso_file)
                if not self.quiet:
                    if console:
                        console.print(f"[bold green][✓] Đã nạp thành công mô hình ML từ {self.models_dir}[/bold green]")
                    else:
                        print(f"[✓] Đã nạp thành công mô hình ML từ {self.models_dir}")
            except Exception as e:
                print(f"[!] Cảnh báo: Lỗi nạp mô hình ML: {e}")
        else:
            if not self.quiet:
                if console:
                    console.print(f"[bold yellow][!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}. Hãy chạy 'python ml/train.py' trước.[/bold yellow]")
                else:
                    print(f"[!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}")

    def evaluate_all_rules(self, event: Dict[str, Any], raw_features: Dict[str, Any]) -> List[RuleMatch]:
        """
        Tầng 1: Đánh giá toàn bộ các luật theo thứ tự độ đặc hiệu giảm dần
        để tránh luật tổng quát che khuất (shadow) các luật đặc hiệu hơn.
        """
        matches: List[RuleMatch] = []
        e_type = event.get("event_type", 0)
        euid = 1000 if event.get("euid") is None else event.get("euid")
        uid = 1000 if event.get("uid") is None else event.get("uid")
        comm = event.get("comm") or ""
        filename = event.get("filename") or ""

        uid_change = raw_features.get("uid_change_flag", 0)
        suspicious_path = raw_features.get("suspicious_path_flag", 0)
        service_parent = raw_features.get("service_parent_flag", 0)

        exe_for_wl = filename if e_type == 1 else ""
        default_wl = 1 if (suspicious_path == 0 and is_whitelisted_binary(exe_for_wl, comm)) else 0
        is_whitelisted = raw_features.get("is_whitelisted_bin", default_wl)
        if suspicious_path == 1:
            is_whitelisted = 0

        bin_name = filename.split("/")[-1] if (e_type == 1 and filename) else (comm or filename.split("/")[-1])

        # 1. PRIVESC-001: commit_creds nhảy quyền EUID=0 từ tiến trình không nằm trong whitelist SUID
        if e_type == 2 and euid == 0 and uid != 0 and is_whitelisted == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-001",
                    name="RULE_COMMIT_CREDS_EUID_JUMP",
                    severity="CRITICAL",
                    mitre_id="T1548.001",
                    description="Tiến trình không đặc quyền gọi trực tiếp commit_creds để nhảy sang EUID=0",
                    rationale="Tiến trình người dùng thông thường không được phép tự cấp quyền root trừ khi qua binary xác thực chuẩn tại thư mục hệ thống tin cậy.",
                )
            )

        # 2. PRIVESC-005: Yêu cầu mở /etc/shadow, /etc/sudoers, /etc/gshadow, /etc/ld.so.preload trong bối cảnh nghi vấn
        if e_type == 4 and any(s in filename for s in SENSITIVE_OPEN_TARGETS):
            if is_whitelisted == 0 and (euid == 0 or suspicious_path == 1 or service_parent == 1):
                matches.append(
                    RuleMatch(
                        rule_id="PRIVESC-005",
                        name="RULE_SENSITIVE_FILE_ACCESS_ATTEMPT",
                        severity="HIGH",
                        mitre_id="T1003.008",
                        description=f"Yêu cầu mở file cấu hình nhạy cảm ({filename}) trong bối cảnh đáng ngờ",
                        rationale="Quan sát thấy syscall sys_enter_openat truy cập thông tin hash mật khẩu, phân quyền sudo hoặc cơ chế preload.",
                    )
                )

        # 3. PRIVESC-006: Kiểm tra Capability đặc quyền trong bối cảnh nghi vấn
        # LƯU Ý QUAN TRỌNG VỀ OBSERVABILITY:
        # Sự kiện kprobe cap_capable chỉ quan sát việc kernel thực hiện kiểm tra quyền (audit check),
        # KHÔNG khẳng định quyền đó được chấp thuận (allow) hay bị từ chối (deny/EPERM).
        # Chỉ phát tín hiệu đối với tiến trình không đặc quyền (uid != 0) ngoài whitelist và BẮT BUỘC có ngữ cảnh rủi ro tương quan.
        cap = event.get("cap")
        if e_type == 3 and cap in HIGH_RISK_CAPS:
            cap_label = CAP_NAME_MAP.get(cap, str(cap))
            correlated_cap_probe = (
                raw_features.get("cap_check_count", 0) >= 5
                and raw_features.get("sensitive_file_access", 0) >= 1
            )
            if uid != 0 and is_whitelisted == 0 and (
                suspicious_path == 1
                or service_parent == 1
                or uid_change == 1
                or correlated_cap_probe
            ):
                matches.append(
                    RuleMatch(
                        rule_id="PRIVESC-006",
                        name="RULE_PRIVILEGED_CAPABILITY_PROBE",
                        severity="MEDIUM",
                        mitre_id="T1548",
                        description=f"Tiến trình không đặc quyền ({comm}) kiểm tra capability đặc quyền ({cap_label}={cap}) trong bối cảnh rủi ro",
                        rationale="Quan sát thấy kiểm tra capability nhạy cảm kết hợp với thư mục tạm, phả hệ service, nhảy quyền hoặc truy cập file nhạy cảm. Probe chỉ ghi nhận kiểm tra tại entry, không xác nhận quyền đã được cấp.",
                    )
                )

        # 4. PRIVESC-004: Tiến trình cha là dịch vụ web/mạng (Nginx/Python/Node) nhảy quyền root hoặc sinh shell root
        if service_parent == 1 and (euid == 0 or uid_change == 1) and is_whitelisted == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-004",
                    name="RULE_SERVICE_SPAWNED_ROOT_SHELL",
                    severity="CRITICAL",
                    mitre_id="T1068",
                    description="Tiến trình bắt nguồn từ web/network service đang thực thi với quyền root",
                    rationale="Dấu hiệu điển hình của Web Shell hoặc Remote Code Execution (RCE) kết hợp leo quyền cục bộ.",
                )
            )

        # 5. PRIVESC-003: Thực thi mã từ thư mục tạm (/tmp, /dev/shm, memfd) khi đang có quyền root hoặc nhảy quyền
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

        # 6. PRIVESC-002: SUID binary abuse (GTFOBins) - Luật bao quát nhị phân ngoài whitelist với EUID 0
        if uid_change == 1 and is_whitelisted == 0 and euid == 0:
            matches.append(
                RuleMatch(
                    rule_id="PRIVESC-002",
                    name="RULE_GTFOBINS_SUID_ABUSE",
                    severity="CRITICAL",
                    mitre_id="T1548.001",
                    description=f"Nhị phân ngoài whitelist ({bin_name}) được thực thi và xác lập quyền root (EUID=0)",
                    rationale="Khai thác các nhị phân có SUID bit hoặc misconfiguration để thoát shell root.",
                )
            )

        return matches

    def evaluate_rules(self, event: Dict[str, Any], raw_features: Dict[str, Any]) -> Tuple[bool, Optional[RuleMatch]]:
        """
        Tầng 1: Rule-based Fast Path trả về luật đặc hiệu nhất được kích hoạt.
        Trả về: (is_attack, RuleMatch hoặc None)
        """
        matches = self.evaluate_all_rules(event, raw_features)
        if matches:
            return True, matches[0]
        return False, None

    def evaluate_ml(self, feature_vector: np.ndarray) -> Tuple[float, float, bool]:
        """
        Tầng 2: Machine Learning Anomaly & Classification
        Trả về: (rf_attack_probability, anomaly_score, is_ml_anomaly)
        """
        if self.scaler is None or self.rf_model is None or self.iso_model is None:
            return 0.0, 0.0, False

        arr = np.asarray(feature_vector, dtype=np.float64).reshape(1, -1)
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)
        try:
            feat_scaled = self.scaler.transform(arr)

            # 1. Random Forest Supervised Probability (tra cứu an toàn chỉ số lớp 1)
            proba_row = self.rf_model.predict_proba(feat_scaled)[0]
            classes = list(getattr(self.rf_model, "classes_", [0, 1]))
            if 1 in classes:
                rf_prob = float(proba_row[classes.index(1)])
            else:
                rf_prob = float(proba_row[-1])

            # 2. Isolation Forest Anomaly Score
            # decision_function: giá trị càng âm thì càng dị biệt (anomalous)
            iso_score = float(self.iso_model.decision_function(feat_scaled)[0])
            is_iso_outlier = bool(self.iso_model.predict(feat_scaled)[0] == -1)

            is_ml_anomaly = (rf_prob >= 0.65) or (is_iso_outlier and rf_prob >= 0.40)
            return rf_prob, iso_score, is_ml_anomaly
        except Exception:
            return 0.0, 0.0, False

    def analyze(self, event: Dict[str, Any], feature_vector: np.ndarray, raw_features: Dict[str, Any],
                extractor: Optional[FeatureExtractor] = None) -> Optional[Dict[str, Any]]:
        """
        Kết hợp 2 tầng phân tích để đưa ra quyết định cảnh báo toàn diện.
        Hỗ trợ chống lặp cảnh báo (alert cooldown) theo cặp (tgid, rule_id).
        Ghi log ra file JSONL nếu self.logger được cấu hình.
        Trả về alert_data nếu phát hiện bất thường, ngược lại trả về None.
        """
        matches = self.evaluate_all_rules(event, raw_features)
        rule_hit = len(matches) > 0
        match = matches[0] if rule_hit else None
        matched_rule_ids = [m.rule_id for m in matches]

        rf_prob, iso_score, ml_hit = self.evaluate_ml(feature_vector)

        # Tính toán điểm rủi ro tổng hợp (Composite Threat Score 0 - 100)
        rule_name = match.name if match else "N/A"
        rule_sev = match.severity if match else "INFO"
        ml_score = int(round(rf_prob * 80 + (20 if ml_hit else 0)))

        if rule_hit and match:
            base_rule_score = max(SEVERITY_BASE_SCORE.get(m.severity, 60) for m in matches)
            threat_score = min(100, max(base_rule_score, ml_score))
        else:
            threat_score = min(100, ml_score)

        # Chỉ kích hoạt cảnh báo khi phát hiện vi phạm luật hoặc ML đánh giá nguy hiểm (Threat Score >= 60)
        if rule_hit or ml_hit or threat_score >= 60:
            if self.alert_cooldown_seconds > 0:
                tgid_key = int(event.get("tgid") or 0)
                rule_key = match.rule_id if match else "ML_ANOMALY"
                dedup_key = (tgid_key, rule_key)
                now_ts = extract_explicit_timestamp(event)
                if now_ts is None:
                    now_ts = time.monotonic()
                last_ts = self._last_alert_ts.get(dedup_key)
                if last_ts is not None and 0.0 <= (now_ts - last_ts) < self.alert_cooldown_seconds:
                    self.suppressed_alerts += 1
                    return None
                self._last_alert_ts[dedup_key] = now_ts
                if len(self._last_alert_ts) > 4096:
                    cutoff = now_ts - self.alert_cooldown_seconds
                    self._last_alert_ts = {k: v for k, v in self._last_alert_ts.items() if v >= cutoff}

            alert_data = {
                "event": event,
                "raw_features": raw_features,
                "rule_name": rule_name,
                "rule_sev": rule_sev,
                "match": match,
                "matched_rules": matched_rule_ids,
                "rf_prob": rf_prob,
                "iso_score": iso_score,
                "threat_score": threat_score,
            }

            # In bảng cảnh báo Terminal
            if not self.quiet:
                self.display_alert(event, raw_features, rule_name, rule_sev, rf_prob, iso_score, threat_score, extractor)

            # Ghi log cảnh báo có cấu trúc JSONL an toàn
            if self.logger:
                self.logger.log_alert(alert_data)

            return alert_data

        return None

    def display_alert(self, event: Dict[str, Any], raw_features: Dict[str, Any],
                      rule_name: str, rule_sev: str, rf_prob: float,
                      iso_score: float, threat_score: int,
                      extractor: Optional[FeatureExtractor] = None):
        """Hiển thị bảng cảnh báo chi tiết theo phong cách SOC Dashboard"""
        is_container = is_container_event(
            event,
            host_mntns_id=self.host_mntns_id,
            host_pidns_id=self.host_pidns_id,
        )
        source_env = "CONTAINER / ISOLATED NS" if is_container else "HOST SYSTEM"

        sev_color = "bold red on black" if threat_score >= 80 else "bold yellow on black"

        if console:
            console.print()
            title_text = f"🚨 [BÁO ĐỘNG] PHÁT HIỆN TẤN CÔNG LEO THANG ĐẶC QUYỀN (THREAT SCORE: {threat_score}/100) 🚨"
            console.print(Panel(Text(title_text, justify="center", style=sev_color)))

            # Bảng thông tin tiến trình
            table = Table(title="Chi Tiết Tiến Trình & Môi Trường Bị Nghi Ngờ", show_header=True, header_style="bold magenta")
            table.add_column("Thuộc Tính", style="cyan", width=22)
            table.add_column("Giá Trị Telemetry eBPF", style="white")

            table.add_row(
                "Môi trường",
                f"[bold yellow]{source_env}[/bold yellow] (Cgroup: {event.get('cgroup_id')}, PidNS: {event.get('pidns_id')}, MntNS: {event.get('mntns_id')})",
            )
            table.add_row("Process / Thread ID", f"TGID={event.get('tgid')} | PID={event.get('pid')} | PPID={event.get('ppid')}")
            table.add_row("Executable (comm)", f"[bold red]{event.get('comm')}[/bold red]")
            table.add_row("Path / Target File", f"{event.get('filename') or '(N/A)'}")
            table.add_row("Chuyển quyền (UID -> EUID)", f"UID={event.get('uid')} -> [bold red]EUID={event.get('euid')}[/bold red]")
            table.add_row("Tầng 1 (Rule-Based)", f"[bold red]{rule_name}[/bold red] (Severity: {rule_sev})")
            table.add_row("Tầng 2 (Random Forest)", f"[bold green]{rf_prob * 100:.2f}%[/bold green] Xác suất tấn công")
            table.add_row("Tầng 2 (Isolation Forest)", f"Score: [bold cyan]{iso_score:.4f}[/bold cyan] ({'Bất thường' if iso_score < 0 else 'Bình thường'})")

            console.print(table)

            # Bảng đặc trưng (Features Table) - luôn duyệt đúng thứ tự FEATURE_NAMES
            f_table = Table(title="Vector 8 Đặc Trưng Hành Vi (Sliding Window 3s)", show_header=True, header_style="bold cyan")
            for fname in FEATURE_NAMES:
                f_table.add_column(fname, justify="center")

            row_cells: List[str] = []
            for name in FEATURE_NAMES:
                val = raw_features.get(name, 0)
                if (name in ("uid_change_flag", "suspicious_path_flag") and val == 1) or (name == "is_whitelisted_bin" and val == 0):
                    row_cells.append(f"[bold red]{val}[/bold red]")
                else:
                    row_cells.append(str(val))
            f_table.add_row(*row_cells)
            console.print(f_table)
            console.print("-" * 80)
        else:
            print(f"\n[!] BÁO ĐỘNG LEO THANG ĐẶC QUYỀN: {rule_name} | Score: {threat_score}/100")
            print(f"    PID: {event.get('tgid')}, Comm: {event.get('comm')}, Path: {event.get('filename')}")
            print(f"    UID: {event.get('uid')} -> EUID: {event.get('euid')}")
            print(f"    RF Prob: {rf_prob * 100:.1f}%, ISO Score: {iso_score:.3f}")
            print(f"    Features: {raw_features}")


def run_replay(telemetry_file: str, alert_log_path: Optional[str] = None, quiet: bool = False) -> Dict[str, Any]:
    """
    Chạy bộ phát hiện 2 tầng (Rule + ML) ngoại tuyến trên tệp telemetry có cấu trúc (.jsonl hoặc .csv).
    Cô lập FeatureExtractor theo từng session_id để tránh rò rỉ ngữ cảnh giữa các phiên.
    """
    from ml.telemetry_loader import TelemetryLoader

    loader = TelemetryLoader()
    lower_path = telemetry_file.lower()
    if lower_path.endswith(".jsonl"):
        events = loader.load_jsonl(telemetry_file)
    elif lower_path.endswith(".csv"):
        events = loader.load_csv(telemetry_file)
    else:
        raise ValueError("Định dạng file replay không được hỗ trợ. Vui lòng cung cấp file .jsonl hoặc .csv")

    detector = PrivEscDetector(alert_log_path=alert_log_path, alert_cooldown_seconds=0.0, quiet=quiet)
    extractors: Dict[str, FeatureExtractor] = {}

    tp = fp = tn = fn = 0
    evaluated_events = 0
    alerts_count = 0

    for ev in events:
        sid = str(ev.get("session_id", "default"))
        if sid not in extractors:
            extractors[sid] = FeatureExtractor(window_size_seconds=3.0)
        ext = extractors[sid]

        ev_type = int(ev.get("event_type", 0))
        tgid = int(ev.get("tgid", 0))
        ev_ts = extract_explicit_timestamp(ev)

        if ev_type == 5:
            ext.mark_process_exit(tgid, event_time=ev_ts)
            continue

        ext.update_process(
            pid=tgid,
            ppid=int(ev.get("ppid", 0) or 0),
            comm=str(ev.get("comm", "") or ""),
            uid=int(ev["uid"]),
            euid=int(ev["euid"]),
            cgroup_id=int(ev.get("cgroup_id", 0) or 0),
            mntns_id=int(ev.get("mntns_id", 0) or 0),
            event_time=ev_ts,
            pidns_id=int(ev.get("pidns_id", 0) or 0),
            exe_path=str(ev.get("filename", "") or "") if ev_type == 1 else None,
        )
        ext.add_event(ev)
        feat_vec, raw_feat = ext.extract_features(tgid, ev)
        alert = detector.analyze(ev, feat_vec, raw_feat, ext)

        predicted_attack = alert is not None
        if predicted_attack:
            alerts_count += 1

        evaluated_events += 1
        if "label" in ev:
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
        "sessions": len(extractors),
        "evaluated_events": evaluated_events,
        "alerts_triggered": alerts_count,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }

    print(f"\n[*] Kết quả Offline Replay ({telemetry_file}):")
    print(f"    Sessions: {len(extractors)} | Sự kiện phân tích: {evaluated_events} | Cảnh báo: {alerts_count}")
    print(f"    TP={tp}, FP={fp}, TN={tn}, FN={fn} | Precision={precision:.4f}, Recall={recall:.4f}, F1={f1:.4f}, FPR={fpr:.4f}")
    return summary


def run_test_alert():
    """Hàm tự kiểm thử bộ cảnh báo với dữ liệu giả lập sử dụng Assertion chặt chẽ và kiểm tra AlertLogger"""
    print("[*] Đang chạy kiểm thử bộ phân tích PrivEscDetector với các kịch bản mẫu và kiểm chứng Assertion...")

    # Sử dụng file log tạm thời để kiểm chứng tính năng AlertLogger
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_log:
        tmp_log_path = tmp_log.name

    try:
        detector = PrivEscDetector(alert_log_path=tmp_log_path, alert_cooldown_seconds=0.0)
        host_ns = detector.host_mntns_id or 4026531840
        container_ns = host_ns + 200

        # Kịch bản 1: SUID Abuse trên Host (find gán SUID gọi /bin/sh)
        print("\n--- Test Case 1: SUID Abuse (/usr/bin/find spawning shell with EUID=0) ---")
        event_1 = {
            "event_type": 1,
            "pid": 54321,
            "tgid": 54320,
            "ppid": 1000,
            "uid": 1000,
            "euid": 0,
            "cgroup_id": 4096,
            "mntns_id": host_ns,
            "comm": "find",
            "filename": "/usr/bin/find",
        }
        raw_feat_1 = {
            "exec_count": 4,
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,  # 0: unwhitelisted SUID abuse
            "suspicious_path_flag": 0,
            "service_parent_flag": 0,
            "sensitive_file_access": 1,
            "cap_check_count": 2,
            "priv_syscall_rate": 3.5,
        }
        feat_vec_1 = np.array([4, 1, 0, 0, 0, 1, 2, 3.5], dtype=np.float32)
        res_1 = detector.analyze(event_1, feat_vec_1, raw_feat_1)

        assert res_1 is not None, "Assertion Error: Case 1 không kích hoạt được cảnh báo!"
        assert res_1["rule_name"] == "RULE_GTFOBINS_SUID_ABUSE", f"Sai luật: {res_1['rule_name']}"
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
            "cgroup_id": 8192,
            "mntns_id": container_ns,
            "comm": "exploit",
            "filename": "/etc/shadow",
        }
        raw_feat_2 = {
            "exec_count": 6,
            "uid_change_flag": 1,
            "is_whitelisted_bin": 0,  # unwhitelisted
            "suspicious_path_flag": 1,
            "service_parent_flag": 0,
            "sensitive_file_access": 2,
            "cap_check_count": 3,
            "priv_syscall_rate": 5.0,
        }
        feat_vec_2 = np.array([6, 1, 0, 1, 0, 2, 3, 5.0], dtype=np.float32)
        res_2 = detector.analyze(event_2, feat_vec_2, raw_feat_2)

        assert res_2 is not None, "Assertion Error: Case 2 không kích hoạt được cảnh báo!"
        assert res_2["rule_name"] == "RULE_SENSITIVE_FILE_ACCESS_ATTEMPT", f"Sai luật: {res_2['rule_name']}"
        assert "PRIVESC-005" in res_2["matched_rules"], f"Thiếu PRIVESC-005 trong matched_rules: {res_2['matched_rules']}"
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
            "mntns_id": host_ns,
            "comm": "ls",
            "filename": "/usr/bin/ls",
        }
        raw_feat_3 = {
            "exec_count": 1,
            "uid_change_flag": 0,
            "is_whitelisted_bin": 0,  # bình thường
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
        assert log_entry_2["is_container"] is True, "Tiến trình Container không được nhận diện đúng"

        print("\n[✓] Kiểm thử Assertion thành công 100%! Các luật, ngưỡng điểm và AlertLogger JSONL hoạt động hoàn toàn chính xác.")
    finally:
        if os.path.exists(tmp_log_path):
            os.remove(tmp_log_path)


def main():
    parser = argparse.ArgumentParser(description="Linux eBPF + ML Privilege Escalation Detector")
    parser.add_argument("--test-alert", action="store_true", help="Chạy kiểm thử logic cảnh báo giả lập bằng assertion mà không cần quyền root")
    parser.add_argument("--replay", type=str, default=None, help="Phát lại và đánh giá offline trên tệp telemetry (.jsonl hoặc .csv)")
    parser.add_argument("--alert-log", type=str, default="alerts.jsonl", help="Đường dẫn file ghi cảnh báo JSONL (mặc định: alerts.jsonl)")
    parser.add_argument("--no-log", action="store_true", help="Vô hiệu hóa việc ghi log ra file")
    parser.add_argument("--cooldown", type=float, default=2.0, help="Thời gian chống lặp cảnh báo cho cùng (tgid, rule) khi chạy live (giây, mặc định: 2.0)")
    parser.add_argument("--quiet", action="store_true", help="Ẩn bảng cảnh báo Rich trên Terminal (vẫn ghi file JSONL nếu bật)")
    args = parser.parse_args()

    if args.test_alert:
        run_test_alert()
        return

    log_path = None if args.no_log else args.alert_log

    if args.replay:
        try:
            run_replay(telemetry_file=args.replay, alert_log_path=log_path, quiet=args.quiet)
        except Exception as e:
            print(f"\n[!] LỖI REPLAY TELEMETRY: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Khởi động Agent kết hợp eBPF Collector và AlertLogger
    detector = PrivEscDetector(
        alert_log_path=log_path,
        alert_cooldown_seconds=max(0.0, float(args.cooldown)),
        quiet=args.quiet,
    )

    from agent.collector import BPFCollector
    def on_event(event_dict, feature_vec, raw_features, extractor):
        return detector.analyze(event_dict, feature_vec, raw_features, extractor)

    collector = BPFCollector(event_callback=on_event)
    collector.start()


if __name__ == "__main__":
    main()
