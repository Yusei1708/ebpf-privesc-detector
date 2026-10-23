"""
agent/detector.py: Công cụ phân tích và cảnh báo tấn công leo thang đặc quyền 2 tầng
  - Tầng 1 (Rule-based Fast Path): Bắt ngay lập tức các hành vi nhảy EUID=0, lạm dụng SUID, đọc trộm file nhạy cảm
  - Tầng 2 (ML-based Scoring): Chấm điểm bất thường và xác suất tấn công qua Random Forest & Isolation Forest
  - Tích hợp AlertLogger xuất file JSONL an toàn
"""

import os
import sys
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
    FeatureExtractor,
    is_suspicious_path,
)
from agent.alert_logger import AlertLogger

# Sử dụng Rich để in giao diện cảnh báo đẹp mắt trên Terminal
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
except ImportError:
    console = None


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
    def __init__(self, models_dir: Optional[str] = None, alert_log_path: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else (PROJECT_ROOT / "ml" / "models")
        self.scaler = None
        self.rf_model = None
        self.iso_model = None
        self.logger = AlertLogger(alert_log_path) if alert_log_path else None
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
                if console:
                    console.print(f"[bold green][✓] Đã nạp thành công mô hình ML từ {self.models_dir}[/bold green]")
                else:
                    print(f"[✓] Đã nạp thành công mô hình ML từ {self.models_dir}")
            except Exception as e:
                print(f"[!] Cảnh báo: Lỗi nạp mô hình ML: {e}")
        else:
            if console:
                console.print(f"[bold yellow][!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}. Hãy chạy 'python ml/train.py' trước.[/bold yellow]")
            else:
                print(f"[!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}")

    def evaluate_rules(self, event: Dict[str, Any], raw_features: Dict[str, Any]) -> Tuple[bool, Optional[RuleMatch]]:
        """
        Tầng 1: Rule-based Fast Path với kiểm tra điều kiện chặt chẽ nhằm giảm False Positive.
        Trả về: (is_attack, RuleMatch hoặc None)
        """
        e_type = event.get("event_type", 0)
        euid = event.get("euid", 1000)
        uid = event.get("uid", 1000)
        comm = event.get("comm", "")
        filename = event.get("filename", "")
        bin_name = filename.split("/")[-1] if filename else comm

        is_whitelisted = raw_features.get("is_whitelisted_bin", 1 if bin_name in WHITELISTED_SUID_BINS else 0)
        uid_change = raw_features.get("uid_change_flag", 0)
        suspicious_path = raw_features.get("suspicious_path_flag", 0)
        service_parent = raw_features.get("service_parent_flag", 0)

        # 1. PRIVESC-001: commit_creds nhảy quyền EUID=0 từ tiến trình không nằm trong whitelist SUID
        if e_type == 2:  # commit_creds
            if euid == 0 and uid != 0 and is_whitelisted == 0:
                return True, RuleMatch(
                    rule_id="PRIVESC-001",
                    name="RULE_COMMIT_CREDS_EUID_JUMP",
                    severity="CRITICAL",
                    mitre_id="T1548.001",
                    description="Tiến trình không đặc quyền gọi trực tiếp commit_creds để nhảy sang EUID=0",
                    rationale="Tiến trình người dùng thông thường không được phép tự cấp quyền root trừ khi qua binary xác thực chuẩn như sudo/su.",
                )

        # 2. PRIVESC-002: SUID binary abuse (GTFOBins) - Chạy nhị phân ngoài whitelist với EUID 0
        if uid_change == 1 and is_whitelisted == 0 and euid == 0:
            return True, RuleMatch(
                rule_id="PRIVESC-002",
                name="RULE_GTFOBINS_SUID_ABUSE",
                severity="CRITICAL",
                mitre_id="T1548.001",
                description=f"Nhị phân ngoài whitelist ({bin_name}) được thực thi và xác lập quyền root (EUID=0)",
                rationale="Khai thác các nhị phân có SUID bit hoặc misconfiguration để thoát shell root.",
            )

        # 3. PRIVESC-003: Thực thi mã từ thư mục tạm (/tmp, /dev/shm) khi đang có quyền root hoặc nhảy quyền
        if suspicious_path == 1 and (euid == 0 or uid_change == 1) and is_whitelisted == 0:
            return True, RuleMatch(
                rule_id="PRIVESC-003",
                name="RULE_SUSPICIOUS_PATH_PRIV_EXEC",
                severity="HIGH",
                mitre_id="T1059",
                description=f"Thực thi mã từ thư mục tạm ({filename or comm}) với đặc quyền quản trị viên",
                rationale="Kẻ tấn công thường biên dịch hoặc tải exploit payload vào /tmp hoặc /dev/shm rồi chạy với quyền root.",
            )

        # 4. PRIVESC-004: Tiến trình cha là dịch vụ web/mạng (Nginx/Python/Node) nhảy quyền root hoặc sinh shell root
        if service_parent == 1 and (euid == 0 or uid_change == 1) and is_whitelisted == 0:
            return True, RuleMatch(
                rule_id="PRIVESC-004",
                name="RULE_SERVICE_SPAWNED_ROOT_SHELL",
                severity="CRITICAL",
                mitre_id="T1068",
                description="Tiến trình bắt nguồn từ web/network service đang thực thi với quyền root",
                rationale="Dấu hiệu điển hình của Web Shell hoặc Remote Code Execution (RCE) kết hợp leo quyền cục bộ.",
            )

        # 5. PRIVESC-005: Yêu cầu mở /etc/shadow hoặc /etc/sudoers (Chỉ cảnh báo khi có bối cảnh nghi vấn)
        if e_type == 4:  # openat
            if any(s in filename for s in ["/etc/shadow", "/etc/sudoers"]):
                # Giảm cảnh báo sai: Chỉ báo động HIGH nếu tiến trình chạy từ path lạ, là con của service, hoặc có EUID=0 ngoài whitelist
                if is_whitelisted == 0 and (euid == 0 or suspicious_path == 1 or service_parent == 1):
                    return True, RuleMatch(
                        rule_id="PRIVESC-005",
                        name="RULE_SENSITIVE_FILE_ACCESS_ATTEMPT",
                        severity="HIGH",
                        mitre_id="T1003.008",
                        description=f"Yêu cầu mở file cấu hình nhạy cảm ({filename}) trong bối cảnh đáng ngờ",
                        rationale="Quan sát thấy syscall sys_enter_openat truy cập thông tin hash mật khẩu hoặc phân quyền sudo.",
                    )

        # 6. PRIVESC-006: Kiểm tra Capability đặc quyền trong bối cảnh nghi vấn
        # LƯU Ý QUAN TRỌNG VỀ OBSERVABILITY:
        # Sự kiện kprobe cap_capable chỉ quan sát việc kernel thực hiện kiểm tra quyền (audit check),
        # KHÔNG khẳng định quyền đó được chấp thuận (allow) hay bị từ chối (deny/EPERM).
        # Nhiều ứng dụng người dùng thông thường cũng có thể kích hoạt kiểm tra này trong glibc.
        # Để tránh cảnh báo sai, chỉ phát tín hiệu khi có thêm bối cảnh bất thường:
        # thực thi từ thư mục tạm, tiến trình con của web service, hoặc đi kèm nhảy quyền EUID.
        if e_type == 3 and event.get("cap") in (10, 21):  # CAP_SETUID (10), CAP_SYS_ADMIN (21)
            if is_whitelisted == 0 and (suspicious_path == 1 or service_parent == 1 or uid_change == 1 or raw_features.get("cap_check_count", 0) >= 5):
                return True, RuleMatch(
                    rule_id="PRIVESC-006",
                    name="RULE_PRIVILEGED_CAPABILITY_PROBE",
                    severity="MEDIUM",
                    mitre_id="T1548",
                    description=f"Tiến trình nghi vấn ({comm}) kiểm tra capability đặc quyền (CAP={event.get('cap')}) trong bối cảnh rủi ro",
                    rationale="Quan sát thấy kiểm tra capability nhạy cảm kết hợp với thư mục tạm hoặc phả hệ service. Lưu ý probe chỉ ghi nhận kiểm tra tại entry, không xác nhận quyền đã được cấp.",
                )

        return False, None

    def evaluate_ml(self, feature_vector: np.ndarray) -> Tuple[float, float, bool]:
        """
        Tầng 2: Machine Learning Anomaly & Classification
        Trả về: (rf_attack_probability, anomaly_score, is_ml_anomaly)
        """
        if self.scaler is None or self.rf_model is None or self.iso_model is None:
            return 0.0, 0.0, False

        feat_2d = feature_vector.reshape(1, -1)
        try:
            feat_scaled = self.scaler.transform(feat_2d)

            # 1. Random Forest Supervised Probability
            rf_prob = float(self.rf_model.predict_proba(feat_scaled)[0, 1])

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
        Ghi log ra file JSONL nếu self.logger được cấu hình.
        Trả về alert_data nếu phát hiện bất thường, ngược lại trả về None.
        """
        rule_hit, match = self.evaluate_rules(event, raw_features)
        rf_prob, iso_score, ml_hit = self.evaluate_ml(feature_vector)

        # Tính toán điểm rủi ro tổng hợp (Composite Threat Score 0 - 100)
        threat_score = 0
        rule_name = match.name if match else "N/A"
        rule_sev = match.severity if match else "INFO"

        if rule_hit and match:
            threat_score = 95 if match.severity == "CRITICAL" else 85
        else:
            threat_score = int(rf_prob * 80 + (20 if ml_hit else 0))

        # Chỉ kích hoạt cảnh báo khi phát hiện vi phạm luật hoặc ML đánh giá nguy hiểm (Threat Score >= 60)
        if rule_hit or ml_hit or threat_score >= 60:
            alert_data = {
                "event": event,
                "raw_features": raw_features,
                "rule_name": rule_name,
                "rule_sev": rule_sev,
                "match": match,
                "rf_prob": rf_prob,
                "iso_score": iso_score,
                "threat_score": threat_score,
            }

            # In bảng cảnh báo Terminal
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
        is_container = (event.get("cgroup_id", 0) != 0 and event.get("mntns_id", 0) != 0)
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

            table.add_row("Môi trường", f"[bold yellow]{source_env}[/bold yellow] (Cgroup: {event.get('cgroup_id')}, MntNS: {event.get('mntns_id')})")
            table.add_row("Process / Thread ID", f"TGID={event.get('tgid')} | PID={event.get('pid')} | PPID={event.get('ppid')}")
            table.add_row("Executable (comm)", f"[bold red]{event.get('comm')}[/bold red]")
            table.add_row("Path / Target File", f"{event.get('filename') or '(N/A)'}")
            table.add_row("Chuyển quyền (UID -> EUID)", f"UID={event.get('uid')} -> [bold red]EUID={event.get('euid')}[/bold red]")
            table.add_row("Tầng 1 (Rule-Based)", f"[bold red]{rule_name}[/bold red] (Severity: {rule_sev})")
            table.add_row("Tầng 2 (Random Forest)", f"[bold green]{rf_prob * 100:.2f}%[/bold green] Xác suất tấn công")
            table.add_row("Tầng 2 (Isolation Forest)", f"Score: [bold cyan]{iso_score:.4f}[/bold cyan] ({'Bất thường' if iso_score < 0 else 'Bình thường'})")

            console.print(table)

            # Bảng đặc trưng (Features Table)
            f_table = Table(title="Vector 8 Đặc Trưng Hành Vi (Sliding Window 3s)", show_header=True, header_style="bold cyan")
            for fname in FEATURE_NAMES:
                f_table.add_column(fname, justify="center")

            f_table.add_row(*[
                f"[bold red]{val}[/bold red]" if (name in ("uid_change_flag", "suspicious_path_flag") and val == 1) or (name == "is_whitelisted_bin" and val == 0) else str(val)
                for name, val in raw_features.items()
            ])
            console.print(f_table)
            console.print("-" * 80)
        else:
            print(f"\n[!] BÁO ĐỘNG LEO THANG ĐẶC QUYỀN: {rule_name} | Score: {threat_score}/100")
            print(f"    PID: {event.get('tgid')}, Comm: {event.get('comm')}, Path: {event.get('filename')}")
            print(f"    UID: {event.get('uid')} -> EUID: {event.get('euid')}")
            print(f"    RF Prob: {rf_prob * 100:.1f}%, ISO Score: {iso_score:.3f}")
            print(f"    Features: {raw_features}")


def run_test_alert():
    """Hàm tự kiểm thử bộ cảnh báo với dữ liệu giả lập sử dụng Assertion chặt chẽ và kiểm tra AlertLogger"""
    print("[*] Đang chạy kiểm thử bộ phân tích PrivEscDetector với các kịch bản mẫu và kiểm chứng Assertion...")

    # Sử dụng file log tạm thời để kiểm chứng tính năng AlertLogger
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_log:
        tmp_log_path = tmp_log.name

    try:
        detector = PrivEscDetector(alert_log_path=tmp_log_path)

        # Kịch bản 1: SUID Abuse (find gán SUID gọi /bin/sh)
        print("\n--- Test Case 1: SUID Abuse (/usr/bin/find spawning shell with EUID=0) ---")
        event_1 = {
            "event_type": 1,
            "pid": 54321,
            "tgid": 54320,
            "ppid": 1000,
            "uid": 1000,
            "euid": 0,
            "cgroup_id": 4096,
            "mntns_id": 4026531840,
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

        # Kịch bản 2: Exploit từ thư mục /tmp đọc /etc/shadow
        print("\n--- Test Case 2: Exploit Drop trong /tmp đọc trộm /etc/shadow ---")
        event_2 = {
            "event_type": 4,
            "pid": 55112,
            "tgid": 55110,
            "ppid": 2040,
            "uid": 1000,
            "euid": 0,
            "cgroup_id": 8192,
            "mntns_id": 4026532200,
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
            "cgroup_id": 0,
            "mntns_id": 4026531840,
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
        log_entry = json.loads(lines[0])
        assert "timestamp" in log_entry, "Thiếu trường timestamp trong JSONL"
        assert log_entry["threat_score"] >= 80, "Threat score trong log không khớp"
        assert log_entry["comm"] == "find", "Comm trong log không khớp"

        print("\n[✓] Kiểm thử Assertion thành công 100%! Các luật, ngưỡng điểm và AlertLogger JSONL hoạt động hoàn toàn chính xác.")
    finally:
        if os.path.exists(tmp_log_path):
            os.remove(tmp_log_path)


def main():
    parser = argparse.ArgumentParser(description="Linux eBPF + ML Privilege Escalation Detector")
    parser.add_argument("--test-alert", action="store_true", help="Chạy kiểm thử logic cảnh báo giả lập bằng assertion mà không cần quyền root")
    parser.add_argument("--alert-log", type=str, default="alerts.jsonl", help="Đường dẫn file ghi cảnh báo JSONL (mặc định: alerts.jsonl)")
    parser.add_argument("--no-log", action="store_true", help="Vô hiệu hóa việc ghi log ra file")
    args = parser.parse_args()

    if args.test_alert:
        run_test_alert()
        return

    log_path = None if args.no_log else args.alert_log

    # Khởi động Agent kết hợp eBPF Collector và AlertLogger
    detector = PrivEscDetector(alert_log_path=log_path)

    from agent.collector import BPFCollector
    def on_event(event_dict, feature_vec, raw_features, extractor):
        detector.analyze(event_dict, feature_vec, raw_features, extractor)

    collector = BPFCollector(event_callback=on_event)
    collector.start()


if __name__ == "__main__":
    main()
