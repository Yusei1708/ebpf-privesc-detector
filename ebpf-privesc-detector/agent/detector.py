"""
agent/detector.py: Công cụ phân tích và cảnh báo tấn công leo thang đặc quyền 2 tầng
  - Tầng 1 (Rule-based Fast Path): Bắt ngay lập tức các hành vi nhảy EUID=0, lạm dụng SUID, đọc trộm file nhạy cảm
  - Tầng 2 (ML-based Scoring): Chấm điểm bất thường và xác suất tấn công qua Random Forest & Isolation Forest
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import numpy as np
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import FEATURE_NAMES, WHITELISTED_SUID_BINS, SUSPICIOUS_PATH_PREFIXES, SERVICE_PARENT_NAMES, FeatureExtractor

# Sử dụng Rich để in giao diện cảnh báo đẹp mắt trên Terminal
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
except ImportError:
    console = None


class PrivEscDetector:
    """
    Hệ thống phát hiện tấn công tích hợp Rule-based Engine và Machine Learning
    """
    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = Path(models_dir) if models_dir else (PROJECT_ROOT / "ml" / "models")
        self.scaler = None
        self.rf_model = None
        self.iso_model = None
        self._load_models()

    def _load_models(self):
        scaler_file = self.models_dir / "scaler.joblib"
        rf_file = self.models_dir / "random_forest.joblib"
        iso_file = self.models_dir / "isolation_forest.joblib"

        if scaler_file.exists() and rf_file.exists() and iso_file.exists():
            self.scaler = joblib.load(scaler_file)
            self.rf_model = joblib.load(rf_file)
            self.iso_model = joblib.load(iso_file)
            if console:
                console.print(f"[bold green][✓] Đã nạp thành công mô hình ML từ {self.models_dir}[/bold green]")
            else:
                print(f"[✓] Đã nạp thành công mô hình ML từ {self.models_dir}")
        else:
            if console:
                console.print(f"[bold yellow][!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}. Hãy chạy 'python ml/train.py' trước.[/bold yellow]")
            else:
                print(f"[!] Cảnh báo: Chưa tìm thấy mô hình ML tại {self.models_dir}")

    def evaluate_rules(self, event: Dict[str, Any], raw_features: Dict[str, Any]) -> Tuple[bool, str, str]:
        """
        Tầng 1: Rule-based Fast Path
        Kiểm tra các quy tắc cứng để bắt ngay lập tức các cuộc tấn công leo quyền.
        Trả về: (is_attack, rule_name, severity)
        """
        e_type = event.get("event_type", 0)
        euid = event.get("euid", 1000)
        uid = event.get("uid", 1000)
        comm = event.get("comm", "")
        filename = event.get("filename", "")
        bin_name = filename.split("/")[-1] if filename else comm

        # Quy tắc 1: commit_creds nhảy quyền EUID=0 từ tiến trình không nằm trong whitelist SUID
        if e_type == 2:  # commit_creds
            if euid == 0 and uid != 0:
                if bin_name not in WHITELISTED_SUID_BINS:
                    return True, "RULE_UNAUTHORIZED_EUID_ZERO_JUMP", "CRITICAL"

        # Quy tắc 2: SUID binary abuse (GTFOBins) - Chạy nhị phân không thuộc whitelist với EUID 0
        if raw_features.get("uid_change_flag") == 1 and raw_features.get("is_whitelisted_bin") == 1:
            return True, "RULE_GTFOBINS_SUID_ABUSE", "CRITICAL"

        # Quy tắc 3: Thực thi mã từ thư mục tạm (/tmp, /dev/shm) khi đang có quyền root hoặc nhảy quyền
        if raw_features.get("suspicious_path_flag") == 1 and (euid == 0 or raw_features.get("uid_change_flag") == 1):
            return True, "RULE_ROOT_EXECUTION_FROM_SUSPICIOUS_PATH", "HIGH"

        # Quy tắc 4: Tiến trình cha là dịch vụ web/mạng (Nginx/Python/Node) nhảy quyền root hoặc sinh shell root
        if raw_features.get("service_parent_flag") == 1 and (euid == 0 or raw_features.get("uid_change_flag") == 1):
            return True, "RULE_SERVICE_PARENT_ESCALATION", "CRITICAL"

        # Quy tắc 5: Đọc trái phép /etc/shadow hoặc /etc/sudoers bởi tiến trình không phải root thông thường
        if e_type == 4:  # openat
            if any(s in filename for s in ["/etc/shadow", "/etc/sudoers"]):
                if uid != 0 and bin_name not in WHITELISTED_SUID_BINS:
                    return True, "RULE_SENSITIVE_CREDENTIAL_THEFT", "HIGH"

        # Quy tắc 6: Lạm dụng Capability (CAP_SETUID / CAP_SYS_ADMIN)
        if e_type == 3 and event.get("cap") in (10, 21):  # CAP_SETUID, CAP_SYS_ADMIN
            if uid != 0 and bin_name not in WHITELISTED_SUID_BINS:
                return True, "RULE_PRIVILEGED_CAPABILITY_ABUSE", "HIGH"

        return False, "", "INFO"

    def evaluate_ml(self, feature_vector: np.ndarray) -> Tuple[float, float, bool]:
        """
        Tầng 2: Machine Learning Anomaly & Classification
        Trả về: (rf_attack_probability, anomaly_score, is_ml_anomaly)
        """
        if self.scaler is None or self.rf_model is None or self.iso_model is None:
            return 0.0, 0.0, False

        feat_2d = feature_vector.reshape(1, -1)
        feat_scaled = self.scaler.transform(feat_2d)

        # 1. Random Forest Supervised Probability
        rf_prob = float(self.rf_model.predict_proba(feat_scaled)[0, 1])

        # 2. Isolation Forest Anomaly Score
        # decision_function: giá trị càng âm thì càng dị biệt (anomalous)
        iso_score = float(self.iso_model.decision_function(feat_scaled)[0])
        is_iso_outlier = bool(self.iso_model.predict(feat_scaled)[0] == -1)

        is_ml_anomaly = (rf_prob >= 0.65) or (is_iso_outlier and rf_prob >= 0.40)
        return rf_prob, iso_score, is_ml_anomaly

    def analyze(self, event: Dict[str, Any], feature_vector: np.ndarray, raw_features: Dict[str, Any], extractor: Optional[FeatureExtractor] = None):
        """
        Kết hợp 2 tầng phân tích để đưa ra quyết định cảnh báo toàn diện
        """
        rule_hit, rule_name, rule_sev = self.evaluate_rules(event, raw_features)
        rf_prob, iso_score, ml_hit = self.evaluate_ml(feature_vector)

        # Tính toán điểm rủi ro tổng hợp (Composite Threat Score 0 - 100)
        threat_score = 0
        if rule_hit:
            threat_score = 95 if rule_sev == "CRITICAL" else 85
        else:
            threat_score = int(rf_prob * 80 + (20 if ml_hit else 0))

        # Chỉ cảnh báo khi phát hiện vi phạm luật hoặc ML đánh giá nguy hiểm
        if rule_hit or ml_hit or threat_score >= 60:
            self.display_alert(event, raw_features, rule_name, rule_sev, rf_prob, iso_score, threat_score, extractor)

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
            table.add_row("Tầng 1 (Rule-Based)", f"[bold red]{rule_name or 'N/A'}[/bold red] (Severity: {rule_sev})")
            table.add_row("Tầng 2 (Random Forest)", f"[bold green]{rf_prob * 100:.2f}%[/bold green] Xác suất tấn công")
            table.add_row("Tầng 2 (Isolation Forest)", f"Score: [bold cyan]{iso_score:.4f}[/bold cyan] ({'Bất thường' if iso_score < 0 else 'Bình thường'})")

            console.print(table)

            # Bảng đặc trưng (Features Table)
            f_table = Table(title="Vector 8 Đặc Trưng Hành Vi (Sliding Window 3s)", show_header=True, header_style="bold cyan")
            for fname in FEATURE_NAMES:
                f_table.add_column(fname, justify="center")

            f_table.add_row(*[
                f"[bold red]{val}[/bold red]" if (name in ("uid_change_flag", "is_whitelisted_bin", "suspicious_path_flag") and val == 1) else str(val)
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
    """Hàm tự kiểm thử bộ cảnh báo với dữ liệu giả lập (Không cần root hay nạp probe)"""
    print("[*] Đang chạy kiểm thử bộ phân tích PrivEscDetector với các kịch bản mẫu...")
    detector = PrivEscDetector()

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
        "is_whitelisted_bin": 1,
        "suspicious_path_flag": 0,
        "service_parent_flag": 0,
        "sensitive_file_access": 1,
        "cap_check_count": 2,
        "priv_syscall_rate": 3.5,
    }
    feat_vec_1 = np.array([4, 1, 1, 0, 0, 1, 2, 3.5], dtype=np.float32)
    detector.analyze(event_1, feat_vec_1, raw_feat_1)

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
        "is_whitelisted_bin": 1,
        "suspicious_path_flag": 1,
        "service_parent_flag": 0,
        "sensitive_file_access": 2,
        "cap_check_count": 3,
        "priv_syscall_rate": 5.0,
    }
    feat_vec_2 = np.array([6, 1, 1, 1, 0, 2, 3, 5.0], dtype=np.float32)
    detector.analyze(event_2, feat_vec_2, raw_feat_2)

    print("\n[✓] Kiểm thử thành công 100%! Bộ Detector hoạt động chính xác.")


def main():
    parser = argparse.ArgumentParser(description="Linux eBPF + ML Privilege Escalation Detector")
    parser.add_argument("--test-alert", action="store_true", help="Chạy kiểm thử logic cảnh báo giả lập mà không cần quyền root")
    args = parser.parse_args()

    if args.test_alert:
        run_test_alert()
        return

    # Khởi động Agent kết hợp eBPF Collector
    detector = PrivEscDetector()

    from agent.collector import BPFCollector
    def on_event(event_dict, feature_vec, raw_features, extractor):
        detector.analyze(event_dict, feature_vec, raw_features, extractor)

    collector = BPFCollector(event_callback=on_event)
    collector.start()


if __name__ == "__main__":
    main()
