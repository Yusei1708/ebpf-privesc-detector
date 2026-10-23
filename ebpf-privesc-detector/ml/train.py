"""
ml/train.py: Huấn luyện mô hình Machine Learning phát hiện tấn công leo thang đặc quyền
Sử dụng kết hợp:
  1. Isolation Forest: Unsupervised Anomaly Detection (Phát hiện kỹ thuật zero-day / hành vi lạ)
  2. Random Forest: Supervised Classification (Phát hiện chính xác các mẫu tấn công đã biết)
Đảm bảo:
  - Tách train/test theo session_id (GroupShuffleSplit) để chống rò rỉ dữ liệu (Data Leakage)
  - Tính toán và lưu trữ FPR, FNR, Precision, Recall, F1, Confusion Matrix
  - Hỗ trợ nạp telemetry gán nhãn thực tế qua --telemetry-file
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Optional
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

from agent.features import FEATURE_NAMES

MODELS_DIR = PROJECT_ROOT / "ml" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def generate_synthetic_telemetry(n_sessions: int = 500) -> pd.DataFrame:
    """
    Tạo tập dữ liệu mô phỏng theo từng phiên làm việc (sessions) để phân chia train/test theo nhóm:
    - 85% Sessions bình thường (Benign developers, web daemon, admin sudo hợp lệ)
    - 15% Sessions tấn công (SUID abuse, dropped exploit /tmp, web shell privilege escalation)
    """
    np.random.seed(42)
    session_rows = []

    for sid in range(n_sessions):
        is_attack_session = (np.random.rand() < 0.15)
        session_name = f"session_{sid:04d}"
        session_len = np.random.randint(5, 25)

        if not is_attack_session:
            # 80% user bình thường, 20% admin dùng sudo hợp lệ
            is_admin_sudo = (np.random.rand() < 0.20)
            for _ in range(session_len):
                if is_admin_sudo:
                    exec_c = np.random.poisson(lam=2.5)
                    uid_ch = np.random.choice([0, 1], p=[0.2, 0.8])
                    is_white = 1  # 1: binary trong whitelist (sudo, su)
                    susp_p = 0
                    serv_p = 0
                    sens_f = np.random.choice([0, 1], p=[0.9, 0.1])
                    cap_c = np.random.poisson(lam=1.0)
                    priv_r = np.random.uniform(0.5, 2.0)
                else:
                    exec_c = np.random.poisson(lam=1.2)
                    uid_ch = 0
                    is_white = 0  # bình thường
                    susp_p = int(np.random.rand() < 0.01)
                    serv_p = int(np.random.rand() < 0.02)
                    sens_f = 0
                    cap_c = int(np.random.rand() < 0.02)
                    priv_r = np.random.uniform(0.1, 1.0)

                session_rows.append({
                    "session_id": session_name,
                    "exec_count": exec_c,
                    "uid_change_flag": uid_ch,
                    "is_whitelisted_bin": is_white,
                    "suspicious_path_flag": susp_p,
                    "service_parent_flag": serv_p,
                    "sensitive_file_access": sens_f,
                    "cap_check_count": cap_c,
                    "priv_syscall_rate": round(priv_r, 2),
                    "label": 0,
                })
        else:
            # Session tấn công
            attack_type = np.random.choice(["suid_abuse", "tmp_exploit", "webshell"])
            for step in range(session_len):
                # Các bước đầu có thể là trinh sát (benign), các bước sau là khai thác (attack)
                is_exploit_step = (step >= (session_len // 2))

                if not is_exploit_step:
                    # Giai đoạn thăm dò trước khai thác
                    exec_c = np.random.poisson(lam=1.5)
                    uid_ch = 0
                    is_white = 0
                    susp_p = int(attack_type == "tmp_exploit")
                    serv_p = int(attack_type == "webshell")
                    sens_f = 0
                    cap_c = 0
                    priv_r = np.random.uniform(0.5, 1.5)
                    lbl = 0
                else:
                    # Giai đoạn kích hoạt leo thang đặc quyền
                    exec_c = np.random.poisson(lam=5.0)
                    uid_ch = 1
                    is_white = 0  # 0: binary unwhitelisted (find, bash, custom exploit)
                    susp_p = 1 if attack_type == "tmp_exploit" else int(np.random.rand() < 0.4)
                    serv_p = 1 if attack_type == "webshell" else 0
                    sens_f = np.random.choice([1, 2, 3], p=[0.5, 0.3, 0.2])
                    cap_c = np.random.poisson(lam=2.5)
                    priv_r = np.random.uniform(3.0, 8.0)
                    lbl = 1

                session_rows.append({
                    "session_id": session_name,
                    "exec_count": exec_c,
                    "uid_change_flag": uid_ch,
                    "is_whitelisted_bin": is_white,
                    "suspicious_path_flag": susp_p,
                    "service_parent_flag": serv_p,
                    "sensitive_file_access": sens_f,
                    "cap_check_count": cap_c,
                    "priv_syscall_rate": round(priv_r, 2),
                    "label": lbl,
                })

    df = pd.DataFrame(session_rows)
    return df


def train_models(telemetry_file: Optional[str] = None, check_only: bool = False):
    print("[*] Đang khởi tạo quy trình huấn luyện Machine Learning phát hiện Privilege Escalation...")

    if telemetry_file:
        print(f"[*] Đang nạp dữ liệu telemetry thực tế từ: {telemetry_file}")
        from ml.telemetry_loader import TelemetryLoader
        loader = TelemetryLoader()
        if telemetry_file.endswith(".jsonl"):
            events = loader.load_jsonl(telemetry_file)
        elif telemetry_file.endswith(".csv"):
            events = loader.load_csv(telemetry_file)
        else:
            raise ValueError("Định dạng file không được hỗ trợ. Vui lòng cung cấp file .jsonl hoặc .csv")
        df = loader.convert_events_to_features(events)
        data_source = f"Real Telemetry File: {telemetry_file}"
    else:
        print("[*] Sử dụng tập dữ liệu mô phỏng baseline (Synthetic Telemetry Sessions)...")
        df = generate_synthetic_telemetry(n_sessions=600)
        data_source = "Synthetic Baseline Simulation (Grouped Sessions)"

    print(f"[+] Tổng số mẫu dữ liệu: {len(df)} (Bình thường: {sum(df['label'] == 0)}, Tấn công: {sum(df['label'] == 1)})")
    print(f"[+] Số phiên (sessions): {df['session_id'].nunique()}")

    if check_only:
        print("[✓] Kiểm tra cú pháp và dữ liệu hoàn tất (Check-only mode).")
        return

    # Phân chia train/test theo GroupShuffleSplit dựa trên session_id nhằm chống rò rỉ dữ liệu (Data Leakage)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df["session_id"]))

    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]

    X_train = train_df[FEATURE_NAMES].values
    y_train = train_df["label"].values
    X_test = test_df[FEATURE_NAMES].values
    y_test = test_df["label"].values

    print(f"[*] Tập huấn luyện: {len(train_df)} mẫu | Tập kiểm thử độc lập: {len(test_df)} mẫu")

    # 1. Chuẩn hóa dữ liệu bằng StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 2. Huấn luyện Random Forest Classifier (Supervised)
    print("\n[*] Đang huấn luyện Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf_model.fit(X_train_scaled, y_train)

    # Đánh giá Random Forest
    rf_pred = rf_model.predict(X_test_scaled)
    rf_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
    rf_auc = roc_auc_score(y_test, rf_proba)
    cm = confusion_matrix(y_test, rf_pred)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0
    fnr = float(fn) / float(fn + tp) if (fn + tp) > 0 else 0.0
    precision = float(tp) / float(tp + fp) if (tp + fp) > 0 else 0.0
    recall = float(tp) / float(tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n--- KẾT QUẢ ĐÁNH GIÁ RANDOM FOREST TRÊN TẬP KIỂM THỬ ĐỘC LẬP ---")
    print(classification_report(y_test, rf_pred, target_names=["Benign", "Attack"]))
    print(f"ROC-AUC Score:          {rf_auc:.4f}")
    print(f"False Positive Rate (FPR): {fpr * 100:.2f}%")
    print(f"False Negative Rate (FNR): {fnr * 100:.2f}%")
    print("Confusion Matrix:")
    print(cm)

    # Tầm quan trọng của các đặc trưng (Feature Importance)
    importances = rf_model.feature_importances_
    print("\n--- ĐỘ QUAN TRỌNG CỦA CÁC ĐẶC TRƯNG ---")
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {name:<25}: {imp * 100:.2f}%")

    # 3. Huấn luyện Isolation Forest (Unsupervised Anomaly Detection)
    # Chỉ fit trên các mẫu bình thường (Benign) của tập train
    print("\n[*] Đang huấn luyện Isolation Forest (Anomaly Detection)...")
    X_train_benign = X_train_scaled[y_train == 0]
    iso_model = IsolationForest(
        n_estimators=120,
        contamination=0.03,
        random_state=42,
        n_jobs=-1,
    )
    iso_model.fit(X_train_benign)

    # 4. Lưu lại Models, Scaler và Metadata
    scaler_path = MODELS_DIR / "scaler.joblib"
    rf_path = MODELS_DIR / "random_forest.joblib"
    iso_path = MODELS_DIR / "isolation_forest.joblib"
    summary_path = MODELS_DIR / "dataset_summary.json"

    joblib.dump(scaler, scaler_path)
    joblib.dump(rf_model, rf_path)
    joblib.dump(iso_model, iso_path)

    summary = {
        "disclaimer": (
            "CHÚ Ý VỀ DỮ LIỆU ĐÁNH GIÁ: Các chỉ số dưới đây được đánh giá trên tập dữ liệu mô phỏng "
            "hoặc telemetry ban đầu dùng để thiết lập trọng số khởi động (cold-start). "
            "Hiệu năng phát hiện trong môi trường sản xuất thực tế phụ thuộc vào việc nạp và tinh chỉnh "
            "thêm với telemetry có nhãn từ hệ thống mục tiêu."
        ),
        "data_source": data_source,
        "split_method": "GroupShuffleSplit (grouped by session_id to prevent data leakage)",
        "n_samples": len(df),
        "n_train": len(train_df),
        "n_test": len(test_df),
        "features": FEATURE_NAMES,
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
        "feature_importances": {name: round(float(imp), 4) for name, imp in zip(FEATURE_NAMES, importances)},
    }

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n[✓] Huấn luyện và xuất chỉ số hoàn tất! Các artifact:")
    print(f"    - Scaler:           {scaler_path}")
    print(f"    - Random Forest:    {rf_path}")
    print(f"    - Isolation Forest: {iso_path}")
    print(f"    - Summary Metrics:  {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Huấn luyện mô hình Machine Learning phát hiện Privilege Escalation")
    parser.add_argument("--telemetry-file", type=str, default=None, help="Đường dẫn file telemetry gán nhãn thực tế (.jsonl hoặc .csv)")
    parser.add_argument("--check-only", action="store_true", help="Chỉ kiểm tra tính hợp lệ của dữ liệu mà không ghi đè model")
    args = parser.parse_args()

    train_models(telemetry_file=args.telemetry_file, check_only=args.check_only)


if __name__ == "__main__":
    main()
