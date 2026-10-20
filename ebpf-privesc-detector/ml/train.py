"""
ml/train.py: Huấn luyện mô hình Machine Learning phát hiện tấn công leo thang đặc quyền
Sử dụng kết hợp:
  1. Isolation Forest: Unsupervised Anomaly Detection (Phát hiện kỹ thuật zero-day / hành vi lạ)
  2. Random Forest: Supervised Classification (Phát hiện chính xác các mẫu tấn công đã biết)
"""

import os
import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.features import FEATURE_NAMES

MODELS_DIR = PROJECT_ROOT / "ml" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)


def generate_synthetic_telemetry(n_samples: int = 10000, attack_ratio: float = 0.15) -> pd.DataFrame:
    """
    Tạo tập dữ liệu mô phỏng hành vi Kernel Linux thực tế:
    - 85% Mẫu bình thường (Benign): Lập trình viên gõ lệnh, daemon dịch vụ, sudo hợp lệ, cronjob...
    - 15% Mẫu tấn công (Privilege Escalation): SUID abuse, exploit từ /tmp, shell từ web service, đọc /etc/shadow...
    """
    np.random.seed(42)
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    # --- 1. DỮ LIỆU BÌNH THƯỜN (BENIGN) ---
    # Case A: Thao tác thông thường của user (ls, git, gcc, python, vim)
    n_b_user = int(n_benign * 0.7)
    b_exec_count = np.random.poisson(lam=1.5, size=n_b_user)
    b_uid_change = np.zeros(n_b_user, dtype=int)
    b_is_whitelisted = np.zeros(n_b_user, dtype=int)  # 0: hợp lệ/không dùng SUID bất thường
    b_suspicious_path = (np.random.rand(n_b_user) < 0.01).astype(int)  # hiếm khi chạy từ /tmp
    b_service_parent = (np.random.rand(n_b_user) < 0.02).astype(int)
    b_sensitive_file = np.zeros(n_b_user, dtype=int)
    b_cap_check = np.random.choice([0, 1], size=n_b_user, p=[0.98, 0.02])
    b_priv_rate = np.random.uniform(0.1, 1.0, size=n_b_user)

    # Case B: Thao tác sudo / su hợp lệ của Quản trị viên
    n_b_admin = n_benign - n_b_user
    ba_exec_count = np.random.poisson(lam=2.5, size=n_b_admin)
    ba_uid_change = np.ones(n_b_admin, dtype=int)  # Có nhảy sang root
    ba_is_whitelisted = np.zeros(n_b_admin, dtype=int)  # Nhưng dùng sudo/su hợp lệ (whitelist = 0)
    ba_suspicious_path = np.zeros(n_b_admin, dtype=int)
    ba_service_parent = np.zeros(n_b_admin, dtype=int)
    ba_sensitive_file = np.random.choice([0, 1], size=n_b_admin, p=[0.85, 0.15])  # admin đọc shadow
    ba_cap_check = np.random.poisson(lam=1.2, size=n_b_admin)
    ba_priv_rate = np.random.uniform(0.5, 2.0, size=n_b_admin)

    benign_features = np.column_stack([
        np.concatenate([b_exec_count, ba_exec_count]),
        np.concatenate([b_uid_change, ba_uid_change]),
        np.concatenate([b_is_whitelisted, ba_is_whitelisted]),
        np.concatenate([b_suspicious_path, ba_suspicious_path]),
        np.concatenate([b_service_parent, ba_service_parent]),
        np.concatenate([b_sensitive_file, ba_sensitive_file]),
        np.concatenate([b_cap_check, ba_cap_check]),
        np.concatenate([b_priv_rate, ba_priv_rate]),
    ])
    benign_labels = np.zeros(n_benign, dtype=int)

    # --- 2. DỮ LIỆU TẤN CÔNG (PRIVILEGE ESCALATION ATTACKS) ---
    # Tấn công 1: SUID Abuse (GTFOBins như find, python, vim được cấp SUID)
    n_a1 = int(n_attacks * 0.35)
    a1_exec = np.random.poisson(lam=4.0, size=n_a1)
    a1_uid_change = np.ones(n_a1, dtype=int)
    a1_is_whitelisted = np.ones(n_a1, dtype=int)  # 1: binary không thuộc whitelist
    a1_suspicious_path = (np.random.rand(n_a1) < 0.25).astype(int)
    a1_service_parent = np.zeros(n_a1, dtype=int)
    a1_sensitive_file = np.random.choice([0, 1, 2], size=n_a1, p=[0.6, 0.3, 0.1])
    a1_cap_check = np.random.poisson(lam=2.5, size=n_a1)
    a1_priv_rate = np.random.uniform(2.0, 6.0, size=n_a1)

    # Tấn công 2: Exploit thả payload trong /tmp hoặc /dev/shm (Dirty Pipe, Ptrace, etc.)
    n_a2 = int(n_attacks * 0.35)
    a2_exec = np.random.poisson(lam=6.0, size=n_a2)
    a2_uid_change = np.ones(n_a2, dtype=int)
    a2_is_whitelisted = np.ones(n_a2, dtype=int)
    a2_suspicious_path = np.ones(n_a2, dtype=int)  # 100% chạy từ /tmp, /dev/shm
    a2_service_parent = (np.random.rand(n_a2) < 0.4).astype(int)
    a2_sensitive_file = np.random.choice([1, 2, 3], size=n_a2, p=[0.4, 0.4, 0.2])
    a2_cap_check = np.random.poisson(lam=3.0, size=n_a2)
    a2_priv_rate = np.random.uniform(3.0, 9.0, size=n_a2)

    # Tấn công 3: Web Service Spawn Root Shell (RCE trên Nginx/Apache/Python rồi leo quyền)
    n_a3 = n_attacks - n_a1 - n_a2
    a3_exec = np.random.poisson(lam=5.0, size=n_a3)
    a3_uid_change = np.ones(n_a3, dtype=int)
    a3_is_whitelisted = np.ones(n_a3, dtype=int)
    a3_suspicious_path = (np.random.rand(n_a3) < 0.6).astype(int)
    a3_service_parent = np.ones(n_a3, dtype=int)  # Tiến trình cha là web server
    a3_sensitive_file = np.random.choice([1, 2, 4], size=n_a3, p=[0.3, 0.5, 0.2])
    a3_cap_check = np.random.poisson(lam=2.8, size=n_a3)
    a3_priv_rate = np.random.uniform(2.5, 8.0, size=n_a3)

    attack_features = np.column_stack([
        np.concatenate([a1_exec, a2_exec, a3_exec]),
        np.concatenate([a1_uid_change, a2_uid_change, a3_uid_change]),
        np.concatenate([a1_is_whitelisted, a2_is_whitelisted, a3_is_whitelisted]),
        np.concatenate([a1_suspicious_path, a2_suspicious_path, a3_suspicious_path]),
        np.concatenate([a1_service_parent, a2_service_parent, a3_service_parent]),
        np.concatenate([a1_sensitive_file, a2_sensitive_file, a3_sensitive_file]),
        np.concatenate([a1_cap_check, a2_cap_check, a3_cap_check]),
        np.concatenate([a1_priv_rate, a2_priv_rate, a3_priv_rate]),
    ])
    attack_labels = np.ones(n_attacks, dtype=int)

    # Ghép dữ liệu và xáo trộn
    X = np.vstack([benign_features, attack_features])
    y = np.concatenate([benign_labels, attack_labels])

    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]

    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y
    return df


def train_models():
    print("[*] Đang khởi tạo tập dữ liệu huấn luyện đặc trưng eBPF...")
    df = generate_synthetic_telemetry(n_samples=12000, attack_ratio=0.15)
    print(f"[+] Tổng số mẫu: {len(df)} (Bình thường: {sum(df['label'] == 0)}, Tấn công: {sum(df['label'] == 1)})")

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # 1. Chuẩn hóa dữ liệu bằng StandardScaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 2. Huấn luyện mô hình Random Forest Classifier (Supervised)
    print("\n[*] Đang huấn luyện Random Forest Classifier...")
    rf_model = RandomForestClassifier(
        n_estimators=120,
        max_depth=10,
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
    print("\n--- KẾT QUẢ ĐÁNH GIÁ RANDOM FOREST ---")
    print(classification_report(y_test, rf_pred, target_names=["Benign", "Attack"]))
    print(f"ROC-AUC Score: {rf_auc:.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_pred))

    # Tầm quan trọng của các đặc trưng (Feature Importances)
    importances = rf_model.feature_importances_
    print("\n--- ĐỘ QUAN TRỌNG CỦA CÁC ĐẶC TRƯNG (FEATURE IMPORTANCE) ---")
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {name:<25}: {imp * 100:.2f}%")

    # 3. Huấn luyện mô hình Isolation Forest (Unsupervised Anomaly Detection)
    # Chỉ fit trên tập dữ liệu bình thường (Benign) để học ranh giới bình thường
    print("\n[*] Đang huấn luyện Isolation Forest (Anomaly Detection)...")
    X_train_benign = X_train_scaled[y_train == 0]
    iso_model = IsolationForest(
        n_estimators=150,
        contamination=0.04,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    iso_model.fit(X_train_benign)

    # 4. Lưu lại Models và Scaler vào thư mục ml/models
    scaler_path = MODELS_DIR / "scaler.joblib"
    rf_path = MODELS_DIR / "random_forest.joblib"
    iso_path = MODELS_DIR / "isolation_forest.joblib"
    summary_path = MODELS_DIR / "dataset_summary.json"

    joblib.dump(scaler, scaler_path)
    joblib.dump(rf_model, rf_path)
    joblib.dump(iso_model, iso_path)

    summary = {
        "n_samples": len(df),
        "features": FEATURE_NAMES,
        "rf_auc": float(rf_auc),
        "feature_importances": {name: float(imp) for name, imp in zip(FEATURE_NAMES, importances)},
    }
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[✓] Huấn luyện hoàn tất! Đã lưu các artifact:")
    print(f"    - Scaler:           {scaler_path}")
    print(f"    - Random Forest:    {rf_path}")
    print(f"    - Isolation Forest: {iso_path}")
    print(f"    - Model Summary:    {summary_path}")


if __name__ == "__main__":
    train_models()
