"""
Day 18 - FPR per legitimate IP per minute.

Amaç:
Normal user traffic üzerinde Random Forest modelinin false positive oranını
operasyonel bir metrik olarak hesaplamak.

FPR per legitimate IP per minute =
false positive window count / legitimate IP-minutes

Burada sadece normal_user satırları kullanılır.
Eğer normal_user window'u attack class olarak tahmin edilirse false positive sayılır.

1. Train Sentinel: Fit a 200-tree multi-class Random Forest using pre-processed training vectors.
2. Ingest Splits: Load 'dataset_split.parquet' containing your designated multi-fold splits.
3. Isolate Clean Profiles: Filter data to keep only true 'normal_user' rows aggregated at the 'ip' level.
4. Predict Deviations: Run the clean dataset through the model; flags are false positives if they don't say 'normal_user'.
5. Normalize to Operational Time: Convert rows to equivalent minutes (rows * 10 seconds / 60) to compute IP-minute density.
6. Export False Alarm Ledger: Write metrics and granular false alarm telemetry into down
"""

import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
FEATURE_DIR = ROOT / "data/features"
TRAIN_DIR = FEATURE_DIR / "train_ready"
RESULTS_DIR = ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

DROP_COLS = [
    "scenario_id",
    "majority_label",
    "label",
    "split",
    "window_start",
    "window_end",
    "aggregation_key",
]

WINDOW_SEC = 10


def build_X(subset_df, feature_cols):
    X = subset_df.drop(columns=DROP_COLS, errors="ignore")
    X = X.select_dtypes(include=["number", "bool"])

    if "aggregation_type" in subset_df.columns:
        ohe = pd.get_dummies(subset_df["aggregation_type"], prefix="agg")
        X = pd.concat([X.reset_index(drop=True), ohe.reset_index(drop=True)], axis=1)

    X = X.fillna(0)
    X = X.reindex(columns=feature_cols, fill_value=0)
    return X


print("Loading train-ready matrices...")
X_train = pd.read_parquet(TRAIN_DIR / "X_train.parquet")
y_train = pd.read_parquet(TRAIN_DIR / "y_train.parquet")["label"]

feature_cols = list(X_train.columns)

print(f"Train rows: {len(X_train):,}")
print(f"Features: {len(feature_cols)}")

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("Training RF...")
clf.fit(X_train, y_train)

print("Loading dataset_split.parquet...")
df = pd.read_parquet(FEATURE_DIR / "dataset_split.parquet")
df["window_start"] = pd.to_datetime(df["window_start"], utc=True)

# Normal user rows only
normal_df = df[df["label"] == "normal_user"].copy()

# Use ip-level only to avoid double-counting ip + ipSubnet24
normal_ip = normal_df[normal_df["aggregation_type"] == "ip"].copy()

print(f"Normal user ip-level windows: {len(normal_ip):,}")

X_normal = build_X(normal_ip, feature_cols)
pred = clf.predict(X_normal)

normal_ip["pred"] = pred
normal_ip["is_false_positive"] = normal_ip["pred"] != "normal_user"

fp_count = int(normal_ip["is_false_positive"].sum())
total_windows = int(len(normal_ip))

# legitimate IP-minutes:
# each ip-level window is WINDOW_SEC seconds for one IP/key.
legit_ip_minutes = total_windows * (WINDOW_SEC / 60.0)

fpr_per_ip_min = fp_count / legit_ip_minutes if legit_ip_minutes > 0 else 0.0
window_fpr = fp_count / total_windows if total_windows > 0 else 0.0

print("\n=== FPR per legitimate IP per minute ===")
print(f"Total normal ip-level windows: {total_windows}")
print(f"False positive windows: {fp_count}")
print(f"Window-level FPR: {window_fpr:.6f}")
print(f"Legitimate IP-minutes: {legit_ip_minutes:.2f}")
print(f"FPR per legitimate IP-minute: {fpr_per_ip_min:.6f}")

print("\nFalse positive predictions by predicted class:")
print(normal_ip[normal_ip["is_false_positive"]]["pred"].value_counts())

print("\nFalse positives by scenario:")
print(normal_ip[normal_ip["is_false_positive"]].groupby("scenario_id").size())

out_summary = pd.DataFrame([{
    "total_normal_ip_windows": total_windows,
    "false_positive_windows": fp_count,
    "window_level_fpr": window_fpr,
    "legitimate_ip_minutes": legit_ip_minutes,
    "fpr_per_legit_ip_minute": fpr_per_ip_min,
}])

out_summary.to_csv(RESULTS_DIR / "fpr_per_legit_ip_minute.csv", index=False)

normal_ip[[
    "scenario_id",
    "aggregation_key",
    "window_start",
    "label",
    "pred",
    "is_false_positive",
]].to_csv(RESULTS_DIR / "fpr_normal_user_predictions.csv", index=False)

print(f"\nSaved FPR results to {RESULTS_DIR}")