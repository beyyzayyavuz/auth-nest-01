"""
Day 18 - Detection latency (post-hoc).

Amaç:
Test setindeki saldırı sınıfları için, saldırı başlangıcından sonra
ilk doğru pozitif detection'ın kaç saniye sonra geldiğini hesaplamak.

Not:
- In-distribution test için RF multiclass kullanılır.
- Mimicry holdout train'de görülmediği için binary attack detection olarak değerlendirilir:
  predicted != normal_user ise attack detected.
- slow_http supervised RF içinde yoktur; partial_ratio/timeout_ratio > 0 kuralı ile değerlendirilir.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/features"
RESULTS = ROOT / "data/results"
RESULTS.mkdir(parents=True, exist_ok=True)

print("Loading dataset_split.parquet...")
df = pd.read_parquet(OUT / "dataset_split.parquet")
df["window_start"] = pd.to_datetime(df["window_start"], utc=True)

DROP_COLS = [
    "scenario_id",
    "majority_label",
    "label",
    "split",
    "window_start",
    "window_end",
    "aggregation_key",
]

def build_X_y(subset_df, feature_cols=None):
    X = subset_df.drop(columns=DROP_COLS, errors="ignore")
    X = X.select_dtypes(include=["number", "bool"])

    if "aggregation_type" in subset_df.columns:
        ohe = pd.get_dummies(subset_df["aggregation_type"], prefix="agg")
        X = pd.concat([X.reset_index(drop=True), ohe.reset_index(drop=True)], axis=1)

    X = X.fillna(0)

    if feature_cols is not None:
        X = X.reindex(columns=feature_cols, fill_value=0)

    y = subset_df["label"].reset_index(drop=True)
    return X, y

train_df = df[df["split"] == "train"].copy()
test_df = df[df["split"] == "test"].copy()
mimicry_df = df[df["split"] == "mimicry_test"].copy()
slow_df = df[df["split"] == "slow_http_test"].copy()

X_train, y_train = build_X_y(train_df)
feature_cols = list(X_train.columns)

X_test, y_test = build_X_y(test_df, feature_cols)
X_mimicry, y_mimicry = build_X_y(mimicry_df, feature_cols)

print(f"Train rows: {len(X_train):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")
print(f"Slow HTTP rows: {len(slow_df):,}")

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining RF...")
clf.fit(X_train, y_train)

# ------------------------------------------------------------
# Helper: latency calculation
# ------------------------------------------------------------

def compute_latency(rows_df, pred, mode_name, strict_multiclass=True):
    """
    rows_df must include: label, window_start
    pred is model prediction array.

    strict_multiclass=True:
      correct detection = pred == true label

    strict_multiclass=False:
      binary attack detection = true label != normal_user and pred != normal_user
    """
    rows = rows_df.reset_index(drop=True).copy()
    rows["pred"] = pred

    out = []

    for label in sorted(rows["label"].unique()):
        if label == "normal_user":
            continue

        sub = rows[rows["label"] == label].sort_values("window_start").copy()
        if len(sub) == 0:
            continue

        attack_start = sub["window_start"].min()

        if strict_multiclass:
            detected = sub[sub["pred"] == sub["label"]]
        else:
            detected = sub[sub["pred"] != "normal_user"]

        if len(detected) == 0:
            latency_sec = np.nan
            first_detection = pd.NaT
            detected_flag = False
        else:
            first_detection = detected["window_start"].min()
            latency_sec = (first_detection - attack_start).total_seconds()
            detected_flag = True

        out.append({
            "mode": mode_name,
            "label": label,
            "n_windows": len(sub),
            "attack_start": attack_start,
            "first_detection": first_detection,
            "detected": detected_flag,
            "latency_sec": latency_sec,
            "latency_min": latency_sec / 60 if pd.notna(latency_sec) else np.nan,
        })

    return out

# ------------------------------------------------------------
# In-distribution test
# ------------------------------------------------------------

print("\nPredicting test split...")
test_pred = clf.predict(X_test)

latency_rows = []
latency_rows.extend(
    compute_latency(test_df, test_pred, "test_strict_multiclass", strict_multiclass=True)
)
latency_rows.extend(
    compute_latency(test_df, test_pred, "test_binary_attack", strict_multiclass=False)
)

# ------------------------------------------------------------
# Mimicry holdout
# ------------------------------------------------------------

print("Predicting mimicry holdout...")
mimicry_pred = clf.predict(X_mimicry)

# mimicry is unseen, so strict multiclass is not meaningful.
# Use binary attack detection: pred != normal_user.
latency_rows.extend(
    compute_latency(mimicry_df, mimicry_pred, "mimicry_binary_attack", strict_multiclass=False)
)

# ------------------------------------------------------------
# Slow HTTP test
# ------------------------------------------------------------

# slow_http is not RF-trained. Use connection-level rule:
# partial_ratio > 0 OR timeout_ratio > 0
if len(slow_df) > 0:
    slow_rows = slow_df.sort_values("window_start").copy()
    attack_start = slow_rows["window_start"].min()

    detected = slow_rows[
        (slow_rows["partial_ratio"] > 0) |
        (slow_rows["timeout_ratio"] > 0) |
        (slow_rows["partial_connection_count"] > 0) |
        (slow_rows["timeout_connection_count"] > 0)
    ]

    if len(detected) > 0:
        first_detection = detected["window_start"].min()
        latency_sec = (first_detection - attack_start).total_seconds()
        detected_flag = True
    else:
        first_detection = pd.NaT
        latency_sec = np.nan
        detected_flag = False

    latency_rows.append({
        "mode": "slow_http_rule_based",
        "label": "slow_http",
        "n_windows": len(slow_rows),
        "attack_start": attack_start,
        "first_detection": first_detection,
        "detected": detected_flag,
        "latency_sec": latency_sec,
        "latency_min": latency_sec / 60 if pd.notna(latency_sec) else np.nan,
    })

latency_df = pd.DataFrame(latency_rows)
print("\n=== Detection latency summary ===")
print(latency_df.to_string(index=False))

out_path = RESULTS / "detection_latency_posthoc.csv"
latency_df.to_csv(out_path, index=False)
print(f"\nSaved detection latency results to {out_path}")