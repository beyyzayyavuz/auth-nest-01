"""
Day 18 - Detection latency by scenario flow.

Amaç:
Stratified test split yerine, master_features içindeki gerçek scenario zaman akışı
üzerinden ilk detection zamanını hesaplamak.

Bu script:
- Train-ready X_train/y_train ile RF eğitir.
- master_features.parquet üzerinden final scenario akışlarını okur.
- S6 retry artifact'larını (_broken, _slowonly) dışarıda bırakır.
- Her attack scenario için window_start sırasına göre ilk detection'ı bulur.
- Mimicry için binary attack detection kullanır: pred != normal_user.
- Slow HTTP için RF değil, partial/timeout rule kullanır.

1. Train Sentinel: Train a multi-class Random Forest model on pre-split training data.
2. Load Master Matrix: Read continuous chronological timelines from 'master_features.parquet'.
3. Isolate IP Scope: Filter out network subnets to evaluate timelines purely from individual IPs.
4. Align Timelines: Group rows by production scenarios and track their absolute start timestamps.
5. Apply Multi-Pronged Detection: Calculate latency using strict class matching, binary zero-day flags, or connection heuristics.
6. Export Scenario Metrics: Compute the overall scenario detection recall and write out the latency table.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

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

FINAL_SCENARIOS = [
    "S1_legit_only",
    "S2_http_flood",
    "S3_low_rate_bot",
    "S4_credential_stuffing",
    "S5_mimicry_flood",
    "S6_slowloris",
]

ATTACK_SCENARIOS = [
    "S2_http_flood",
    "S3_low_rate_bot",
    "S4_credential_stuffing",
    "S5_mimicry_flood",
    "S6_slowloris",
]

SCENARIO_EXPECTED_LABEL = {
    "S2_http_flood": "http_flood",
    "S3_low_rate_bot": "low_rate_bot",
    "S4_credential_stuffing": "credential_stuffing",
    "S5_mimicry_flood": "mimicry_flood",
    "S6_slowloris": "slow_http",
}


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

print(f"Train rows: {len(X_train):,}, features: {len(feature_cols)}")
print("Train labels:")
print(y_train.value_counts())

print("\nTraining RF...")
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)
clf.fit(X_train, y_train)

print("\nLoading master_features.parquet...")
df = pd.read_parquet(FEATURE_DIR / "master_features.parquet")
df["window_start"] = pd.to_datetime(df["window_start"], utc=True)

# Final senaryoları tut, debug artifact'ları dışarıda bırak
df = df[df["scenario_id"].isin(FINAL_SCENARIOS)].copy()

# Scenario-flow latency için ip-level kullanıyoruz.
# Böylece ip + ipSubnet24 çift temsili latency hesabını şişirmez.
df = df[df["aggregation_type"] == "ip"].copy()

print(f"Scenario-flow rows after filtering: {len(df):,}")
print(df.groupby("scenario_id").size())

rows = []

for scenario_id in ATTACK_SCENARIOS:
    sub = df[df["scenario_id"] == scenario_id].sort_values("window_start").copy()

    if len(sub) == 0:
        rows.append({
            "scenario_id": scenario_id,
            "expected_label": SCENARIO_EXPECTED_LABEL[scenario_id],
            "n_windows": 0,
            "scenario_start": pd.NaT,
            "first_detection": pd.NaT,
            "detected": False,
            "latency_sec": np.nan,
            "latency_min": np.nan,
            "detection_mode": "missing",
            "detected_windows": 0,
            "total_attack_windows": 0,
            "scenario_recall": np.nan,
        })
        continue

    scenario_start = sub["window_start"].min()
    expected_label = SCENARIO_EXPECTED_LABEL[scenario_id]

    if scenario_id == "S6_slowloris":
        # Slow HTTP RF class'ında eğitilmedi; connection-level rule kullanılır.
        detected_mask = (
            (sub["partial_ratio"] > 0) |
            (sub["timeout_ratio"] > 0) |
            (sub["partial_connection_count"] > 0) |
            (sub["timeout_connection_count"] > 0)
        )
        detection_mode = "slow_http_rule_partial_timeout"
        pred_label_counts = {}
    else:
        X_sub = build_X(sub, feature_cols)
        pred = clf.predict(X_sub)
        sub["pred"] = pred

        if scenario_id == "S5_mimicry_flood":
            # Mimicry train'de görülmedi; binary attack detection:
            # normal_user dışı tahmin attack olarak kabul edilir.
            detected_mask = sub["pred"] != "normal_user"
            detection_mode = "rf_binary_pred_not_normal"
        else:
            # In-distribution attack scenarios:
            # doğru class'a tahmin strict detection kabul edilir.
            detected_mask = sub["pred"] == expected_label
            detection_mode = "rf_strict_multiclass"

        pred_label_counts = sub["pred"].value_counts().to_dict()

    detected_windows = int(detected_mask.sum())
    total_windows = int(len(sub))
    scenario_recall = detected_windows / total_windows if total_windows > 0 else np.nan

    detected_sub = sub[detected_mask]
    if len(detected_sub) > 0:
        first_detection = detected_sub["window_start"].min()
        latency_sec = (first_detection - scenario_start).total_seconds()
        detected_flag = True
    else:
        first_detection = pd.NaT
        latency_sec = np.nan
        detected_flag = False

    rows.append({
        "scenario_id": scenario_id,
        "expected_label": expected_label,
        "n_windows": total_windows,
        "scenario_start": scenario_start,
        "first_detection": first_detection,
        "detected": detected_flag,
        "latency_sec": latency_sec,
        "latency_min": latency_sec / 60 if pd.notna(latency_sec) else np.nan,
        "detection_mode": detection_mode,
        "detected_windows": detected_windows,
        "total_attack_windows": total_windows,
        "scenario_recall": scenario_recall,
        "pred_label_counts": str(pred_label_counts),
    })

latency_df = pd.DataFrame(rows)

print("\n=== Scenario-flow detection latency ===")
print(latency_df.to_string(index=False))

out_path = RESULTS_DIR / "detection_latency_by_scenario.csv"
latency_df.to_csv(out_path, index=False)

print(f"\nSaved scenario-flow latency results to {out_path}")