"""
Day 21 - Ablation study.

Amaç:
Feature gruplarını çıkararak model performansının nasıl değiştiğini görmek.

Özellikle:
- all features
- no_iat
- no_endpoint
- no_connection
- no_global_or_baseline_dist
- ua_only
- ip/global-only style features

Metrikler:
- Val accuracy / macro-F1
- Test accuracy / macro-F1
- Mimicry binary attack recall
- Mimicry evasion rate

1. Parse Input Sets: Load train, validation, test, and out-of-distribution matrices.
2. Define Ablation Mappings: Programmatically isolate feature blocks using string patterns 
   (e.g., dropping or isolating "iat_", "endpoint_", "global_").
3. Retrain and Test: Iteratively train an independent Random Forest model on each isolated configuration.
4. Track Evasion Resilience: Record accuracy, Macro-F1, and out-of-distribution mimicry metrics.
5. Compute Degradation Delta: Subtract baseline performance from ablated scores to measure the impact.
6. Shortcut Diagnostic: Audit the 'ua_only' slice to flag over-reliance on superficial headers.
"""

import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score

ROOT = Path(__file__).resolve().parents[1]
TRAIN_DIR = ROOT / "data/features/train_ready"
RESULTS_DIR = ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

print("Loading train-ready matrices...")

X_train = pd.read_parquet(TRAIN_DIR / "X_train.parquet")
y_train = pd.read_parquet(TRAIN_DIR / "y_train.parquet")["label"]

X_val = pd.read_parquet(TRAIN_DIR / "X_val.parquet")
y_val = pd.read_parquet(TRAIN_DIR / "y_val.parquet")["label"]

X_test = pd.read_parquet(TRAIN_DIR / "X_test.parquet")
y_test = pd.read_parquet(TRAIN_DIR / "y_test.parquet")["label"]

X_mimicry = pd.read_parquet(TRAIN_DIR / "X_mimicry_test.parquet")
y_mimicry = pd.read_parquet(TRAIN_DIR / "y_mimicry_test.parquet")["label"]

all_features = list(X_train.columns)

print(f"Train rows: {len(X_train):,}")
print(f"Val rows: {len(X_val):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")
print(f"All features: {len(all_features)}")

def existing(cols):
    return [c for c in cols if c in all_features]

ablation_groups = {
    "all": all_features,

    "no_iat": [
        c for c in all_features
        if "iat_" not in c and c != "iat_mean" and c != "iat_std" and c != "iat_cv"
    ],

    "no_endpoint": [
        c for c in all_features
        if "endpoint_" not in c
    ],

    "no_connection": [
        c for c in all_features
        if "connection_" not in c
        and "partial_" not in c
        and "timeout_" not in c
        and c not in ["partial_ratio", "timeout_ratio", "request_partial_ratio"]
    ],

    "no_global_or_baseline_dist": [
        c for c in all_features
        if "global_" not in c
        and "markov_" not in c
        and "iat_ks" not in c
    ],

    "no_cost": [
        c for c in all_features
        if "cost" not in c
        and "cpu" not in c
        and "db" not in c
    ],

    "no_status": [
        c for c in all_features
        if "status_" not in c
    ],

    "ua_only": existing([
        "ua_unique",
        "ua_entropy",
    ]),

    "rate_only": existing([
        "req_rate",
        "global_req_rate",
        "request_count",
        "global_request_count",
    ]),

    "endpoint_only": [
        c for c in all_features
        if "endpoint_" in c
    ],

    "connection_only": [
        c for c in all_features
        if "connection_" in c
        or "partial_" in c
        or "timeout_" in c
        or c in ["partial_ratio", "timeout_ratio", "request_partial_ratio"]
    ],

    "global_baseline_only": [
        c for c in all_features
        if "global_" in c
        or "markov_" in c
        or "iat_ks" in c
    ],
}

def evaluate_group(name, cols):
    cols = existing(cols)

    if len(cols) == 0:
        print(f"\nSkipping {name}: no columns")
        return None

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    clf.fit(X_train[cols], y_train)

    val_pred = clf.predict(X_val[cols])
    test_pred = clf.predict(X_test[cols])
    mimicry_pred = clf.predict(X_mimicry[cols])

    val_acc = accuracy_score(y_val, val_pred)
    val_macro_f1 = f1_score(y_val, val_pred, average="macro", zero_division=0)

    test_acc = accuracy_score(y_test, test_pred)
    test_macro_f1 = f1_score(y_test, test_pred, average="macro", zero_division=0)

    # mimicry was unseen in training.
    # predicted != normal_user means detected as attack.
    mimicry_binary_recall = (mimicry_pred != "normal_user").mean()
    mimicry_evasion_rate = (mimicry_pred == "normal_user").mean()
    mimicry_as_flood = (mimicry_pred == "http_flood").mean()

    pred_counts = pd.Series(mimicry_pred).value_counts().to_dict()

    print(f"\n=== {name} ===")
    print(f"Features: {len(cols)}")
    print(f"Val accuracy: {val_acc:.4f}, Val macro-F1: {val_macro_f1:.4f}")
    print(f"Test accuracy: {test_acc:.4f}, Test macro-F1: {test_macro_f1:.4f}")
    print(f"Mimicry recall as http_flood: {mimicry_as_flood:.4f}")
    print(f"Mimicry binary attack recall: {mimicry_binary_recall:.4f}")
    print(f"Mimicry evasion rate: {mimicry_evasion_rate:.4f}")
    print(f"Mimicry predicted as: {pred_counts}")

    return {
        "group": name,
        "n_features": len(cols),
        "features": ",".join(cols),
        "val_accuracy": val_acc,
        "val_macro_f1": val_macro_f1,
        "test_accuracy": test_acc,
        "test_macro_f1": test_macro_f1,
        "mimicry_recall_as_flood": mimicry_as_flood,
        "mimicry_binary_attack_recall": mimicry_binary_recall,
        "mimicry_evasion_rate": mimicry_evasion_rate,
        "mimicry_pred_counts": str(pred_counts),
    }

rows = []

for name, cols in ablation_groups.items():
    result = evaluate_group(name, cols)
    if result is not None:
        rows.append(result)

results_df = pd.DataFrame(rows)

# Diff from all
all_row = results_df[results_df["group"] == "all"].iloc[0]

for metric in [
    "val_accuracy",
    "val_macro_f1",
    "test_accuracy",
    "test_macro_f1",
    "mimicry_recall_as_flood",
    "mimicry_binary_attack_recall",
    "mimicry_evasion_rate",
]:
    results_df[f"diff_vs_all_{metric}"] = results_df[metric] - all_row[metric]

print("\n=== Ablation summary ===")
summary_cols = [
    "group",
    "n_features",
    "val_accuracy",
    "val_macro_f1",
    "test_accuracy",
    "test_macro_f1",
    "mimicry_recall_as_flood",
    "mimicry_binary_attack_recall",
    "mimicry_evasion_rate",
]
print(results_df[summary_cols].to_string(index=False))

out_path = RESULTS_DIR / "ablation_study_results.csv"
results_df.to_csv(out_path, index=False)

print(f"\nSaved ablation study results to {out_path}")

# Specific warning for UA-only shortcut risk
ua_row = results_df[results_df["group"] == "ua_only"]
if len(ua_row) > 0:
    ua_acc = float(ua_row.iloc[0]["val_accuracy"])
    if ua_acc >= 0.85:
        print("\n⚠️ WARNING: UA-only val accuracy >= 0.85. Model may rely strongly on surface UA features.")
    else:
        print("\n✓ UA-only accuracy is below 0.85; no strong UA-only shortcut signal.")