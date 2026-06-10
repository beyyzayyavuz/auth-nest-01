"""
Day 20 - Mimicry holdout analysis.

Amaç:
Mimicry flood train'e hiç girmeden, modelin mimicry holdout'u nasıl
sınıflandırdığını final tablo olarak üretmek.

Metrikler:
- In-distribution test accuracy / macro-F1
- Mimicry prediction distribution
- Mimicry recall as http_flood
- Mimicry evasion rate = normal_user olarak sınıflanan oran
- Mimicry binary attack recall = normal_user dışı sınıflanan oran
- Baseline RF vs Proposed ISO+RF karşılaştırması

. Load Matrices: Pull pre-processed, aligned parquet splits from disk.
2. Train Baseline: Fit a standalone 200-tree supervised Random Forest.
3. Establish Layer A: Train an unsupervised Isolation Forest purely on legit users 
   to append an inverted 'anomaly_score' matrix.
4. Train Layer B: Fit an augmented 300-tree Random Forest using the new anomaly feature.
5. In-Distribution Audit: Extract accuracy and Macro-F1 across known test profiles.
6. Stress-Test Evasion: Send the unseen mimicry files through both models to trace 
   exact destination classes (Evasion Rate, Fallback Flood Recall, Binary Alert Recall).
7. Execute Interpretive Bucketing: Assign a deterministic resilience classification 
   to the proposed model depending on its structural vulnerability margins.

Inputs:  'X_train.parquet', 'y_train.parquet', 'X_test.parquet', 'X_mimicry_test.parquet'
Outputs: 'mimicry_holdout_summary.csv', 'mimicry_baseline_vs_proposed.csv', 
         and an interpretive diagnostic text ledger.
"""

import pandas as pd
from pathlib import Path

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report

ROOT = Path(__file__).resolve().parents[1]
TRAIN_DIR = ROOT / "data/features/train_ready"
RESULTS_DIR = ROOT / "data/results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

print("Loading train-ready matrices...")

X_train = pd.read_parquet(TRAIN_DIR / "X_train.parquet")
y_train = pd.read_parquet(TRAIN_DIR / "y_train.parquet")["label"]

X_test = pd.read_parquet(TRAIN_DIR / "X_test.parquet")
y_test = pd.read_parquet(TRAIN_DIR / "y_test.parquet")["label"]

X_mimicry = pd.read_parquet(TRAIN_DIR / "X_mimicry_test.parquet")
y_mimicry = pd.read_parquet(TRAIN_DIR / "y_mimicry_test.parquet")["label"]

print(f"Train rows: {len(X_train):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")

print("\nTrain label distribution:")
print(y_train.value_counts())

classes = sorted(y_train.unique())
print(f"\nTraining classes: {classes}")

# ============================================================
# Baseline RF
# ============================================================

baseline_rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining baseline RF...")
baseline_rf.fit(X_train, y_train)

baseline_test_pred = baseline_rf.predict(X_test)
baseline_mimicry_pred = baseline_rf.predict(X_mimicry)

# ============================================================
# Proposed ISO + RF
# ============================================================

print("\nTraining IsolationForest on normal_user train rows...")
X_train_legit = X_train[y_train == "normal_user"].copy()

iso = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1,
)

iso.fit(X_train_legit)

def add_anomaly_score(X):
    X2 = X.copy()
    # decision_function: higher = more normal.
    # We invert it so higher anomaly_score means more anomalous.
    X2["anomaly_score"] = -iso.decision_function(X2)
    return X2

X_train_prop = add_anomaly_score(X_train)
X_test_prop = add_anomaly_score(X_test)
X_mimicry_prop = add_anomaly_score(X_mimicry)

print("\nAnomaly score means on train:")
tmp = X_train_prop.copy()
tmp["label"] = y_train.values
print(tmp.groupby("label")["anomaly_score"].mean().round(4))

proposed_rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining proposed ISO+RF...")
proposed_rf.fit(X_train_prop, y_train)

proposed_test_pred = proposed_rf.predict(X_test_prop)
proposed_mimicry_pred = proposed_rf.predict(X_mimicry_prop)

# ============================================================
# Metrics
# ============================================================

def in_dist_metrics(model_name, y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)

    print(f"\n=== {model_name} in-distribution test ===")
    print(f"Accuracy   : {acc:.4f}")
    print(f"Macro-F1   : {macro_f1:.4f}")
    print(f"Weighted-F1: {weighted_f1:.4f}")
    print(classification_report(y_true, y_pred, zero_division=0))

    return {
        "model": model_name,
        "in_dist_accuracy": acc,
        "in_dist_macro_f1": macro_f1,
        "in_dist_weighted_f1": weighted_f1,
    }

def mimicry_metrics(model_name, pred):
    pred_s = pd.Series(pred)
    total = len(pred_s)

    pred_counts = pred_s.value_counts()
    pred_dist = pred_s.value_counts(normalize=True)

    recall_as_flood = (pred_s == "http_flood").mean()
    evasion_rate = (pred_s == "normal_user").mean()
    binary_attack_recall = (pred_s != "normal_user").mean()

    print(f"\n=== {model_name} mimicry holdout ===")
    print("Prediction counts:")
    print(pred_counts)
    print("\nPrediction distribution:")
    print(pred_dist.round(4))

    print(f"\nMimicry recall as http_flood: {recall_as_flood:.4f}")
    print(f"Mimicry evasion rate (classified as normal_user): {evasion_rate:.4f}")
    print(f"Mimicry binary attack recall: {binary_attack_recall:.4f}")

    return {
        "model": model_name,
        "mimicry_total": total,
        "mimicry_pred_http_flood": int((pred_s == "http_flood").sum()),
        "mimicry_pred_low_rate_bot": int((pred_s == "low_rate_bot").sum()),
        "mimicry_pred_credential_stuffing": int((pred_s == "credential_stuffing").sum()),
        "mimicry_pred_normal_user": int((pred_s == "normal_user").sum()),
        "mimicry_recall_as_flood": recall_as_flood,
        "mimicry_evasion_rate": evasion_rate,
        "mimicry_binary_attack_recall": binary_attack_recall,
    }

baseline_indist = in_dist_metrics("baseline_rf", y_test, baseline_test_pred)
proposed_indist = in_dist_metrics("proposed_iso_rf", y_test, proposed_test_pred)

baseline_mimicry = mimicry_metrics("baseline_rf", baseline_mimicry_pred)
proposed_mimicry = mimicry_metrics("proposed_iso_rf", proposed_mimicry_pred)

# Merge metrics
summary_rows = []
for indist, mim in [
    (baseline_indist, baseline_mimicry),
    (proposed_indist, proposed_mimicry),
]:
    row = {}
    row.update(indist)
    row.update(mim)
    summary_rows.append(row)

summary_df = pd.DataFrame(summary_rows)

comparison = []

b = summary_df[summary_df["model"] == "baseline_rf"].iloc[0]
p = summary_df[summary_df["model"] == "proposed_iso_rf"].iloc[0]

for metric in [
    "in_dist_accuracy",
    "in_dist_macro_f1",
    "mimicry_recall_as_flood",
    "mimicry_evasion_rate",
    "mimicry_binary_attack_recall",
]:
    comparison.append({
        "metric": metric,
        "baseline_rf": b[metric],
        "proposed_iso_rf": p[metric],
        "diff": p[metric] - b[metric],
    })

comparison_df = pd.DataFrame(comparison)

print("\n=== Mimicry holdout final summary ===")
print(summary_df.to_string(index=False))

print("\n=== Baseline vs Proposed comparison ===")
print(comparison_df.to_string(index=False))

# Classification bucket according to Day 20 plan
def classify_mimicry_result(recall_as_flood, evasion_rate):
    if recall_as_flood > 0.7 and evasion_rate < 0.2:
        return "Strong: behavioral features appear robust to mimicry"
    if 0.3 <= recall_as_flood <= 0.6 and 0.2 <= evasion_rate <= 0.5:
        return "Expected: partial robustness, partial evasion"
    if recall_as_flood < 0.3 and evasion_rate > 0.5:
        return "Weak: detection likely surface-dependent"
    return "Mixed: outside predefined buckets"

bucket = classify_mimicry_result(
    proposed_mimicry["mimicry_recall_as_flood"],
    proposed_mimicry["mimicry_evasion_rate"],
)

print(f"\nFinal mimicry interpretation bucket: {bucket}")

# Save outputs
summary_df.to_csv(RESULTS_DIR / "mimicry_holdout_summary.csv", index=False)
comparison_df.to_csv(RESULTS_DIR / "mimicry_baseline_vs_proposed.csv", index=False)

pd.DataFrame({
    "true_label": y_mimicry.values,
    "baseline_predicted_as": baseline_mimicry_pred,
    "proposed_predicted_as": proposed_mimicry_pred,
    "baseline_detected_as_attack": baseline_mimicry_pred != "normal_user",
    "proposed_detected_as_attack": proposed_mimicry_pred != "normal_user",
}).to_csv(RESULTS_DIR / "mimicry_holdout_predictions.csv", index=False)

with open(RESULTS_DIR / "mimicry_interpretation.txt", "w") as f:
    f.write(bucket + "\n")

print(f"\nSaved mimicry holdout analysis results to {RESULTS_DIR}")