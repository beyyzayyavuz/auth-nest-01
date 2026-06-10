"""
Day 19 - Proposed model: Isolation Forest anomaly score + Random Forest.

Layer A:
- IsolationForest is trained only on normal_user train rows.
- It produces anomaly_score for train/val/test/mimicry_test.

Layer B:
- RandomForest is trained with original features + anomaly_score.

Comparison:
- Baseline RF vs Proposed RF
- In-distribution val/test metrics
- Mimicry holdout binary attack recall

1. Parse Input Sets: Load train, validation, test, and out-of-distribution matrices.
2. Train Layer A (Isolation Forest): Fit an Isolation Forest on true 'normal_user' traffic rows.
3. Compute Anomaly Features: Generate inverted decision functions to create an anomaly_score metric.
4. Scale Input Matrix: Concat the anomaly_score into the train/validation/test feature spaces.
5. Train Layer B (Random Forest): Train an augmented 300-tree multiclass classifier.
6. Run Stress-Test Diagnostics: Cross-examine baseline versus proposed scores using Macro-F1, 
   PR-AUC, and out-of-distribution mimicry recall bounds.
"""

import pandas as pd
from pathlib import Path

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
    average_precision_score,
)
from sklearn.preprocessing import label_binarize

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

print(f"Train rows: {len(X_train):,}, features: {X_train.shape[1]}")
print(f"Val rows: {len(X_val):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")

classes = sorted(y_train.unique())
print(f"Training classes: {classes}")

# ============================================================
# Baseline RF: original features only
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

# ============================================================
# Layer A: Isolation Forest trained only on legit traffic
# ============================================================

X_train_legit = X_train[y_train == "normal_user"].copy()

print("\nTraining Layer A IsolationForest on normal_user only...")
print(f"Legit train rows: {len(X_train_legit):,}")

iso = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42,
    n_jobs=-1,
)

iso.fit(X_train_legit)

def add_anomaly_score(X):
    X2 = X.copy()
    # decision_function: higher = more normal, lower = more anomalous.
    # We invert it so higher anomaly_score = more anomalous.
    X2["anomaly_score"] = -iso.decision_function(X2)
    return X2

X_train_prop = add_anomaly_score(X_train)
X_val_prop = add_anomaly_score(X_val)
X_test_prop = add_anomaly_score(X_test)
X_mimicry_prop = add_anomaly_score(X_mimicry)

print("\nAnomaly score means by train label:")
tmp = X_train_prop.copy()
tmp["label"] = y_train.values
print(tmp.groupby("label")["anomaly_score"].mean().round(4))

# ============================================================
# Layer B: RF with anomaly_score
# ============================================================

proposed_rf = RandomForestClassifier(
    n_estimators=300,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining proposed RF with anomaly_score...")
proposed_rf.fit(X_train_prop, y_train)

# ============================================================
# Evaluation helpers
# ============================================================

def eval_multiclass(model_name, split_name, model, X, y):
    pred = model.predict(X)

    acc = accuracy_score(y, pred)
    macro_f1 = f1_score(y, pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y, pred, average="weighted", zero_division=0)

    print(f"\n=== {model_name} / {split_name} ===")
    print(f"Accuracy   : {acc:.4f}")
    print(f"Macro-F1   : {macro_f1:.4f}")
    print(f"Weighted-F1: {weighted_f1:.4f}")

    print("\nClassification report:")
    print(classification_report(y, pred, labels=classes, zero_division=0))

    cm = confusion_matrix(y, pred, labels=classes)
    cm_df = pd.DataFrame(
        cm,
        index=[f"true_{c}" for c in classes],
        columns=[f"pred_{c}" for c in classes],
    )
    print("Confusion matrix:")
    print(cm_df)

    return {
        "model": model_name,
        "split": split_name,
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
    }, pred, cm_df

def mimicry_binary_recall(model_name, model, X):
    pred = model.predict(X)

    # mimicry_flood was not in training.
    # If predicted != normal_user, we count it as detected attack.
    detected = pred != "normal_user"
    recall = detected.mean()

    counts = pd.Series(pred).value_counts()

    print(f"\n=== {model_name} / mimicry holdout ===")
    print("Predicted as:")
    print(counts)
    print(f"Mimicry binary attack recall: {recall:.4f}")
    print(f"Mimicry missed as normal_user: {(pred == 'normal_user').sum()} / {len(pred)}")

    return {
        "model": model_name,
        "split": "mimicry_test",
        "mimicry_binary_recall": recall,
        "mimicry_missed_normal": int((pred == "normal_user").sum()),
        "mimicry_total": int(len(pred)),
    }, pred

def per_class_pr_auc(model_name, split_name, model, X, y):
    y_bin = label_binarize(y, classes=classes)
    y_score = model.predict_proba(X)

    rows = []
    for i, c in enumerate(classes):
        ap = average_precision_score(y_bin[:, i], y_score[:, i])
        print(f"{model_name} / {split_name} / {c}: PR-AUC = {ap:.4f}")
        rows.append({
            "model": model_name,
            "split": split_name,
            "class": c,
            "pr_auc": ap,
        })
    return rows

# ============================================================
# Run evaluations
# ============================================================

metrics_rows = []
pr_rows = []

# Baseline
m, baseline_val_pred, baseline_val_cm = eval_multiclass(
    "baseline_rf", "val", baseline_rf, X_val, y_val
)
metrics_rows.append(m)

m, baseline_test_pred, baseline_test_cm = eval_multiclass(
    "baseline_rf", "test", baseline_rf, X_test, y_test
)
metrics_rows.append(m)

mimicry_baseline, baseline_mimicry_pred = mimicry_binary_recall(
    "baseline_rf", baseline_rf, X_mimicry
)

print("\n=== Baseline RF PR-AUC ===")
pr_rows.extend(per_class_pr_auc("baseline_rf", "val", baseline_rf, X_val, y_val))
pr_rows.extend(per_class_pr_auc("baseline_rf", "test", baseline_rf, X_test, y_test))

# Proposed
m, proposed_val_pred, proposed_val_cm = eval_multiclass(
    "proposed_iso_rf", "val", proposed_rf, X_val_prop, y_val
)
metrics_rows.append(m)

m, proposed_test_pred, proposed_test_cm = eval_multiclass(
    "proposed_iso_rf", "test", proposed_rf, X_test_prop, y_test
)
metrics_rows.append(m)

mimicry_proposed, proposed_mimicry_pred = mimicry_binary_recall(
    "proposed_iso_rf", proposed_rf, X_mimicry_prop
)

print("\n=== Proposed RF PR-AUC ===")
pr_rows.extend(per_class_pr_auc("proposed_iso_rf", "val", proposed_rf, X_val_prop, y_val))
pr_rows.extend(per_class_pr_auc("proposed_iso_rf", "test", proposed_rf, X_test_prop, y_test))

# ============================================================
# Comparison table
# ============================================================

metrics_df = pd.DataFrame(metrics_rows)
mimicry_df = pd.DataFrame([mimicry_baseline, mimicry_proposed])

comparison = []

for split in ["val", "test"]:
    b = metrics_df[(metrics_df["model"] == "baseline_rf") & (metrics_df["split"] == split)].iloc[0]
    p = metrics_df[(metrics_df["model"] == "proposed_iso_rf") & (metrics_df["split"] == split)].iloc[0]

    comparison.append({
        "metric": f"{split}_accuracy",
        "baseline_rf": b["accuracy"],
        "proposed_iso_rf": p["accuracy"],
        "diff": p["accuracy"] - b["accuracy"],
    })
    comparison.append({
        "metric": f"{split}_macro_f1",
        "baseline_rf": b["macro_f1"],
        "proposed_iso_rf": p["macro_f1"],
        "diff": p["macro_f1"] - b["macro_f1"],
    })

b_m = mimicry_df[mimicry_df["model"] == "baseline_rf"].iloc[0]
p_m = mimicry_df[mimicry_df["model"] == "proposed_iso_rf"].iloc[0]

comparison.append({
    "metric": "mimicry_binary_recall",
    "baseline_rf": b_m["mimicry_binary_recall"],
    "proposed_iso_rf": p_m["mimicry_binary_recall"],
    "diff": p_m["mimicry_binary_recall"] - b_m["mimicry_binary_recall"],
})

comparison_df = pd.DataFrame(comparison)

print("\n=== Baseline RF vs Proposed ISO+RF comparison ===")
print(comparison_df.to_string(index=False))

# Feature importance proposed
importance_df = pd.DataFrame({
    "feature": list(X_train_prop.columns),
    "importance": proposed_rf.feature_importances_,
}).sort_values("importance", ascending=False)

print("\n=== Proposed top 20 feature importances ===")
print(importance_df.head(20).to_string(index=False))

# Save outputs
metrics_df.to_csv(RESULTS_DIR / "proposed_model_metrics.csv", index=False)
mimicry_df.to_csv(RESULTS_DIR / "proposed_model_mimicry.csv", index=False)
comparison_df.to_csv(RESULTS_DIR / "proposed_vs_baseline_comparison.csv", index=False)
pd.DataFrame(pr_rows).to_csv(RESULTS_DIR / "proposed_model_pr_auc.csv", index=False)

baseline_val_cm.to_csv(RESULTS_DIR / "baseline_rf_val_cm_day19.csv")
baseline_test_cm.to_csv(RESULTS_DIR / "baseline_rf_test_cm_day19.csv")
proposed_val_cm.to_csv(RESULTS_DIR / "proposed_iso_rf_val_cm.csv")
proposed_test_cm.to_csv(RESULTS_DIR / "proposed_iso_rf_test_cm.csv")

pd.DataFrame({
    "true_label": y_mimicry.values,
    "baseline_predicted_as": baseline_mimicry_pred,
    "proposed_predicted_as": proposed_mimicry_pred,
    "baseline_detected_as_attack": baseline_mimicry_pred != "normal_user",
    "proposed_detected_as_attack": proposed_mimicry_pred != "normal_user",
}).to_csv(RESULTS_DIR / "proposed_vs_baseline_mimicry_predictions.csv", index=False)

importance_df.to_csv(RESULTS_DIR / "proposed_model_feature_importance.csv", index=False)

print(f"\nSaved proposed model results to {RESULTS_DIR}")