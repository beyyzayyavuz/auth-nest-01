"""
Day 18 - Baseline 3: Random Forest multiclass.

Train classes:
- normal_user
- http_flood
- low_rate_bot
- credential_stuffing

Holdout:
- mimicry_flood is kept as mimicry_test only.
- slow_http is not part of supervised multiclass training because it has only 2 rows.

1. Load Matrices: Pull fully engineered numeric X and y parquet folders.
2. Fit Classifier: Train an ensemble of 200 decision trees using class weighting.
3. Multi-Class Evaluation: Compute accuracy, macro/weighted F1, and confusion tables.
4. Precision-Recall AUC: Measure model certainty for each known attack class.
5. Zero-Day Stress Test: Run the unseen 'mimicry_flood' records through the engine 
   to evaluate fallback detection and document evasion risks.
6. Export Diagnostics: Save metrics, prediction logs, and feature importances.

Inputs:  'X_train.parquet', 'y_train.parquet', etc.
Outputs: Multiple diagnostics files mapping accuracy, PR-AUC, and feature rankings.
"""

import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    average_precision_score,
)
from sklearn.preprocessing import label_binarize

ROOT = Path(__file__).resolve().parents[1]
TRAIN_DIR = ROOT / "data/features/train_ready"
OUT_DIR = ROOT / "data/results"
OUT_DIR.mkdir(parents=True, exist_ok=True)

print("Loading train-ready matrices...")

X_train = pd.read_parquet(TRAIN_DIR / "X_train.parquet")
y_train = pd.read_parquet(TRAIN_DIR / "y_train.parquet")["label"]

X_val = pd.read_parquet(TRAIN_DIR / "X_val.parquet")
y_val = pd.read_parquet(TRAIN_DIR / "y_val.parquet")["label"]

X_test = pd.read_parquet(TRAIN_DIR / "X_test.parquet")
y_test = pd.read_parquet(TRAIN_DIR / "y_test.parquet")["label"]

X_mimicry = pd.read_parquet(TRAIN_DIR / "X_mimicry_test.parquet")
y_mimicry = pd.read_parquet(TRAIN_DIR / "y_mimicry_test.parquet")["label"]

feature_cols = list(X_train.columns)

print(f"Train rows: {len(X_train):,}, features: {len(feature_cols)}")
print(f"Val rows: {len(X_val):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")

print("\nTrain label distribution:")
print(y_train.value_counts())

classes = sorted(y_train.unique())
print(f"\nTraining classes: {classes}")

clf_rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining Random Forest...")
clf_rf.fit(X_train, y_train)

def evaluate_multiclass(name, X, y):
    print(f"\n=== {name} multiclass ===")
    pred = clf_rf.predict(X)

    acc = accuracy_score(y, pred)
    macro_f1 = f1_score(y, pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y, pred, average="weighted", zero_division=0)

    print(f"Accuracy   : {acc:.4f}")
    print(f"Macro-F1   : {macro_f1:.4f}")
    print(f"Weighted-F1: {weighted_f1:.4f}")

    print("\nClassification report:")
    print(classification_report(y, pred, labels=classes, zero_division=0))

    print("Confusion matrix:")
    cm = confusion_matrix(y, pred, labels=classes)
    cm_df = pd.DataFrame(cm, index=[f"true_{c}" for c in classes], columns=[f"pred_{c}" for c in classes])
    print(cm_df)

    return {
        "split": name,
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
    }, pred, cm_df

val_result, val_pred, val_cm = evaluate_multiclass("val", X_val, y_val)
test_result, test_pred, test_cm = evaluate_multiclass("test", X_test, y_test)

# PR-AUC per in-distribution class
print("\n=== Per-class PR-AUC ===")
results_pr = []

for split_name, X, y in [("val", X_val, y_val), ("test", X_test, y_test)]:
    y_bin = label_binarize(y, classes=classes)
    y_score = clf_rf.predict_proba(X)

    for i, c in enumerate(classes):
        ap = average_precision_score(y_bin[:, i], y_score[:, i])
        print(f"{split_name} / {c}: PR-AUC = {ap:.4f}")
        results_pr.append({
            "split": split_name,
            "class": c,
            "pr_auc": ap,
        })

# Mimicry holdout behavior
# Since mimicry_flood was not in training, RF cannot predict "mimicry_flood".
# We inspect which trained class it resembles and whether binary attack-vs-normal catches it.
print("\n=== Mimicry holdout behavior ===")
mimicry_pred = clf_rf.predict(X_mimicry)
mimicry_pred_counts = pd.Series(mimicry_pred).value_counts()

print("Mimicry predictions as trained classes:")
print(mimicry_pred_counts)

# Binary interpretation:
# If mimicry is predicted as normal_user => missed attack.
# If predicted as any attack class => detected as attack.
mimicry_detected = (mimicry_pred != "normal_user").astype(int)
mimicry_recall = mimicry_detected.mean()

print(f"\nMimicry binary attack recall: {mimicry_recall:.4f}")
print(f"Mimicry missed as normal_user: {(mimicry_pred == 'normal_user').sum()} / {len(mimicry_pred)}")

# Feature importance
importance_df = pd.DataFrame({
    "feature": feature_cols,
    "importance": clf_rf.feature_importances_,
}).sort_values("importance", ascending=False)

print("\n=== Top 20 feature importances ===")
print(importance_df.head(20).to_string(index=False))

# Save outputs
metrics_df = pd.DataFrame([val_result, test_result])
metrics_df.to_csv(OUT_DIR / "baseline_random_forest_metrics.csv", index=False)

pd.DataFrame(results_pr).to_csv(OUT_DIR / "baseline_random_forest_pr_auc.csv", index=False)

val_cm.to_csv(OUT_DIR / "baseline_random_forest_val_confusion_matrix.csv")
test_cm.to_csv(OUT_DIR / "baseline_random_forest_test_confusion_matrix.csv")

pd.DataFrame({
    "true_label": y_mimicry.values,
    "predicted_as": mimicry_pred,
    "detected_as_attack": mimicry_detected,
}).to_csv(OUT_DIR / "baseline_random_forest_mimicry_predictions.csv", index=False)

importance_df.to_csv(OUT_DIR / "baseline_random_forest_feature_importance.csv", index=False)

print(f"\nSaved RF results to {OUT_DIR}")