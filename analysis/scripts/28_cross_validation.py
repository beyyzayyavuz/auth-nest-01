"""
5-fold stratified cross-validation for the proposed Random Forest model.

Goal: report in-distribution accuracy as a mean ± std across folds,
which is the academic standard, rather than a single train/val/test
split number.

Output:
- analysis/data/results/cross_validation_results.csv  (per-fold metrics)
- Printed summary: mean ± std accuracy and macro-F1
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

ROOT = Path(__file__).resolve().parents[1]
TRAIN_DIR = ROOT / "data/features/train_ready"
RESULTS = ROOT / "data/results"
RESULTS.mkdir(parents=True, exist_ok=True)

print("Loading train-ready matrices...")
X_train = pd.read_parquet(TRAIN_DIR / "X_train.parquet")
y_train = pd.read_parquet(TRAIN_DIR / "y_train.parquet")["label"]

X_val = pd.read_parquet(TRAIN_DIR / "X_val.parquet")
y_val = pd.read_parquet(TRAIN_DIR / "y_val.parquet")["label"]

X_test = pd.read_parquet(TRAIN_DIR / "X_test.parquet")
y_test = pd.read_parquet(TRAIN_DIR / "y_test.parquet")["label"]

# Combine train+val+test for 5-fold CV (in-distribution pool)
X_all = pd.concat([X_train, X_val, X_test], axis=0, ignore_index=True)
y_all = pd.concat([y_train, y_val, y_test], axis=0, ignore_index=True)

print(f"Total in-distribution rows: {len(X_all):,}")
print(f"Features: {X_all.shape[1]}")
print(f"\nClass distribution:")
print(y_all.value_counts())

# 5-fold stratified CV
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nRunning 5-fold stratified cross-validation...")
scoring = {
    "accuracy": "accuracy",
    "macro_f1": "f1_macro",
    "weighted_f1": "f1_weighted",
}

cv_results = cross_validate(
    clf, X_all, y_all,
    cv=skf,
    scoring=scoring,
    return_train_score=False,
    n_jobs=-1,
)

# Per-fold table
per_fold = pd.DataFrame({
    "fold": list(range(1, 6)),
    "accuracy": cv_results["test_accuracy"],
    "macro_f1": cv_results["test_macro_f1"],
    "weighted_f1": cv_results["test_weighted_f1"],
})

print("\n=== Per-fold metrics ===")
print(per_fold.to_string(index=False))

# Summary
summary = pd.DataFrame([{
    "metric": "accuracy",
    "mean": cv_results["test_accuracy"].mean(),
    "std": cv_results["test_accuracy"].std(),
    "min": cv_results["test_accuracy"].min(),
    "max": cv_results["test_accuracy"].max(),
}, {
    "metric": "macro_f1",
    "mean": cv_results["test_macro_f1"].mean(),
    "std": cv_results["test_macro_f1"].std(),
    "min": cv_results["test_macro_f1"].min(),
    "max": cv_results["test_macro_f1"].max(),
}, {
    "metric": "weighted_f1",
    "mean": cv_results["test_weighted_f1"].mean(),
    "std": cv_results["test_weighted_f1"].std(),
    "min": cv_results["test_weighted_f1"].min(),
    "max": cv_results["test_weighted_f1"].max(),
}])

print("\n=== 5-fold CV Summary ===")
print(summary.to_string(index=False))

print(f"\n=== Headline ===")
print(f"5-fold CV accuracy:    {cv_results['test_accuracy'].mean():.4f} ± {cv_results['test_accuracy'].std():.4f}")
print(f"5-fold CV macro-F1:    {cv_results['test_macro_f1'].mean():.4f} ± {cv_results['test_macro_f1'].std():.4f}")
print(f"5-fold CV weighted-F1: {cv_results['test_weighted_f1'].mean():.4f} ± {cv_results['test_weighted_f1'].std():.4f}")

# Save
per_fold.to_csv(RESULTS / "cross_validation_per_fold.csv", index=False)
summary.to_csv(RESULTS / "cross_validation_summary.csv", index=False)

print(f"\nSaved:")
print(f"  {RESULTS / 'cross_validation_per_fold.csv'}")
print(f"  {RESULTS / 'cross_validation_summary.csv'}")
