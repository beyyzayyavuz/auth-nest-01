"""
Day 18 - Baseline 1: Per-IP req_rate threshold.

Amaç:
Sadece req_rate kullanarak binary attack detection yapmak.
Threshold, train setindeki normal_user req_rate p95 değerinden alınır.

normal_user -> benign / 0
diğer class'lar -> attack / 1
"""

import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

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

print(f"Train rows: {len(X_train):,}")
print(f"Val rows: {len(X_val):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Mimicry rows: {len(X_mimicry):,}")

# Binary label: normal_user = 0, attack = 1
def to_binary(y):
    return (y != "normal_user").astype(int)

y_train_bin = to_binary(y_train)
y_val_bin = to_binary(y_val)
y_test_bin = to_binary(y_test)
y_mimicry_bin = to_binary(y_mimicry)

# Threshold: normal_user train req_rate p95
normal_train_req_rate = X_train.loc[y_train == "normal_user", "req_rate"]
threshold = normal_train_req_rate.quantile(0.95)

print(f"\nThreshold selected from normal_user train req_rate p95: {threshold:.4f}")

def predict_with_threshold(X):
    return (X["req_rate"] > threshold).astype(int)

def evaluate(name, X, y_bin):
    pred = predict_with_threshold(X)

    acc = accuracy_score(y_bin, pred)
    prec = precision_score(y_bin, pred, zero_division=0)
    rec = recall_score(y_bin, pred, zero_division=0)
    f1 = f1_score(y_bin, pred, zero_division=0)

    print(f"\n=== {name} ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1       : {f1:.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(confusion_matrix(y_bin, pred))

    print("\nClassification report:")
    print(classification_report(
        y_bin,
        pred,
        target_names=["normal_user", "attack"],
        zero_division=0
    ))

    return {
        "split": name,
        "threshold": threshold,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "tn": confusion_matrix(y_bin, pred).ravel()[0],
        "fp": confusion_matrix(y_bin, pred).ravel()[1],
        "fn": confusion_matrix(y_bin, pred).ravel()[2],
        "tp": confusion_matrix(y_bin, pred).ravel()[3],
    }

results = []
results.append(evaluate("val", X_val, y_val_bin))
results.append(evaluate("test", X_test, y_test_bin))
results.append(evaluate("mimicry_test", X_mimicry, y_mimicry_bin))

results_df = pd.DataFrame(results)
results_path = OUT_DIR / "baseline_rate_threshold_results.csv"
results_df.to_csv(results_path, index=False)

print(f"\nSaved results to {results_path}")