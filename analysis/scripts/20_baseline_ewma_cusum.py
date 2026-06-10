"""
Day 18 - Baseline 2: EWMA + CUSUM statistical change detection.

Amaç:
Per-window req_rate üzerinden basit online anomaly detection yapmak.
Bu baseline binary çalışır:

normal_user -> 0
diğer class'lar -> 1

EWMA/CUSUM parametreleri train setindeki normal_user dağılımından kalibre edilir.

1. Calibrate Normalcy: Calculate the exact baseline mean ($\mu$) and variance ($\sigma$) of real users.
2. Configure Alarms: Set internal scaling parameters ($K$ for minor deviations, $H$ for the cumulative alarm limit).
3. Track Trends (EWMA): Calculate a moving average that heavily weights recent activity to catch sudden shifts.
4. Accumulate Offsets (CUSUM): Continuously add up small, consecutive deviations that drift above normal.
5. Alarm & Reset: Trigger an anomaly flag if EWMA or CUSUM benchmarks are violated, then clear memory for the next loop.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

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

def to_binary(y):
    return (y != "normal_user").astype(int)

y_val_bin = to_binary(y_val)
y_test_bin = to_binary(y_test)
y_mimicry_bin = to_binary(y_mimicry)

# Calibration from normal_user train req_rate
normal_req = X_train.loc[y_train == "normal_user", "req_rate"].astype(float)
mu = normal_req.mean()
sigma = normal_req.std(ddof=1)

if sigma == 0 or np.isnan(sigma):
    sigma = 1e-6

print("\nCalibration from train normal_user req_rate:")
print(f"  mean  = {mu:.4f}")
print(f"  std   = {sigma:.4f}")
print(f"  p95   = {normal_req.quantile(0.95):.4f}")
print(f"  p99   = {normal_req.quantile(0.99):.4f}")

# EWMA/CUSUM parameters
ALPHA = 0.30
K = 0.5 * sigma
H = 5.0 * sigma

print("\nEWMA/CUSUM parameters:")
print(f"  alpha = {ALPHA}")
print(f"  k     = {K:.4f}")
print(f"  h     = {H:.4f}")

def ewma_cusum_predict(X):
    """
    Basit sequential detector.
    X sırası parquet sırası üzerinden gider.
    Her row için req_rate'i normal mean'e göre izler.

    CUSUM sadece upper-shift detection yapar:
    req_rate normalden belirgin yüksekse anomaly.
    """
    rates = X["req_rate"].astype(float).fillna(0).values

    ewma = mu
    cusum_pos = 0.0
    preds = []

    for x in rates:
        ewma = ALPHA * x + (1 - ALPHA) * ewma

        # Upper CUSUM
        cusum_pos = max(0.0, cusum_pos + (x - mu - K))

        # anomaly condition
        is_anomaly = (cusum_pos > H) or (ewma > mu + 3 * sigma)

        preds.append(1 if is_anomaly else 0)

        # reset after alarm to avoid one attack burst contaminating all later rows
        if is_anomaly:
            cusum_pos = 0.0
            ewma = mu

    return np.array(preds)

def evaluate(name, X, y_bin):
    pred = ewma_cusum_predict(X)

    acc = accuracy_score(y_bin, pred)
    prec = precision_score(y_bin, pred, zero_division=0)
    rec = recall_score(y_bin, pred, zero_division=0)
    f1 = f1_score(y_bin, pred, zero_division=0)

    cm = confusion_matrix(y_bin, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    print(f"\n=== {name} ===")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1       : {f1:.4f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(cm)

    print("\nClassification report:")
    print(classification_report(
        y_bin,
        pred,
        labels=[0, 1],
        target_names=["normal_user", "attack"],
        zero_division=0
    ))

    return {
        "split": name,
        "alpha": ALPHA,
        "k": K,
        "h": H,
        "normal_mean": mu,
        "normal_std": sigma,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }

results = []
results.append(evaluate("val", X_val, y_val_bin))
results.append(evaluate("test", X_test, y_test_bin))
results.append(evaluate("mimicry_test", X_mimicry, y_mimicry_bin))

results_df = pd.DataFrame(results)
out_path = OUT_DIR / "baseline_ewma_cusum_results.csv"
results_df.to_csv(out_path, index=False)

print(f"\nSaved results to {out_path}")