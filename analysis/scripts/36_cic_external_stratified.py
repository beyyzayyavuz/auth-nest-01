"""
CIC-DDoS2019 limited external sanity check — stratified binary split.

Amaç:
- UDPLag train/test parquet dosyalarını birleştir
- Binary label üret: Benign vs Attack
- Aynı CIC subset içinde stratified train/test split yap
- Flow-level RF ile attack/benign ayrımı yapılabiliyor mu bak

Not:
Bu hâlâ bizim API-layer proposed modelimizin doğrudan external validation'ı değildir.
Bu sadece CIC flow-level feature space'inde sınırlı bir sanity check'tir.
"""

import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parents[1]
CIC_DIR = ROOT / "data/external/cicddos2019"
OUT = ROOT / "data/results/cic_external"
OUT.mkdir(parents=True, exist_ok=True)

paths = [
    CIC_DIR / "UDPLag-training.parquet",
    CIC_DIR / "UDPLag-testing.parquet",
]

print("Loading CIC UDPLag parquet files...")
dfs = []
for p in paths:
    if not p.exists():
        raise FileNotFoundError(f"Missing file: {p}")
    d = pd.read_parquet(p)
    d.columns = [str(c).strip() for c in d.columns]
    d["source_file"] = p.name
    dfs.append(d)

df = pd.concat(dfs, ignore_index=True)

print(f"Combined shape: {df.shape}")

label_col = "Label"

print("\nOriginal label distribution:")
print(df[label_col].value_counts())

def to_binary_label(x):
    return "benign" if str(x).lower() == "benign" else "attack"

df["binary_label"] = df[label_col].apply(to_binary_label)

print("\nBinary label distribution:")
print(df["binary_label"].value_counts())

# Numeric flow features only
drop_cols = [label_col, "binary_label", "source_file"]
X = df.drop(columns=drop_cols, errors="ignore").select_dtypes(include=["number", "bool"])
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
y = df["binary_label"]

print(f"\nNumeric feature count: {X.shape[1]}")

# Stratified split
X_train, X_test, y_train, y_test, meta_train, meta_test = train_test_split(
    X,
    y,
    df[[label_col, "source_file"]],
    test_size=0.30,
    random_state=42,
    stratify=y,
)

print(f"Train rows: {len(X_train):,}")
print(f"Test rows : {len(X_test):,}")

print("\nTrain binary distribution:")
print(y_train.value_counts())

print("\nTest binary distribution:")
print(y_test.value_counts())

clf = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining stratified CIC flow-level RF...")
clf.fit(X_train, y_train)

print("Predicting stratified CIC test...")
pred = clf.predict(X_test)

acc = accuracy_score(y_test, pred)
macro_f1 = f1_score(y_test, pred, average="macro", zero_division=0)
weighted_f1 = f1_score(y_test, pred, average="weighted", zero_division=0)

labels = ["benign", "attack"]
cm = confusion_matrix(y_test, pred, labels=labels)
cm_df = pd.DataFrame(
    cm,
    index=[f"true_{x}" for x in labels],
    columns=[f"pred_{x}" for x in labels],
)

tn = cm[0, 0]
fp = cm[0, 1]
fn = cm[1, 0]
tp = cm[1, 1]

attack_recall = tp / (tp + fn) if (tp + fn) > 0 else np.nan
benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else np.nan

print("\n=== CIC UDPLag stratified binary sanity check ===")
print(f"Accuracy   : {acc:.4f}")
print(f"Macro-F1   : {macro_f1:.4f}")
print(f"Weighted-F1: {weighted_f1:.4f}")
print(f"Attack recall: {attack_recall:.4f}")
print(f"Benign FPR   : {benign_fpr:.4f}")

print("\nClassification report:")
print(classification_report(y_test, pred, labels=labels, zero_division=0))

print("\nConfusion matrix:")
print(cm_df)

# Original label breakdown on stratified test
breakdown = meta_test.copy().reset_index(drop=True)
breakdown["binary_label"] = y_test.reset_index(drop=True)
breakdown["pred"] = pred

breakdown_table = pd.crosstab(
    breakdown[label_col],
    breakdown["pred"],
    normalize="index",
)

print("\nPrediction distribution by original CIC label:")
print(breakdown_table)

# Feature importance
importance = pd.DataFrame({
    "feature": X_train.columns,
    "importance": clf.feature_importances_,
}).sort_values("importance", ascending=False)

print("\nTop 20 CIC flow feature importances:")
print(importance.head(20).to_string(index=False))

summary = pd.DataFrame([{
    "dataset": "CIC-DDoS2019 UDPLag subset combined stratified",
    "rows": len(df),
    "train_rows": len(X_train),
    "test_rows": len(X_test),
    "features": X_train.shape[1],
    "accuracy": acc,
    "macro_f1": macro_f1,
    "weighted_f1": weighted_f1,
    "attack_recall": attack_recall,
    "benign_fpr": benign_fpr,
    "note": (
        "Limited external flow-level sanity check using stratified split. "
        "Not direct validation of the API-layer proposed model because CIC lacks "
        "route templates, endpoint cost, backend timing, and nginx timeout features."
    ),
}])

summary.to_csv(OUT / "cic_udplag_stratified_summary.csv", index=False)
cm_df.to_csv(OUT / "cic_udplag_stratified_confusion_matrix.csv")
breakdown_table.to_csv(OUT / "cic_udplag_stratified_label_breakdown.csv")
importance.to_csv(OUT / "cic_udplag_stratified_feature_importance.csv", index=False)

print(f"\nSaved CIC stratified sanity outputs to: {OUT}")