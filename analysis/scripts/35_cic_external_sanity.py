"""
CIC-DDoS2019 limited external sanity check.

Amaç:
- UDPLag train/test parquet dosyalarını oku
- Binary label üret: Benign vs Attack
- Flow-level Random Forest eğit
- Test setinde accuracy, macro-F1, attack recall, benign FPR raporla
- Sonucu ana API-layer model validation değil, limited external flow-level sanity check olarak kaydet

Not:
Bu script bizim API-layer proposed modelimizi CIC'e doğrudan uygulamaz.
CIC feature-space'i network/flow-level olduğu için ayrı bir reference experiment yapılır.
"""

import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
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

train_path = CIC_DIR / "UDPLag-training.parquet"
test_path = CIC_DIR / "UDPLag-testing.parquet"

print("Loading CIC UDPLag train/test...")
train = pd.read_parquet(train_path)
test = pd.read_parquet(test_path)

train.columns = [str(c).strip() for c in train.columns]
test.columns = [str(c).strip() for c in test.columns]

print(f"Train shape: {train.shape}")
print(f"Test shape : {test.shape}")

label_col = "Label"

print("\nTrain label distribution:")
print(train[label_col].value_counts())

print("\nTest label distribution:")
print(test[label_col].value_counts())

# Binary label: Benign vs Attack
def to_binary_label(x):
    return "benign" if str(x).lower() == "benign" else "attack"

y_train = train[label_col].apply(to_binary_label)
y_test = test[label_col].apply(to_binary_label)

# Numeric flow features only
drop_cols = [label_col]
X_train = train.drop(columns=drop_cols, errors="ignore").select_dtypes(include=["number", "bool"])
X_test = test.drop(columns=drop_cols, errors="ignore").select_dtypes(include=["number", "bool"])

# Replace inf/nan
X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)

# Align columns
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

print(f"\nNumeric feature count: {X_train.shape[1]}")

clf = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced_subsample",
)

print("\nTraining CIC flow-level RF...")
clf.fit(X_train, y_train)

print("Predicting CIC test...")
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

# Attack recall and benign FPR
# cm layout:
# true benign: [TN, FP]
# true attack: [FN, TP]
tn = cm[0, 0]
fp = cm[0, 1]
fn = cm[1, 0]
tp = cm[1, 1]

attack_recall = tp / (tp + fn) if (tp + fn) > 0 else np.nan
benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else np.nan

print("\n=== CIC UDPLag limited external sanity check ===")
print(f"Accuracy   : {acc:.4f}")
print(f"Macro-F1   : {macro_f1:.4f}")
print(f"Weighted-F1: {weighted_f1:.4f}")
print(f"Attack recall: {attack_recall:.4f}")
print(f"Benign FPR   : {benign_fpr:.4f}")

print("\nClassification report:")
print(classification_report(y_test, pred, labels=labels, zero_division=0))

print("\nConfusion matrix:")
print(cm_df)

# Per-original-label prediction breakdown
breakdown = pd.DataFrame({
    "original_label": test[label_col].values,
    "binary_label": y_test.values,
    "pred": pred,
})
breakdown_table = pd.crosstab(
    breakdown["original_label"],
    breakdown["pred"],
    normalize="index"
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

# Save
summary = pd.DataFrame([{
    "dataset": "CIC-DDoS2019 UDPLag subset",
    "train_rows": len(train),
    "test_rows": len(test),
    "features": X_train.shape[1],
    "accuracy": acc,
    "macro_f1": macro_f1,
    "weighted_f1": weighted_f1,
    "attack_recall": attack_recall,
    "benign_fpr": benign_fpr,
    "note": "Limited external flow-level sanity check; not direct API-layer proposed-model validation due to feature-space mismatch.",
}])

summary.to_csv(OUT / "cic_udplag_external_sanity_summary.csv", index=False)
cm_df.to_csv(OUT / "cic_udplag_confusion_matrix.csv")
breakdown_table.to_csv(OUT / "cic_udplag_label_prediction_breakdown.csv")
importance.to_csv(OUT / "cic_udplag_feature_importance.csv", index=False)

print(f"\nSaved CIC external sanity outputs to: {OUT}")