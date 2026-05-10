"""
Day 22 — Publication-ready metric tabloları.
Çıktı: analysis/data/results/ altında CSV + Markdown.
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from sklearn.metrics import (
    classification_report, confusion_matrix, precision_recall_curve,
    average_precision_score, f1_score, accuracy_score
)
from sklearn.preprocessing import label_binarize

ROOT = Path(__file__).resolve().parents[1]
TRAIN_DIR = ROOT / 'data/features/train_ready'
RESULTS = ROOT / 'data/results'
RESULTS.mkdir(parents=True, exist_ok=True)

# Day 18-19'dan saved model predictions varsa onları yükle.
# Yoksa burada tekrar train+predict et.
# (Saved predictions: analysis/data/predictions/ altında y_pred_*.parquet bekleniyor)

PREDS_DIR = ROOT / 'data/predictions'

# Eğer Day 18-19 sonucu pred'leri save etmediysen, burada baseline ve
# proposed modelleri yeniden train et ve predictions üret. Aksi halde:
# y_pred_baseline_test, y_pred_proposed_test, y_pred_proposed_mimicry vs.

# Örnek workflow (eğer pred parquet'ler hazırsa):
# y_test = pd.read_parquet(TRAIN_DIR / 'y_test.parquet')['label']
# y_pred_rf = pd.read_parquet(PREDS_DIR / 'y_pred_rf_test.parquet')['pred']
# y_pred_proposed = pd.read_parquet(PREDS_DIR / 'y_pred_proposed_test.parquet')['pred']

# Eğer pred'ler yoksa, modeli yeniden train et:
from sklearn.ensemble import RandomForestClassifier, IsolationForest

X_train = pd.read_parquet(TRAIN_DIR / 'X_train.parquet')
y_train = pd.read_parquet(TRAIN_DIR / 'y_train.parquet')['label']
X_test = pd.read_parquet(TRAIN_DIR / 'X_test.parquet')
y_test = pd.read_parquet(TRAIN_DIR / 'y_test.parquet')['label']
X_mimicry = pd.read_parquet(TRAIN_DIR / 'X_mimicry_test.parquet')
y_mimicry = pd.read_parquet(TRAIN_DIR / 'y_mimicry_test.parquet')['label']

print('Training baseline RF...')
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight='balanced_subsample')
rf.fit(X_train, y_train)
y_pred_rf_test = rf.predict(X_test)
y_pred_rf_mimicry = rf.predict(X_mimicry)
y_proba_rf_test = rf.predict_proba(X_test)

print('Training proposed (ISO+RF)...')
X_train_legit = X_train[y_train == 'normal_user']
iso = IsolationForest(contamination=0.05, random_state=42)
iso.fit(X_train_legit)
X_train_aug = X_train.copy()
X_train_aug['anomaly_score'] = -iso.decision_function(X_train)
X_test_aug = X_test.copy()
X_test_aug['anomaly_score'] = -iso.decision_function(X_test)
X_mimicry_aug = X_mimicry.copy()
X_mimicry_aug['anomaly_score'] = -iso.decision_function(X_mimicry)

rf_prop = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1, class_weight='balanced_subsample')
rf_prop.fit(X_train_aug, y_train)
y_pred_prop_test = rf_prop.predict(X_test_aug)
y_pred_prop_mimicry = rf_prop.predict(X_mimicry_aug)
y_proba_prop_test = rf_prop.predict_proba(X_test_aug)

# ============================================================
# Tablo 1 — Overall comparison
# ============================================================

classes = sorted(y_test.unique())
print(f'\nClasses: {classes}')

def metrics_summary(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'macro_f1': f1_score(y_true, y_pred, average='macro'),
        'weighted_f1': f1_score(y_true, y_pred, average='weighted'),
    }

table1 = pd.DataFrame({
    'Baseline RF': metrics_summary(y_test, y_pred_rf_test),
    'Proposed (ISO+RF)': metrics_summary(y_test, y_pred_prop_test),
}).T
table1.to_csv(RESULTS / 'table1_overall.csv')
print('\n=== Table 1: Overall comparison ===')
print(table1.round(4).to_markdown())

# ============================================================
# Tablo 2 — Per-class metrics (Proposed)
# ============================================================

cls_report = classification_report(y_test, y_pred_prop_test, output_dict=True)
table2 = pd.DataFrame(cls_report).T.round(4)
table2.to_csv(RESULTS / 'table2_per_class_proposed.csv')
print('\n=== Table 2: Per-class metrics (Proposed) ===')
print(table2.to_markdown())

# ============================================================
# Tablo 3 — PR-AUC per class
# ============================================================

y_test_bin = label_binarize(y_test, classes=classes)
table3_data = []
for i, c in enumerate(classes):
    ap_rf = average_precision_score(y_test_bin[:, i], y_proba_rf_test[:, i])
    ap_prop = average_precision_score(y_test_bin[:, i], y_proba_prop_test[:, i])
    table3_data.append({'class': c, 'PR_AUC_baseline': ap_rf, 'PR_AUC_proposed': ap_prop})
table3 = pd.DataFrame(table3_data)
table3.to_csv(RESULTS / 'table3_pr_auc.csv', index=False)
print('\n=== Table 3: PR-AUC per class ===')
print(table3.round(4).to_markdown(index=False))

# ============================================================
# Tablo 4 — Mimicry holdout (ASIL ANA TABLO)
# ============================================================

mimicry_pred_dist_baseline = pd.Series(y_pred_rf_mimicry).value_counts(normalize=True)
mimicry_pred_dist_proposed = pd.Series(y_pred_prop_mimicry).value_counts(normalize=True)

table4 = pd.DataFrame({
    'Baseline RF': mimicry_pred_dist_baseline,
    'Proposed': mimicry_pred_dist_proposed,
}).fillna(0)
table4.to_csv(RESULTS / 'table4_mimicry_holdout.csv')
print('\n=== Table 4: Mimicry holdout — prediction distribution ===')
print(table4.round(4).to_markdown())

# Specific mimicry metrics
print(f'\nMimicry recall as http_flood (proposed): {(y_pred_prop_mimicry == "http_flood").mean():.4f}')
print(f'Mimicry evasion rate (proposed): {(y_pred_prop_mimicry == "normal_user").mean():.4f}')

# ============================================================
# Tablo 5 — Confusion matrices
# ============================================================

cm_proposed = confusion_matrix(y_test, y_pred_prop_test, labels=classes)
cm_df = pd.DataFrame(cm_proposed, index=classes, columns=classes)
cm_df.to_csv(RESULTS / 'table5_confusion_matrix.csv')
print('\n=== Table 5: Confusion matrix (Proposed) ===')
print(cm_df.to_markdown())

# ============================================================
# Tablo 6 — Detection latency by scenario-flow
# ============================================================

latency_path = RESULTS / 'detection_latency_by_scenario.csv'
table6 = pd.read_csv(latency_path)

table6_out = table6[[
    'scenario_id',
    'expected_label',
    'detected',
    'latency_sec',
    'latency_min',
    'scenario_recall'
]].copy()

table6_out.to_csv(RESULTS / 'table6_detection_latency.csv', index=False)

print('\n=== Table 6: Detection latency by scenario-flow ===')
print(table6_out.to_markdown(index=False))

detected_latency = table6_out[table6_out['detected'] == True]['latency_sec'].dropna()

print(f'\nDetection latency summary:')
print(f'  p50: {detected_latency.quantile(0.50):.1f} s')
print(f'  p95: {detected_latency.quantile(0.95):.1f} s')
print(f'  mean: {detected_latency.mean():.1f} s')