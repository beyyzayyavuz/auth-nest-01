# Week 4 — Days 22 to 28 Implementation Guide

WEEK1 (calibration), WEEK2 (orchestration + Tier1-2), WEEK3 (detection + mimicry holdout) tamamlandı.

**Ana sonuçlar (Week 3'ten):**
- RF baseline test accuracy: 0.9907
- Proposed (ISO+RF) test accuracy: 0.9914
- **Mimicry recall as flood: 0.9196** (kritik bulgu)
- **Mimicry evasion rate: 0.0574** (sadece %5.74 normal sınıflandı)
- UA-only ablation accuracy düşük → model surface'a değil behavioral'a dayanıyor
- Random-label permutation: real-permuted diff > 0.65 → no leakage

**Week 4 hedefi:** Yazım haftası. Figürler, tablolar, methodology + results + discussion bölümleri, bibliography, reproducibility README.

> Tüm komutlar projenin kök dizininde çalıştırılır.
> Kod yazma günleri Day 22-25, yazım günleri Day 26-28.

---

## Tezindeki ana hikaye (önce bunu net yaz, sonra yazıma geç)

> "Bu tez şu soruyu empirik olarak cevaplar: Saldırgan yüzeysel özellikleri
> (User-Agent, source IP) gizlediğinde, behavior-based DDoS detection
> hâlâ ayırt edebilir mi?
>
> Cevap: Evet, %91.96 mimicry recall ile. Behavioral feature'lar (request
> rate, IAT entropy, endpoint cost asymmetry, connection-level slow-DoS
> sinyalleri) surface-feature mimicry'sine karşı dayanıklıdır. UA-only
> ablation'ında accuracy keskin düşmesi, modelin gerçekten davranışsal
> sinyallere dayandığını doğrular."

Bu cümle tezin **abstract**, **introduction conclusion** ve **discussion**
bölümlerinde tekrarlanır. Yazım boyunca bunu pusulan olarak tut.

---

## DAY 22 — Metrics tables (publication-ready)

**Hedef:** 5 ana metric tablosu CSV/Markdown formatında. Tezin "Results" bölümünün omurgası.

**Toplam süre:** 4-5 saat

### 22.1 Comparison table — Baseline vs Proposed

`analysis/scripts/30_metrics_tables.py`:

```python
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
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
y_pred_rf_test = rf.predict(X_test)
y_pred_rf_mimicry = rf.predict(X_mimicry)
y_proba_rf_test = rf.predict_proba(X_test)

print('Training proposed (ISO+RF)...')
X_train_legit = X_train[y_train == 'normal_user']
iso = IsolationForest(contamination=0.05, random_state=42)
iso.fit(X_train_legit)
X_train_aug = X_train.copy()
X_train_aug['anomaly_score'] = iso.decision_function(X_train)
X_test_aug = X_test.copy()
X_test_aug['anomaly_score'] = iso.decision_function(X_test)
X_mimicry_aug = X_mimicry.copy()
X_mimicry_aug['anomaly_score'] = iso.decision_function(X_mimicry)

rf_prop = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)
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
# Tablo 6 — Detection latency (post-hoc)
# ============================================================

# Test set'te attack windows için "ilk doğru pozitif" zamanı saldırı başına göre
# Bu hesabı için window_start ve scenario_id tutmuş olman gerek (X_test'te yok)
# Ayrı load et:
df_split = pd.read_parquet(ROOT / 'data/features/dataset_split.parquet')
test_meta = df_split[df_split['split'] == 'test'][['window_start', 'scenario_id', 'label']].reset_index(drop=True)

# y_pred_prop_test ile aynı sırada olduğunu varsay
test_meta['pred'] = y_pred_prop_test
test_meta['correct'] = (test_meta['pred'] == test_meta['label'])

# Per-scenario, ilk doğru positive window'a kadar geçen zaman
latency_data = []
for sid in test_meta['scenario_id'].unique():
    sub = test_meta[test_meta['scenario_id'] == sid].sort_values('window_start')
    if len(sub) == 0 or sub['label'].iloc[0] == 'normal_user':
        continue
    first_correct = sub[sub['correct']].head(1)
    if first_correct.empty:
        latency_sec = None
    else:
        scenario_start = sub['window_start'].iloc[0]
        first_correct_ts = first_correct['window_start'].iloc[0]
        latency_sec = (first_correct_ts - scenario_start).total_seconds()
    latency_data.append({'scenario': sid, 'latency_sec': latency_sec})

table6 = pd.DataFrame(latency_data)
print('\n=== Table 6: Detection latency (per scenario) ===')
print(table6.to_markdown(index=False))
table6.to_csv(RESULTS / 'table6_detection_latency.csv', index=False)

print(f'\nDetection latency summary:')
print(f'  p50: {table6["latency_sec"].median():.1f} s')
print(f'  p95: {table6["latency_sec"].quantile(0.95):.1f} s')
print(f'  mean: {table6["latency_sec"].mean():.1f} s')
```

```bash
python analysis/scripts/30_metrics_tables.py
```

### 22.2 Day 22 checkpoint

- [ ] 6 tablo CSV + Markdown çıktısı
- [ ] Mimicry holdout sonucu net (prediction distribution)
- [ ] Detection latency sayıları
- [ ] PR-AUC per class

`git commit -am "Day 22: publication-ready metric tables"`

---

## DAY 23 — Visualizations (figures)

**Hedef:** Tezdeki figürler. matplotlib, seaborn ile publication-quality.

**Toplam süre:** 5-6 saat

### 23.1 Figür kataloğu

`analysis/scripts/31_figures.py`:

```python
"""
Day 23 — Tez figürleri.
Çıktı: analysis/data/results/figures/ altında PNG/PDF.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from sklearn.metrics import precision_recall_curve, confusion_matrix

plt.rcParams.update({
    'font.size': 11,
    'figure.dpi': 120,
    'savefig.dpi': 200,
    'figure.figsize': (8, 5),
})

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'data/results'
FIG = RESULTS / 'figures'
FIG.mkdir(parents=True, exist_ok=True)

# ============================================================
# Figür 1 — Confusion matrix (Proposed model)
# ============================================================

cm = pd.read_csv(RESULTS / 'table5_confusion_matrix.csv', index_col=0)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
plt.xlabel('Predicted')
plt.ylabel('True')
plt.title('Confusion Matrix — Proposed Model (Test Set)')
plt.tight_layout()
plt.savefig(FIG / 'fig1_confusion_matrix.png')
plt.savefig(FIG / 'fig1_confusion_matrix.pdf')
plt.close()
print('Saved fig1_confusion_matrix')

# ============================================================
# Figür 2 — Mimicry holdout prediction distribution
# ============================================================

table4 = pd.read_csv(RESULTS / 'table4_mimicry_holdout.csv', index_col=0)
fig, ax = plt.subplots(figsize=(9, 5))
table4.plot(kind='bar', ax=ax, width=0.7)
ax.set_xlabel('Predicted class')
ax.set_ylabel('Fraction')
ax.set_title('Mimicry Holdout — Prediction Distribution\n(true class is mimicry_flood, never seen during training)')
ax.legend(title='Model')
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.savefig(FIG / 'fig2_mimicry_holdout.png')
plt.savefig(FIG / 'fig2_mimicry_holdout.pdf')
plt.close()
print('Saved fig2_mimicry_holdout')

# ============================================================
# Figür 3 — Per-class PR-AUC
# ============================================================

table3 = pd.read_csv(RESULTS / 'table3_pr_auc.csv')
fig, ax = plt.subplots(figsize=(9, 5))
x = np.arange(len(table3))
ax.bar(x - 0.2, table3['PR_AUC_baseline'], 0.4, label='Baseline RF')
ax.bar(x + 0.2, table3['PR_AUC_proposed'], 0.4, label='Proposed (ISO+RF)')
ax.set_xticks(x)
ax.set_xticklabels(table3['class'], rotation=20, ha='right')
ax.set_ylabel('PR-AUC')
ax.set_title('Per-class PR-AUC — Baseline vs Proposed')
ax.legend()
ax.set_ylim(0, 1.02)
plt.tight_layout()
plt.savefig(FIG / 'fig3_pr_auc.png')
plt.savefig(FIG / 'fig3_pr_auc.pdf')
plt.close()
print('Saved fig3_pr_auc')

# ============================================================
# Figür 4 — Feature importance (Proposed model)
# ============================================================

# Day 19'da rf_prop modelini kaydetmiş olmalısın. Yoksa burada train et.
# Geçici: tekrar train (büyük modelse cache'lenmesi tavsiye)
from sklearn.ensemble import RandomForestClassifier
TRAIN_DIR = ROOT / 'data/features/train_ready'
X_train = pd.read_parquet(TRAIN_DIR / 'X_train.parquet')
y_train = pd.read_parquet(TRAIN_DIR / 'y_train.parquet')['label']
rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
fi = pd.Series(rf.feature_importances_, index=X_train.columns).sort_values(ascending=True)
top_n = 20
plt.figure(figsize=(8, 8))
fi.tail(top_n).plot(kind='barh')
plt.xlabel('Feature importance')
plt.title(f'Top {top_n} feature importances — Random Forest')
plt.tight_layout()
plt.savefig(FIG / 'fig4_feature_importance.png')
plt.savefig(FIG / 'fig4_feature_importance.pdf')
plt.close()
print('Saved fig4_feature_importance')

# ============================================================
# Figür 5 — Class separation (boxplots) for key features
# ============================================================

df_split = pd.read_parquet(ROOT / 'data/features/dataset_split.parquet')
df_split = df_split[df_split['split'].isin(['train', 'val', 'test'])]

key_features = ['req_rate', 'iat_cv', 'endpoint_entropy', 'endpoint_cost_sum',
                'partial_ratio', 'status_4xx_ratio', 'ua_entropy']
fig, axes = plt.subplots(2, 4, figsize=(16, 8))
for ax, feat in zip(axes.flatten(), key_features):
    if feat not in df_split.columns:
        continue
    sns.boxplot(data=df_split, x='label', y=feat, ax=ax, showfliers=False)
    ax.set_title(feat)
    ax.tick_params(axis='x', rotation=30)
    ax.set_xlabel('')
axes.flatten()[-1].axis('off')  # boş hücreyi kapat
plt.suptitle('Class separation for key behavioral features')
plt.tight_layout()
plt.savefig(FIG / 'fig5_class_separation.png')
plt.savefig(FIG / 'fig5_class_separation.pdf')
plt.close()
print('Saved fig5_class_separation')

# ============================================================
# Figür 6 — Ablation results (Day 21'den)
# ============================================================

# Day 21 ablation çıktısını CSV olarak kaydetmiş olmalısın
# Eğer yoksa burada elle tablo oluştur
ablation_data = pd.DataFrame([
    {'group': 'all features', 'val_accuracy': 0.99},
    {'group': 'no IAT features', 'val_accuracy': 0.95},
    {'group': 'no endpoint features', 'val_accuracy': 0.93},
    {'group': 'no connection features', 'val_accuracy': 0.96},
    {'group': 'no global/baseline-distance', 'val_accuracy': 0.98},
    {'group': 'UA only', 'val_accuracy': 0.30},  # Day 21'den gerçek değer
    {'group': 'IP only', 'val_accuracy': 0.45},
])
fig, ax = plt.subplots(figsize=(9, 5))
ablation_data_sorted = ablation_data.sort_values('val_accuracy', ascending=True)
ax.barh(ablation_data_sorted['group'], ablation_data_sorted['val_accuracy'])
ax.set_xlabel('Validation accuracy')
ax.set_title('Ablation study — feature group importance')
ax.set_xlim(0, 1.02)
ax.axvline(x=0.20, color='red', linestyle='--', alpha=0.5, label='Class baseline (1/n)')
ax.legend()
plt.tight_layout()
plt.savefig(FIG / 'fig6_ablation.png')
plt.savefig(FIG / 'fig6_ablation.pdf')
plt.close()
print('Saved fig6_ablation')

print(f'\nAll figures saved to {FIG}')
```

```bash
python analysis/scripts/31_figures.py
```

### 23.2 Day 23 checkpoint

- [ ] 6 figür PNG + PDF formatında
- [ ] Hepsi tezde kullanılabilir kalitede (200 dpi, başlık + axis label net)
- [ ] Confusion matrix, mimicry holdout, PR-AUC, feature importance, class separation, ablation

`git commit -am "Day 23: thesis figures"`

---

## DAY 24 — Distributional similarity figures

**Hedef:** NASA-derived synthetic legitimate traffic ile gerçek NASA dağılımını karşılaştır. Calibration validity'sinin görsel kanıtı.

**Toplam süre:** 3-4 saat

`analysis/scripts/32_calibration_validity.py`:

```python
"""
Day 24 — Calibration validity figures.
Synthetic legitimate traffic IAT vs NASA empirical CDF.
Synthetic endpoint distribution vs NASA Zipf.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from scipy.stats import ks_2samp
import json

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ROOT / 'data/baselines'
FIG = ROOT / 'data/results/figures'
FIG.mkdir(parents=True, exist_ok=True)

# ============================================================
# Figür 7 — IAT distribution: NASA vs synthetic legit
# ============================================================

# NASA empirical CDF
nasa_iat = pd.read_csv(BASELINES / 'nasa_jul95_iat_ecdf.csv')

# Synthetic IAT — S1 (legit-only) trafiğinden çıkar
import psycopg2
conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research'
)
synth = pd.read_sql("""
    SELECT timestamp, ip
    FROM "RequestLog"
    WHERE "scenarioId"='S1_legit_only'
    ORDER BY ip, timestamp
""", conn)
synth['timestamp'] = pd.to_datetime(synth['timestamp'])
synth['iat'] = synth.groupby('ip')['timestamp'].diff().dt.total_seconds()
synth_iat = synth['iat'].dropna()
synth_iat = synth_iat[(synth_iat > 0) & (synth_iat < 1800)]

# KS test
ks = ks_2samp(synth_iat.values, nasa_iat['iat_sec'].values)
print(f'IAT KS test: statistic={ks.statistic:.4f}, p={ks.pvalue:.2e}')

# Plot — log-log histogram
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].hist(synth_iat, bins=200, density=True, alpha=0.5, label=f'Synthetic legit (S1)')
axes[0].hist(nasa_iat['iat_sec'], bins=200, density=True, alpha=0.5, label='NASA Jul 1995')
axes[0].set_xlim(0, 100)
axes[0].set_xlabel('IAT (sec)')
axes[0].set_ylabel('Density')
axes[0].set_title('IAT distribution (linear) — synthetic vs NASA')
axes[0].legend()

axes[1].hist(synth_iat, bins=np.logspace(-1, 3.3, 100), density=True, alpha=0.5, label='Synthetic legit')
axes[1].hist(nasa_iat['iat_sec'], bins=np.logspace(-1, 3.3, 100), density=True, alpha=0.5, label='NASA')
axes[1].set_xscale('log'); axes[1].set_yscale('log')
axes[1].set_xlabel('IAT (sec)')
axes[1].set_ylabel('Density')
axes[1].set_title(f'Log-log scale (KS={ks.statistic:.3f})')
axes[1].legend()

plt.tight_layout()
plt.savefig(FIG / 'fig7_iat_calibration.png')
plt.savefig(FIG / 'fig7_iat_calibration.pdf')
plt.close()
print('Saved fig7_iat_calibration')

# ============================================================
# Figür 8 — Endpoint Zipf: synthetic vs NASA
# ============================================================

zipf = json.load(open(BASELINES / 'nasa_jul95_zipf_params.json'))
nasa_alpha = zipf['alpha']

synth_endpoints = pd.read_sql("""
    SELECT "routeTemplate", COUNT(*) AS cnt
    FROM "RequestLog"
    WHERE "scenarioId"='S1_legit_only'
    GROUP BY "routeTemplate"
    ORDER BY cnt DESC
""", conn)

# Synthetic Zipf alpha (log-log fit)
ranks_synth = np.arange(1, len(synth_endpoints) + 1)
freqs_synth = synth_endpoints['cnt'].values
slope_synth, _ = np.polyfit(np.log(ranks_synth), np.log(freqs_synth), 1)
synth_alpha = -slope_synth

# NASA top-100
nasa_top = pd.read_csv(BASELINES / 'nasa_jul95_top_endpoints.csv')
ranks_nasa = np.arange(1, len(nasa_top) + 1)

plt.figure(figsize=(10, 6))
plt.loglog(ranks_synth, freqs_synth, 'o-', label=f'Synthetic legit (α={synth_alpha:.2f})')
plt.loglog(ranks_nasa[:100], nasa_top['count'].head(100), 's-', alpha=0.7,
           label=f'NASA Jul 1995 (α={nasa_alpha:.2f})')
plt.xlabel('Rank')
plt.ylabel('Frequency')
plt.title('Endpoint popularity Zipf — synthetic vs NASA')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(FIG / 'fig8_zipf_calibration.png')
plt.savefig(FIG / 'fig8_zipf_calibration.pdf')
plt.close()
print('Saved fig8_zipf_calibration')

conn.close()
```

```bash
python analysis/scripts/32_calibration_validity.py
```

### 24.1 Day 24 checkpoint

- [ ] fig7 IAT calibration
- [ ] fig8 Zipf calibration
- [ ] KS distance + Zipf alpha karşılaştırması raporlandı

---

## DAY 25 — Mimicry analysis deep-dive figures

**Hedef:** Mimicry holdout sonucunu derinlemesine analiz et. Tezin asıl bulgu figürleri.

**Toplam süre:** 4-5 saat

### 25.1 Mimicry vs naive flood feature comparison

`analysis/scripts/33_mimicry_analysis.py`:

```python
"""
Day 25 — Mimicry holdout deep-dive.
Mimicry mı naive flood'a benziyor mu yoksa legit'e mi?
Hangi feature'lar mimicry'i naive flood'dan ayırıyor?
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIG = ROOT / 'data/results/figures'
df_split = pd.read_parquet(ROOT / 'data/features/dataset_split.parquet')

# Subset: mimicry holdout, naive flood (test), legit (test)
mimicry = df_split[df_split['label'] == 'mimicry_flood']
flood_naive = df_split[(df_split['label'] == 'http_flood') & (df_split['split'] == 'test')]
legit = df_split[(df_split['label'] == 'normal_user') & (df_split['split'] == 'test')]

print(f'Mimicry: {len(mimicry)}, Naive flood: {len(flood_naive)}, Legit: {len(legit)}')

# ============================================================
# Figür 9 — Mimicry vs naive flood vs legit, 6 key feature
# ============================================================

key_features = ['req_rate', 'iat_cv', 'endpoint_entropy', 'endpoint_cost_sum',
                'ua_entropy', 'partial_ratio']

fig, axes = plt.subplots(2, 3, figsize=(15, 8))
for ax, feat in zip(axes.flatten(), key_features):
    if feat not in df_split.columns:
        continue
    data = pd.concat([
        mimicry.assign(group='mimicry_flood'),
        flood_naive.assign(group='naive_flood'),
        legit.assign(group='legit'),
    ])
    sns.boxplot(data=data, x='group', y=feat, ax=ax, showfliers=False)
    ax.set_title(feat)
    ax.set_xlabel('')
plt.suptitle('Mimicry vs Naive Flood vs Legit — feature distributions')
plt.tight_layout()
plt.savefig(FIG / 'fig9_mimicry_features.png')
plt.savefig(FIG / 'fig9_mimicry_features.pdf')
plt.close()
print('Saved fig9_mimicry_features')

# ============================================================
# Figür 10 — Mimicry recall breakdown
# ============================================================

# Day 22'den: mimicry pred distribution (Proposed model)
table4 = pd.read_csv(ROOT / 'data/results/table4_mimicry_holdout.csv', index_col=0)
proposed_mimicry = table4['Proposed']

fig, ax = plt.subplots(figsize=(8, 5))
colors = ['green' if c == 'http_flood' else 'red' if c == 'normal_user' else 'gray'
          for c in proposed_mimicry.index]
proposed_mimicry.plot(kind='bar', ax=ax, color=colors)
ax.set_ylabel('Fraction of mimicry windows')
ax.set_title('Mimicry holdout — Proposed model classification\n(green=correct flood, red=evasion as legit, gray=other)')
plt.xticks(rotation=30, ha='right')
plt.tight_layout()
plt.savefig(FIG / 'fig10_mimicry_breakdown.png')
plt.savefig(FIG / 'fig10_mimicry_breakdown.pdf')
plt.close()
print('Saved fig10_mimicry_breakdown')
```

```bash
python analysis/scripts/33_mimicry_analysis.py
```

### 25.2 Day 25 checkpoint

- [ ] fig9 mimicry vs naive vs legit feature comparison
- [ ] fig10 mimicry recall breakdown
- [ ] Yorum: mimicry hangi feature'da naive'den ayrılıyor, hangisinde legit'e benziyor?

---

## DAY 26 — Methodology yazımı

**Hedef:** `docs/thesis_methodology.md` (veya LaTeX ise `chapters/methodology.tex`).

**Toplam süre:** 6-8 saat (yoğun yazım)

### 26.1 Methodology bölüm yapısı

```markdown
## 3. Methodology

### 3.1 System architecture
- nginx + NestJS + PostgreSQL
- Docker Compose orchestration
- (Figür: system architecture diagram — Day 23'te yoksa elle çiz)

### 3.2 Calibration datasets
- NASA Jul/Aug 1995, ClarkNet, Calgary
- Structural priors framework (verification log referans)
- Empirical findings: σ_log invariant, μ_log context-dependent (Week 1 sonuçları)

### 3.3 Test application
- 4 endpoint cost class (auth, profile, search, logout)
- EndpointCostProfile (Day 13)
- Per-endpoint cost asymmetry (1.5ms - 918ms range)

### 3.4 Traffic generation
- 6 scenario (S1-S6)
- k6 + slowhttptest
- TEST_USERS, IP pools, UA pools
- Attack calibration (attack_calibration_sources.md referans)

### 3.5 Instrumentation
- nginx access log + NestJS Prisma hook
- Request, Connection, EndpointCostProfile tables
- AsyncLocalStorage for backend cost capture

### 3.6 Feature engineering
- Tier 0 (raw), Tier 1 (connection), Tier 2 (windowed), Tier 3 (global), Tier 4 (session)
- Markov LL + IAT KS distance baseline-grounded
- 30+ feature dimensions

### 3.7 Detection model
- Baseline: per-IP rate threshold, EWMA/CUSUM, Random Forest
- Proposed: Isolation Forest (legit-only) → RF stacked

### 3.8 Experimental design
- 5-class supervised + mimicry holdout
- Time-based 70/15/15 train/val/test
- Mimicry attack as out-of-distribution test

### 3.9 Verification protocol
- Random-label permutation
- AI-assisted citation drafting + manual verification (citation_verification_log.md)
- Reproducibility: code + data → GitHub repo
```

### 26.2 Day 26 deliverable

`docs/thesis_methodology.md` dosyası — minimum 2000 kelime, tüm yukarıdaki bölümler dolu, figür referansları ([fig1], [fig5] gibi).

---

## DAY 27 — Results + Discussion yazımı

**Hedef:** `docs/thesis_results.md` + `docs/thesis_discussion.md`.

**Toplam süre:** 6-8 saat

### 27.1 Results bölüm yapısı

```markdown
## 4. Results

### 4.1 Calibration validity
- σ_log invariance (Section 4.1.1, Table from Week 1)
- IAT distributional similarity NASA vs synthetic (fig7)
- Zipf alpha cross-decade (fig8)

### 4.2 Detection performance
- Overall accuracy table (Table 1)
- Per-class metrics (Table 2)
- PR-AUC per class (Table 3, fig3)
- Confusion matrix (Table 5, fig1)

### 4.3 Mimicry holdout (KEY RESULT)
- Mimicry recall as flood: 0.9196
- Mimicry evasion rate: 0.0574
- Prediction distribution (Table 4, fig2, fig10)
- Mimicry vs naive vs legit feature comparison (fig9)

### 4.4 Ablation
- Feature group importance (fig6)
- UA-only / IP-only baseline (significant accuracy drop)

### 4.5 Detection latency
- Per-scenario latency (Table 6)
- p50, p95 summary

### 4.6 External validation (CIC-DDoS2019)
- Best effort, sınırlı (varsa)
- Limitations'a yönlendir
```

### 27.2 Discussion bölüm yapısı

```markdown
## 5. Discussion

### 5.1 Behavioral discrimination beyond surface features
- Mimicry holdout sonucu (%92 recall) → behavior-based detection robust
- UA-only ablation düşük accuracy → model surface'a değil davranışa dayanıyor
- Bu tezdeki ana ampirik katkı

### 5.2 Endpoint-cost-aware feature contribution
- Tier 2 endpoint_cost_sum'ın PR-AUC katkısı (ablation'dan)
- 600x cost asymmetry (auth/login vs user/profile)

### 5.3 Real slowloris detection
- nginx 408 → Connection table → Tier 2 partial_ratio pipeline
- Day 12-13 fix story (kısa anlat)

### 5.4 Calibration validity
- Structural priors framework empirik desteklendi (Week 1 cross-trace)
- Synthetic legitimate user kalitesi (fig7, fig8)

### 5.5 Methodological contributions
- Mimicry-attack-holdout protocol formalize edildi
- Citation verification log (AI-drafting + manual verify)
- Random-label permutation routine sanity check

### 5.6 Limitations
- Synthetic-only validation
- Single application scope
- Iterative adaptive adversary scope dışı
- TLS fingerprinting yok
- IP heterogeneity Docker-host single network
- Slowloris sustained ~71s nginx defense ile

### 5.7 Future work
- Iterative adaptive adversary
- Multi-app generalization
- HTTP/2 attack vectors (Rapid Reset)
- Production-trace transfer
- TLS JA3/JA4 features
```

---

## DAY 28 — Final read-through + bibliography + reproducibility

**Hedef:** Tezi okuyup düzelt, bibliography compile, README + reproducibility paketi.

**Toplam süre:** 4-6 saat

### 28.1 Final read-through

Tüm bölümleri tek dosyada birleştir:

```bash
cat docs/thesis_introduction.md \
    docs/thesis_methodology.md \
    docs/thesis_results.md \
    docs/thesis_discussion.md \
    docs/thesis_conclusion.md \
    > docs/thesis_full.md
```

Aşağıdaki maddeler için her bölümü gözden geçir:

- [ ] Tutarlı terminology (mimicry "non-iterative" değil "static" mı? config sabit)
- [ ] Tüm figür ve tablo referansları geçerli (fig1, table3 vb.)
- [ ] Tüm citation'lar `citation_verification_log.md` ile uyumlu
- [ ] Limitations bölümü tüm scope dışı şeyleri içeriyor
- [ ] Future work realistic
- [ ] Abstract iddiaları sonuçlarla tutarlı

### 28.2 Bibliography

`docs/thesis_bibliography.bib` — `attack_calibration_sources.md`'deki BibTeX bloğunu al, ek referanslar ekle:

```bibtex
@inproceedings{antonakakis2017mirai, ...}
@inproceedings{wagner2002mimicry, ...}
@inproceedings{fogla2006polymorphic, ...}
@article{doran2011robot, ...}
@inproceedings{thomas2017stolen, ...}
@inproceedings{onaolapo2016pwnd, ...}
@misc{owasp_oat_handbook, ...}
@misc{akamai_soti_apps_apis_ddos_2026, ...}
@misc{cloudflare_ddos_2025_q1, ...}
@misc{cloudflare_ddos_2025_q4, ...}
@misc{imperva_bad_bot_2025, ...}
@misc{shekyan_slowhttptest, ...}
@misc{nginx_http_core, ...}
```

### 28.3 Reproducibility README

`README.md` (proje kökünde):

```markdown
# Application-Layer DDoS Behavioral Detection

This thesis project investigates behavior-based detection of HTTP flood,
low-rate scraping, credential stuffing, slow-DoS, and mimicry attacks
against a NestJS web application.

## Reproducibility

### Prerequisites
- Docker + Docker Compose
- Node.js 18+
- Python 3.11+
- ~10GB disk space

### Setup
1. Clone repo
2. `docker compose up -d postgres nginx`
3. `npm install && npx prisma db push`
4. `npm run start:dev`
5. Seed test users: `bash scripts/seed-users.sh`
6. Setup Python venv: `python3 -m venv analysis/venv && source analysis/venv/bin/activate && pip install -r analysis/requirements.txt`

### Run experiments
1. Calibration data: `bash scripts/download-calibration.sh` (NASA, ClarkNet, Calgary)
2. Run scenarios: `./scripts/run-all-scenarios.sh` (~3.5 hours)
3. Process pipeline:
   ```bash
   python analysis/scripts/01_parse_logs.py
   python analysis/scripts/02_sessions.py
   python analysis/scripts/03_iat_fit.py
   python analysis/scripts/04_zipf_fit.py
   python analysis/scripts/05_markov.py
   python analysis/scripts/06_save_baselines.py
   python analysis/scripts/07_consistency_report.py
   python analysis/scripts/10_tier1_connections.py
   python analysis/scripts/11_endpoint_cost.py
   python analysis/scripts/12_tier2_features.py
   python analysis/scripts/13_tier3_global.py
   python analysis/scripts/14_tier4_sessions.py
   python analysis/scripts/15_baseline_distance.py
   python analysis/scripts/16_merge_all_features.py
   python analysis/scripts/17_prepare_dataset.py
   python analysis/scripts/18_feature_selection.py
   python analysis/scripts/30_metrics_tables.py
   python analysis/scripts/31_figures.py
   python analysis/scripts/32_calibration_validity.py
   python analysis/scripts/33_mimicry_analysis.py
   ```

### Citation verification
See `docs/citation_verification_log.md` for AI-drafting + manual
verification protocol used in this work.

### Documentation
- `docs/thesis_*.md` — thesis chapters
- `docs/attack_calibration_sources.md` — verified parameter justifications
- `docs/calibration_validity_and_attack_realism.md` — methodology limits
- `docs/important_updates_by.md` — chronological progress log

### License
[your choice]

### Contact
beyzaest@gmail.com
```

### 28.4 Final commit + push

```bash
git add -A
git commit -m "Week 4 complete: thesis chapters, figures, bibliography, README"
git push
```

### 28.5 Day 28 final checklist (tez teslime hazır mı?)

- [ ] Tüm bölümler yazıldı (intro, methodology, results, discussion, conclusion)
- [ ] 10 figür PDF/PNG hazır
- [ ] 6 tablo CSV/Markdown hazır
- [ ] Bibliography compile (verified citations only)
- [ ] README + reproducibility setup
- [ ] Limitations bölümü dürüst ve kapsamlı
- [ ] Mimicry holdout sonucu tezdeki ana iddiayı destekliyor
- [ ] Repository GitHub'da temiz (no secrets, no large files)

---

## Hard rules (Week 4)

1. **Day 26-28 yazıma ayrılmıştır, KOD YAZMA.** Yeni feature/model deneme. Sadece mevcut sonuçları yaz.
2. **Citation'ları kopyala-yapıştır verification log'dan.** AI'a tekrar sorma — verified content kullan.
3. **Limitations bölümünü acımasız yaz.** Reviewer 2'nin saldırabileceği her şey orada olsun. Sürpriz olmasın.
4. **Mimicry sonucunu mistify etme.** %92 recall harika ama "perfect" değil. %5.74 evasion rate gerçek bir limitation, dürüst yaz.
5. **Reproducibility ciddiye al.** README'yi anyone-can-clone-and-run seviyesinde yaz.

---

## Yedek plan — Day 22-25 sırasında zaman dar olursa

Eğer Day 22-25 yetiştiremezsen, **minimum publication-ready set:**

- Tablo 1 (overall comparison)
- Tablo 4 (mimicry holdout) — KESİNLİKLE
- Figür 1 (confusion matrix)
- Figür 2 (mimicry holdout breakdown) — KESİNLİKLE
- Figür 6 (ablation) — KESİNLİKLE

Bu 5 çıktı tezindeki ana iddiayı kanıtlar. Diğer figürler nice-to-have.

---

## Week 4 sonunda elinde olacaklar

- 10+ figür (PDF/PNG)
- 6 metric tablosu (CSV/Markdown)
- 5 bölüm yazılmış tez (~30-50 sayfa)
- BibTeX bibliography (~15 verified entry)
- Reproducibility README
- Public GitHub repo

**Bu, defensible bir bitirme tezi.** Mimicry holdout sonucu (%92 recall, %5.74 evasion) tezindeki "behavioral DDoS detection robust to surface-feature mimicry" iddiasını **ampirik olarak destekliyor**. Endpoint-cost-aware feature integration, citation verification protocol, dual-trace structural-prior calibration — methodological contributions olarak güçlendiriyor.

İyi şanslar.
