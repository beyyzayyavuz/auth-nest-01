"""
Day 17 — Feature selection + train/val/test/mimicry_test split-aware
matrix preparation.

Day 16'dan gelen dataset_split.parquet'i alır, label-leaking kolonları
düşürür, random-label permutation testiyle sanity check yapar, ve Day 18+
modelleri için hazır numerik feature matrislerini parquet olarak kaydeder.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'
TRAIN_DIR = OUT / 'train_ready'
TRAIN_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# 1. Load dataset (with split column from Day 16)
# ============================================================

print('Loading dataset_split.parquet...')
df = pd.read_parquet(OUT / 'dataset_split.parquet')
print(f'  {len(df):,} rows')
print(df.groupby(['split', 'label']).size().unstack(fill_value=0))

# ============================================================
# 2. Drop label-leaking and meta columns
# ============================================================

# Label/target/meta — never as features
DROP_COLS = [
    'scenario_id',           # label proxy (one-to-one with attack class)
    'majority_label',        # target (raw)
    'label',                 # target (normalized)
    'split',                 # meta
    'window_start',          # time (could leak time-of-day → scenario)
    'window_end',
    'aggregation_key',       # unique IP/subnet — overfitting risk
    # 'aggregation_type' KALIYOR — categorical feature (ip vs subnet)
    # 'trafficLabel' KALIYOR (eğer varsa) — bunu da düşürmek lazım, label proxy
]

# trafficLabel feature'larından da koruma (varsa)
for col in df.columns:
    if 'trafficLabel' in col or 'majority_' in col:
        if col not in DROP_COLS:
            DROP_COLS.append(col)

print(f'\nDropping columns: {DROP_COLS}')

# Build feature matrix
def build_X_y(subset_df):
    X = subset_df.drop(columns=DROP_COLS, errors='ignore')
    # Numeric ve boolean kolonları al
    X = X.select_dtypes(include=['number', 'bool'])
    # aggregation_type categorical → one-hot
    if 'aggregation_type' in subset_df.columns:
        ohe = pd.get_dummies(subset_df['aggregation_type'], prefix='agg')
        X = pd.concat([X.reset_index(drop=True), ohe.reset_index(drop=True)], axis=1)
    X = X.fillna(0)
    y = subset_df['label']
    return X, y

# ============================================================
# 3. Build splits
# ============================================================

splits = {}
for split_name in ['train', 'val', 'test', 'mimicry_test']:
    sub = df[df['split'] == split_name]
    X, y = build_X_y(sub)
    splits[split_name] = (X, y)
    print(f'\n{split_name}: {len(X):,} rows, {len(X.columns)} features')
    print(f'  Label distribution: {y.value_counts().to_dict()}')

# ============================================================
# 4. Random-label permutation sanity (Day 14'te yapıldı, tekrarla)
# ============================================================

print('\n=== Random-label permutation sanity ===')
X_train, y_train = splits['train']

clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)

print('  Computing real-label CV accuracy...')
real_acc = cross_val_score(clf, X_train, y_train, cv=3, scoring='accuracy').mean()

print('  Computing permuted-label CV accuracy...')
y_train_perm = y_train.sample(frac=1, random_state=42).reset_index(drop=True)
perm_acc = cross_val_score(clf, X_train, y_train_perm, cv=3, scoring='accuracy').mean()

n_classes = y_train.nunique()
baseline_acc = 1.0 / n_classes
diff = real_acc - perm_acc

print(f'\n  Real label CV accuracy:    {real_acc:.3f}')
print(f'  Permuted label accuracy:   {perm_acc:.3f}')
print(f'  Class baseline (1/n):      {baseline_acc:.3f}')
print(f'  Diff (real - permuted):    {diff:.3f}')

if diff < 0.4:
    print('  ⚠️  WARNING: diff < 0.4 — feature signal weak OR data leakage')
elif perm_acc > baseline_acc + 0.15:
    print('  ⚠️  WARNING: permuted accuracy too high — possible leakage')
else:
    print('  ✓ Sanity check PASSED — features carry genuine signal, no leakage')

# ============================================================
# 5. Save train-ready matrices
# ============================================================

print('\nSaving train-ready matrices...')
for split_name, (X, y) in splits.items():
    X.to_parquet(TRAIN_DIR / f'X_{split_name}.parquet', compression='snappy')
    y.to_frame(name='label').to_parquet(
        TRAIN_DIR / f'y_{split_name}.parquet', compression='snappy'
    )

# Feature column listesini de kaydet (Day 18+ scripts için reference)
feature_cols = list(splits['train'][0].columns)
with open(TRAIN_DIR / 'feature_columns.txt', 'w') as f:
    f.write('\n'.join(feature_cols))

print(f'  Saved to {TRAIN_DIR}')
print(f'  {len(feature_cols)} feature columns:')
for col in feature_cols:
    print(f'    - {col}')