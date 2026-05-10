"""
Master feature DataFrame'i 5-class supervised problem için hazırla.
Mimicry holdout test-only.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

print('Loading master features...')
df = pd.read_parquet(OUT / 'master_features.parquet')
print(f'  {len(df):,} rows')

# Filter out S6 retry artifacts (broken/slowonly) — sadece final S6 kalsın
df = df[~df['scenario_id'].str.contains('_broken|_slowonly', na=False)].copy()
print(f'  After S6 retry artifact removal: {len(df):,} rows')

# Recovery'leri normal_user etiketine çek (label normalize)
df.loc[df['scenario_id'].str.endswith('_recovery'), 'majority_label'] = 'normal_user'

# Class label normalization
def normalize_label(label):
    if pd.isna(label): return 'unknown'
    l = str(label).lower()
    if 'normal_user' in l: return 'normal_user'
    if 'mimicry' in l: return 'mimicry_flood'
    if 'flood' in l and 'mimicry' not in l: return 'http_flood'
    if 'low_rate' in l: return 'low_rate_bot'
    if 'credential' in l or 'stuffing' in l: return 'credential_stuffing'
    if 'slow' in l: return 'slow_http'
    return 'unknown'

df['label'] = df['majority_label'].apply(normalize_label)
df = df[df['label'] != 'unknown'].copy()
print(f'\nLabel distribution:')
print(df['label'].value_counts())

# Split: mimicry_flood holdout test-only
holdout = df[df['label'] == 'mimicry_flood'].copy()
in_dist = df[df['label'] != 'mimicry_flood'].copy()
print(f'\nIn-distribution: {len(in_dist):,}, Holdout (mimicry): {len(holdout):,}')

# Time-based train/val/test split on in_dist
in_dist = in_dist.sort_values('window_start').reset_index(drop=True)
n = len(in_dist)
train_end = int(n * 0.70)
val_end = int(n * 0.85)
in_dist['split'] = 'train'
in_dist.loc[train_end:val_end, 'split'] = 'val'
in_dist.loc[val_end:, 'split'] = 'test'

# Holdout: tamamı mimicry_test
holdout['split'] = 'mimicry_test'

final = pd.concat([in_dist, holdout], ignore_index=True)
final.to_parquet(OUT / 'dataset_split.parquet', compression='snappy')
print(f'\nSaved dataset_split.parquet')
print(final.groupby(['split', 'label']).size().unstack(fill_value=0))