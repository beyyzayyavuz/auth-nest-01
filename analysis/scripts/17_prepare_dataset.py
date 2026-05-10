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

# Holdout groups
mimicry_holdout = df[df['label'] == 'mimicry_flood'].copy()
slow_holdout = df[df['label'] == 'slow_http'].copy()

# Supervised in-distribution classes
# slow_http has too few rows for supervised training, so it is evaluated separately.
in_dist = df[~df['label'].isin(['mimicry_flood', 'slow_http'])].copy()

print(f'\nIn-distribution supervised rows: {len(in_dist):,}')
print(f'Mimicry holdout rows: {len(mimicry_holdout):,}')
print(f'Slow HTTP holdout rows: {len(slow_holdout):,}')

# Stratified split instead of pure time-based split.
# Pure time split caused some classes to disappear from val/test because scenarios were run sequentially.
train_df, temp_df = train_test_split(
    in_dist,
    test_size=0.30,
    random_state=42,
    stratify=in_dist['label']
)

val_df, test_df = train_test_split(
    temp_df,
    test_size=0.50,
    random_state=42,
    stratify=temp_df['label']
)

train_df['split'] = 'train'
val_df['split'] = 'val'
test_df['split'] = 'test'

mimicry_holdout['split'] = 'mimicry_test'
slow_holdout['split'] = 'slow_http_test'

final = pd.concat(
    [train_df, val_df, test_df, mimicry_holdout, slow_holdout],
    ignore_index=True
)

final.to_parquet(OUT / 'dataset_split.parquet', compression='snappy')
print(f'\nSaved dataset_split.parquet')
print(final.groupby(['split', 'label']).size().unstack(fill_value=0))