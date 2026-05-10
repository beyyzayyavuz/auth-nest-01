"""
Tier 2 + Tier 3 (global) + Tier 4 (session) + baseline distance feature'larını
tek bir master parquet'e birleştir.
"""

import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

t2 = pd.read_parquet(OUT / 'tier2_features.parquet')
t3 = pd.read_parquet(OUT / 'tier3_global.parquet')
bd = pd.read_parquet(OUT / 'tier_baseline_distance.parquet')

print(f'T2: {len(t2):,} rows')
print(f'T3: {len(t3):,} rows')
print(f'BD: {len(bd):,} rows')

# Normalize types
for df in [t2, t3, bd]:
    df['scenario_id'] = df['scenario_id'].astype(str)
    df['window_start'] = pd.to_datetime(df['window_start'], utc=True)

# Merge T3 (global, per scenario+window) onto T2
master = t2.merge(t3, on=['scenario_id', 'window_start'], how='left')
print(f'After T3 merge: {len(master):,} rows')

# Merge baseline distance onto T2 (matching aggregation_type, key, window, scenario)
bd['aggregation_key'] = bd['aggregation_key'].astype(str)
master['aggregation_key'] = master['aggregation_key'].astype(str)
master = master.merge(
    bd, on=['aggregation_type', 'aggregation_key', 'window_start', 'scenario_id'],
    how='left'
)
print(f'After baseline-distance merge: {len(master):,} rows')

# Tier 4 session features per-window aggregation skip in v1
# (Future: per-(scenario, ip, window) session count from tier4_sessions)

# Fill NaN
fill_cols = ['global_unique_ip', 'global_unique_subnet', 'global_request_count',
             'global_req_rate', 'global_new_src_ratio',
             'markov_log_likelihood', 'iat_ks_distance']
for col in fill_cols:
    if col in master.columns:
        master[col] = master[col].fillna(0)

master.to_parquet(OUT / 'master_features.parquet', compression='snappy')
print(f'\nSaved master_features.parquet ({len(master):,} rows, {len(master.columns)} columns)')

print('\n=== Feature columns ===')
print(master.columns.tolist())