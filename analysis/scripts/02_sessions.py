"""
Per-host session segmentation — NASA Jul95 ve NASA Aug95.
Calgary anonymized olduğu için (2 host) atlanır.
"""

import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SESSION_DATASETS = ['nasa_jul95', 'nasa_aug95', 'clarknet_aug28', 'clarknet_sep4']
PARSED = ROOT / 'data/parsed'
SESSION_GAP_SEC = 1800

summary = []

for name in SESSION_DATASETS:
    in_path = PARSED / f'{name}.parquet'
    if not in_path.exists():
        print(f'SKIP {name}: parsed parquet bulunamadı')
        continue

    print(f'\n=== Sessions: {name} ===')
    df = pd.read_parquet(in_path)
    df = df.sort_values(['host', 'timestamp']).reset_index(drop=True)

    df['gap_sec'] = df.groupby('host')['timestamp'].diff().dt.total_seconds()
    df['new_session'] = (df.gap_sec.isna()) | (df.gap_sec > SESSION_GAP_SEC)
    df['session_idx'] = df.groupby('host')['new_session'].cumsum()
    df['session_id'] = df['host'] + '_' + df['session_idx'].astype(str)

    session_stats = df.groupby('session_id').agg(
        request_count=('timestamp', 'count'),
        duration_sec=('timestamp', lambda x: (x.max() - x.min()).total_seconds()),
        unique_paths=('path', 'nunique'),
    ).reset_index()

    print(f'  Total sessions: {len(session_stats):,}')
    print(f'  Avg requests/session: {session_stats.request_count.mean():.2f}')
    print(f'  Median: {session_stats.request_count.median():.0f}')
    print(f'  P95: {session_stats.request_count.quantile(0.95):.0f}')
    bounces = (session_stats.request_count == 1).sum()
    print(f'  Bounce rate: {bounces/len(session_stats):.2%}')

    session_stats.to_parquet(PARSED / f'{name}_sessions.parquet', compression='snappy')
    df.to_parquet(PARSED / f'{name}_with_sessions.parquet', compression='snappy')

    summary.append({
        'dataset': name,
        'sessions': len(session_stats),
        'mean_req_per_session': session_stats.request_count.mean(),
        'median_req_per_session': session_stats.request_count.median(),
        'p95_req_per_session': session_stats.request_count.quantile(0.95),
        'bounce_rate': bounces / len(session_stats),
    })

print('\n=== Cross-trace comparison ===')
print(pd.DataFrame(summary).to_string(index=False))

print('\nNote: Calgary session segmentation skipped — anonymization '
      'reduces all hosts to 2 distinct values (local/remote), making '
      'per-user session analysis meaningless. Calgary is used for '
      'path-level cross-trace validation only (Day 6).')