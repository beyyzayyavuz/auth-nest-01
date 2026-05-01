"""
Endpoint popularity Zipf law fit — 5 dataset cross-trace.
Calgary path-level dahil (host info gerek değil).
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ['nasa_jul95', 'nasa_aug95', 'calgary', 'clarknet_aug28', 'clarknet_sep4']
PARSED = ROOT / 'data/parsed'
OUT = ROOT / 'data/baselines'

results = {}

for name in DATASETS:
    in_path = PARSED / f'{name}.parquet'
    if not in_path.exists():
        continue

    print(f'\n=== Zipf: {name} ===')
    df = pd.read_parquet(in_path)
    filt = df[(df.method == 'GET') & (df.status == 200)]
    counts = filt.path.value_counts()

    ranks = np.arange(1, min(len(counts), 1000) + 1)
    freqs = counts.values[:len(ranks)]
    slope, intercept = np.polyfit(np.log(ranks), np.log(freqs), 1)
    alpha = -slope

    print(f'  Unique paths: {len(counts):,}')
    print(f'  α (top 1000): {alpha:.3f}')
    print(f'  Top-1 share : {counts.iloc[0]/counts.sum():.2%}')
    print(f'  Top-10 share: {counts.head(10).sum()/counts.sum():.2%}')
    print(f'  Top-100 share: {counts.head(100).sum()/counts.sum():.2%}')

    params = {
        'dataset': name,
        'alpha': float(alpha),
        'unique_endpoints': int(len(counts)),
        'top_1_share': float(counts.iloc[0] / counts.sum()),
        'top_10_share': float(counts.head(10).sum() / counts.sum()),
        'top_100_share': float(counts.head(100).sum() / counts.sum()),
    }
    with open(OUT / f'{name}_zipf_params.json', 'w') as f:
        json.dump(params, f, indent=2)
    counts.head(100).to_csv(OUT / f'{name}_top_endpoints.csv')
    results[name] = (ranks, freqs, alpha)

plt.figure(figsize=(10, 6))
colors = {
    'nasa_jul95': 'C0',
    'nasa_aug95': 'C1',
    'calgary': 'C4',
    'clarknet_aug28': 'C2',
    'clarknet_sep4': 'C3',
}
for name, (ranks, freqs, alpha) in results.items():
    plt.loglog(ranks, freqs, '.', alpha=0.5,
               label=f'{name} (α={alpha:.2f})', color=colors.get(name))
plt.xlabel('Rank'); plt.ylabel('Frequency')
plt.title('Endpoint popularity (Zipf) — cross-trace')
plt.legend(); plt.grid(True, alpha=0.3)
plt.savefig(OUT / 'zipf_comparison.png', dpi=120)
print(f'\nSaved plot: {OUT / "zipf_comparison.png"}')

print('\n=== Cross-trace Zipf summary ===')
print(f'{"dataset":<18} {"α":>6} {"unique":>10} {"top-10%":>10}')
for name, (_, _, alpha) in results.items():
    with open(OUT / f'{name}_zipf_params.json') as f:
        p = json.load(f)
    print(f'{name:<18} {alpha:>6.2f} {p["unique_endpoints"]:>10,} '
          f'{p["top_10_share"]*100:>9.1f}%')