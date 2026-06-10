"""
Per-session inter-arrival time fit — NASA + ClarkNet cross-validation.
Calgary atlanır (anonymized).
"""

import json
import pandas as pd
import numpy as np
from scipy import stats
from pathlib import Path
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ['nasa_jul95', 'nasa_aug95', 'clarknet_aug28', 'clarknet_sep4']
PARSED = ROOT / 'data/parsed'
OUT = ROOT / 'data/baselines'
OUT.mkdir(parents=True, exist_ok=True)

results = {}

for name in DATASETS:
    in_path = PARSED / f'{name}_with_sessions.parquet'
    if not in_path.exists():
        print(f'SKIP {name}: not found')
        continue

    print(f'\n=== IAT: {name} ===')
    df = pd.read_parquet(in_path)
    # Keep only real within-session request gaps.
    in_session = df[~df.new_session].copy()
    # in_session.gap_sec: selects the gap_sec column.
    # dropna(): removes any rows where gap_sec is NaN (which happens for the first request of each session).
    # values: converts the pandas Series to a NumPy array for easier processing.
    iat = in_session.gap_sec.dropna().values
    iat = iat[(iat > 0) & (iat < 1800)]

    print(f'  Samples: {len(iat):,}')
    print(f'  mean={iat.mean():.2f}s  median={np.median(iat):.2f}s  '
          f'p95={np.percentile(iat, 95):.2f}s')

    shape, loc, scale = stats.lognorm.fit(iat, floc=0)
    mu_log, sigma_log = np.log(scale), shape
    ks_stat, ks_p = stats.kstest(iat, 'lognorm', args=(shape, loc, scale))
    print(f'  Lognormal: μ_log={mu_log:.3f}, σ_log={sigma_log:.3f}, '
          f'KS={ks_stat:.4f} (p={ks_p:.2e})')

    percentiles = np.arange(0, 100.5, 0.5)
    ecdf = np.percentile(iat, percentiles)
    pd.DataFrame({'percentile': percentiles, 'iat_sec': ecdf}).to_csv(
        OUT / f'{name}_iat_ecdf.csv', index=False
    )

    params = {
        'dataset': name,
        'distribution': 'lognormal',
        'mu_log': float(mu_log),
        'sigma_log': float(sigma_log),
        'ks_statistic': float(ks_stat),
        'ks_p_value': float(ks_p),
        'sample_count': int(len(iat)),
        'mean': float(iat.mean()),
        'median': float(np.median(iat)),
        'p95': float(np.percentile(iat, 95)),
        'p99': float(np.percentile(iat, 99)),
    }
    with open(OUT / f'{name}_iat_params.json', 'w') as f:
        json.dump(params, f, indent=2)

    results[name] = (iat, params)

# Cross-trace plot
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
colors = {
    'nasa_jul95': 'C0',
    'nasa_aug95': 'C1',
    'clarknet_aug28': 'C2',
    'clarknet_sep4': 'C3',
}
for name, (iat, params) in results.items():
    axes[0].hist(iat, bins=200, density=True, alpha=0.5,
                 label=f'{name} (μ={params["mean"]:.1f}s)',
                 color=colors.get(name))
    axes[1].hist(iat, bins=np.logspace(-1, 3.3, 200), density=True,
                 alpha=0.5, label=name, color=colors.get(name))

axes[0].set_xlim(0, 100)
axes[0].set_xlabel('IAT (sec)'); axes[0].set_ylabel('Density')
axes[0].set_title('IAT distribution (linear)'); axes[0].legend()

axes[1].set_xscale('log'); axes[1].set_yscale('log')
axes[1].set_xlabel('IAT (sec)'); axes[1].set_ylabel('Density')
axes[1].set_title('IAT distribution (log-log)'); axes[1].legend()

plt.tight_layout()
plt.savefig(OUT / 'iat_comparison.png', dpi=120)
print(f'\nSaved comparison plot: {OUT / "iat_comparison.png"}')

print('\n=== Cross-trace IAT summary ===')
print(f'{"dataset":<18} {"μ_log":>8} {"σ_log":>8} {"mean":>8} {"median":>8}')
for name, (_, p) in results.items():
    print(f'{name:<18} {p["mu_log"]:>8.3f} {p["sigma_log"]:>8.3f} '
          f'{p["mean"]:>8.2f} {p["median"]:>8.2f}')