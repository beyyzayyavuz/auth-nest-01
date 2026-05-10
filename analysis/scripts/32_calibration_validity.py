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
axes[0].set_title('IAT reference comparison — synthetic vs NASA')
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
plt.title('Endpoint popularity reference comparison — synthetic vs NASA')
plt.legend()
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(FIG / 'fig8_zipf_calibration.png')
plt.savefig(FIG / 'fig8_zipf_calibration.pdf')
plt.close()
print('Saved fig8_zipf_calibration')

conn.close()