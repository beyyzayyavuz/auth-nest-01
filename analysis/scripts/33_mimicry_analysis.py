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