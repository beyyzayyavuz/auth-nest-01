"""
Per-session endpoint kategori Markov chain — 4 dataset cross-trace.
"""

import json
import re
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ['nasa_jul95', 'nasa_aug95', 'clarknet_aug28', 'clarknet_sep4']
PARSED = ROOT / 'data/parsed'
OUT = ROOT / 'data/baselines'

def categorize_path(path):
    p = str(path).lower()
    if p.endswith('.html') or p.endswith('.htm') or p == '/' or '/index' in p:
        return 'html'
    if re.search(r'\.(jpg|jpeg|gif|png|bmp|svg|ico)$', p):
        return 'image'
    if re.search(r'\.(css|js)$', p):
        return 'static'
    if '/cgi-bin/' in p or p.endswith('.cgi') or p.endswith('.pl'):
        return 'cgi'
    if re.search(r'\.(mpg|mpeg|avi|mov)$', p):
        return 'video'
    return 'other'

results = {}

for name in DATASETS:
    in_path = PARSED / f'{name}_with_sessions.parquet'
    if not in_path.exists():
        continue

    print(f'\n=== Markov: {name} ===')
    df = pd.read_parquet(in_path)
    df['category'] = df.path.apply(categorize_path)

    print(f'  Category distribution:')
    print(df.category.value_counts().to_string())

    df = df.sort_values(['session_id', 'timestamp'])
    df['next_category'] = df.groupby('session_id')['category'].shift(-1)
    df['is_session_end'] = df.next_category.isna()

    trans = df[~df.is_session_end].groupby(
        ['category', 'next_category']
    ).size().unstack(fill_value=0)
    trans_norm = trans.div(trans.sum(axis=1), axis=0)

    exit_prob = df.groupby('category')['is_session_end'].mean()
    trans_norm['exit'] = exit_prob
    trans_norm = trans_norm.div(trans_norm.sum(axis=1), axis=0)

    print('\n  Transition matrix (with exit):')
    print(trans_norm.round(3))

    matrix_dict = {cat: row.to_dict() for cat, row in trans_norm.iterrows()}
    with open(OUT / f'{name}_markov_transitions.json', 'w') as f:
        json.dump(matrix_dict, f, indent=2)

    initial = df.groupby('session_id').first().category.value_counts(normalize=True)
    with open(OUT / f'{name}_markov_initial.json', 'w') as f:
        json.dump(initial.to_dict(), f, indent=2)

    results[name] = trans_norm

# Cross-trace transition diff
if len(results) >= 2:
    names = list(results.keys())
    print('\n=== Pairwise |diff| max values ===')
    print(f'{"pair":<40} {"max_diff":>10} {"mean_diff":>10}')
    for i in range(len(names)):
        for j in range(i+1, len(names)):
            a, b = results[names[i]], results[names[j]]
            common_states = a.index.intersection(b.index)
            common_cols = a.columns.intersection(b.columns)
            diff = (a.loc[common_states, common_cols] -
                    b.loc[common_states, common_cols]).abs()
            pair = f'{names[i]} vs {names[j]}'
            print(f'{pair:<40} {diff.values.max():>10.3f} {diff.values.mean():>10.3f}')