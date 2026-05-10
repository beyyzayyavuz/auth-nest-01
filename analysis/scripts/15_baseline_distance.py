"""
Per-window:
- markov_log_likelihood: NASA-trained transition matrix'e göre window'daki
  endpoint sequence'ının log-likelihood'u
- iat_ks_distance: window IAT distribution vs NASA empirical CDF KS distance
"""

import psycopg2
import json
import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import ks_2samp

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'
BASELINES = ROOT / 'data/baselines'

WINDOW_SEC = 10

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

# Load NASA baselines
print('Loading NASA calibration baselines...')
nasa_iat_ecdf = pd.read_csv(BASELINES / 'nasa_jul95_iat_ecdf.csv')
nasa_markov = json.load(open(BASELINES / 'nasa_jul95_markov_transitions.json'))

# Endpoint kategorizasyonu (NASA Markov ile uyumlu)
def categorize_path(path):
    p = str(path).lower()
    if '/auth/' in p: return 'cgi'
    if '/user/profile' in p: return 'html'
    if '/user/search' in p: return 'cgi'
    if '/health' in p or '/ping' in p: return 'static'
    if '/metrics/' in p: return 'cgi'
    return 'other'

print('Loading RequestLog...')
req = pd.read_sql("""
    SELECT timestamp, ip, "ipSubnet24", "scenarioId", "routeTemplate"
    FROM "RequestLog" WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')
req['category'] = req['routeTemplate'].apply(categorize_path)

# NASA IAT empirical CDF as numpy array (bin midpoints + percentile values)
nasa_iat_values = nasa_iat_ecdf['iat_sec'].values

def markov_ll(seq):
    """Sequence'in NASA Markov chain altında log-likelihood'u."""
    if len(seq) < 2: return 0.0
    ll = 0.0
    for i in range(len(seq) - 1):
        from_cat = seq[i]
        to_cat = seq[i + 1]
        prob = nasa_markov.get(from_cat, {}).get(to_cat, 1e-9)
        ll += np.log(max(prob, 1e-9))
    return ll / (len(seq) - 1)  # average per transition

def iat_ks(group_iats):
    """Group IAT'lerini NASA empirical CDF'e karşı KS distance."""
    if len(group_iats) < 5: return 0.0
    return float(ks_2samp(group_iats, nasa_iat_values).statistic)

# Per (scenario, key, window) feature
results = []
for key_col in ['ip', 'ipSubnet24']:
    print(f'\nComputing baseline distances by {key_col}...')
    grouped = req.groupby([key_col, 'bucket_10s', 'scenarioId'])
    n = 0
    for (k, b, sid), g in grouped:
        seq = g['category'].tolist()
        iats = g['timestamp'].diff().dt.total_seconds().dropna().values
        results.append({
            'aggregation_type': key_col,
            'aggregation_key': str(k),
            'window_start': b,
            'scenario_id': sid,
            'markov_log_likelihood': markov_ll(seq),
            'iat_ks_distance': iat_ks(iats[(iats > 0) & (iats < 1800)]),
        })
        n += 1
        if n % 5000 == 0:
            print(f'  {n:,} groups')

dist_df = pd.DataFrame(results)
print(f'\n{len(dist_df):,} baseline-distance rows')
dist_df.to_parquet(OUT / 'tier_baseline_distance.parquet', compression='snappy')
print(f'Saved tier_baseline_distance.parquet')
conn.close()