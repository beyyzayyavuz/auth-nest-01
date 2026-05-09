"""
Per-(src_ip, 10s_window) ve per-(src_subnet_24, 10s_window) feature vektörü.
Output: parquet (Pandas-bound, DB'ye gerek yok şu aşamada).
"""

import psycopg2
import pandas as pd
import numpy as np
from pathlib import Path
from scipy.stats import skew, kurtosis

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'
OUT.mkdir(parents=True, exist_ok=True)

WINDOW_SEC = 10
SLIDE_SEC = 1

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog + EndpointCostProfile...')
req = pd.read_sql("""
    SELECT id, timestamp, ip, "ipSubnet24", "routeTemplate",
           "responseTimeMs", "dbQueryCount", "dbTotalTimeMs", "cpuTimeMs",
           "statusCode", "uaFamily", "loginPresent", "scenarioId",
           "trafficLabel", "partialRequest"
    FROM "RequestLog"
    WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
print(f'  {len(req):,} requests across {req["scenarioId"].nunique()} scenarios')

cost_profile = pd.read_sql(
    'SELECT "routeTemplate", "meanTotalCostMs" FROM "EndpointCostProfile"',
    conn
).set_index('routeTemplate')['meanTotalCostMs'].to_dict()

req['endpoint_cost'] = req['routeTemplate'].map(cost_profile).fillna(0)

# Time bucketing — 1s slide, 10s window. Pandas için tumbling 1s + rolling
req['bucket_1s'] = req['timestamp'].dt.floor('1s')

def shannon_entropy(values):
    if len(values) == 0: return 0.0
    counts = pd.Series(values).value_counts()
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())

def aggregate_window(group, key_col):
    """Tek bir (key, bucket) grubu üzerinde feature'lar."""
    if len(group) < 2:
        return None
    iats = group['timestamp'].diff().dt.total_seconds().dropna().values
    return {
        'aggregation_type': key_col,
        'aggregation_key': group.iloc[0][key_col] if pd.notna(group.iloc[0][key_col]) else None,
        'window_start': group['bucket_1s'].min(),
        'window_end': group['bucket_1s'].max(),
        'request_count': len(group),
        'req_rate': len(group) / WINDOW_SEC,
        'iat_mean': float(np.mean(iats)) if len(iats) else 0,
        'iat_std': float(np.std(iats)) if len(iats) else 0,
        'iat_cv': float(np.std(iats) / np.mean(iats)) if len(iats) and np.mean(iats) > 0 else 0,
        'iat_skew': float(skew(iats)) if len(iats) > 2 else 0,
        'iat_p95': float(np.percentile(iats, 95)) if len(iats) else 0,
        'endpoint_unique': group['routeTemplate'].nunique(),
        'endpoint_entropy': shannon_entropy(group['routeTemplate']),
        'endpoint_cost_sum': float(group['endpoint_cost'].sum()),
        'endpoint_cost_mean': float(group['endpoint_cost'].mean()),
        'ua_unique': group['uaFamily'].nunique(),
        'ua_entropy': shannon_entropy(group['uaFamily']),
        'mean_response_time': float(group['responseTimeMs'].mean()),
        'mean_db_time': float(group['dbTotalTimeMs'].mean()),
        'mean_cpu_time': float(group['cpuTimeMs'].mean()),
        'sum_db_queries': int(group['dbQueryCount'].sum()),
        'status_4xx_ratio': float((group['statusCode'].between(400, 499)).mean()),
        'status_5xx_ratio': float((group['statusCode'].between(500, 599)).mean()),
        'status_404_ratio': float((group['statusCode'] == 404).mean()),
        'status_408_ratio': float((group['statusCode'] == 408).mean()),
        'partial_ratio': float(group['partialRequest'].mean()),
        'login_present_ratio': float(group['loginPresent'].mean()),
        'scenario_id': group.iloc[0]['scenarioId'],
        'majority_label': group['trafficLabel'].mode().iloc[0] if len(group['trafficLabel'].mode()) else 'unlabeled',
    }

results = []
for key_col in ['ip', 'ipSubnet24']:
    print(f'\nAggregating by {key_col}...')
    # Per (key, bucket_1s) — sonra rolling 10s window
    # Basitleştirme: bucket_10s tumbling (sliding değil) v1'de
    req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')
    grouped = req.groupby([key_col, 'bucket_10s'])
    n = 0
    for (k, b), g in grouped:
        feat = aggregate_window(g, key_col)
        if feat:
            results.append(feat)
        n += 1
        if n % 10000 == 0:
            print(f'  {n:,} groups processed')

feats_df = pd.DataFrame(results)
print(f'\nTotal feature rows: {len(feats_df):,}')

# WindowLabel ground truth
print('\nWriting WindowLabel...')
cur = conn.cursor()
cur.execute('TRUNCATE "WindowLabel"')

for r in feats_df.to_dict(orient='records'):
    if not r['aggregation_key']:
        continue
    # tie-breaker: 80%+ legit ise legitimate, ≥20% attack ise dominant attack class
    label = r['majority_label']
    cur.execute("""
        INSERT INTO "WindowLabel"
          ("scenarioId", "aggregationType", "aggregationKey",
           "windowStart", "windowEnd",
           "requestCountTotal", "requestCountAttack",
           "attackRatio", label)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT DO NOTHING
    """, (
        r['scenario_id'], r['aggregation_type'], str(r['aggregation_key']),
        r['window_start'], r['window_end'],
        int(r['request_count']),
        int(r['request_count']) if 'flood' in label or 'bot' in label or 'stuffing' in label else 0,
        1.0 if ('flood' in label or 'bot' in label or 'stuffing' in label) else 0.0,
        label,
    ))

conn.commit()

# Tier 2 features parquet
feats_df.to_parquet(OUT / 'tier2_features.parquet', compression='snappy')
print(f'\nSaved features to {OUT / "tier2_features.parquet"}')

cur.close()
conn.close()