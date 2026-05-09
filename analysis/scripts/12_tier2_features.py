"""
Per-(src_ip, 10s_window) ve per-(src_subnet_24, 10s_window) feature vektörü.

İki kaynak kullanılır:
1. RequestLog → request-level features (volume, IAT, endpoint entropy, cost,
   response time, status mix, login)
2. Connection → connection-level features (connection_count,
   partial_connection_count, timeout_connection_count, partial_ratio,
   timeout_ratio) — slowloris/slow-DoS sinyali için kritik.

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

# ============================================================
# 1. RequestLog → request-level features (mevcut mantık)
# ============================================================

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

req['bucket_1s'] = req['timestamp'].dt.floor('1s')
req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')


def shannon_entropy(values):
    if len(values) == 0:
        return 0.0
    counts = pd.Series(values).value_counts()
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def aggregate_window(group, key_col):
    """Tek bir (key, bucket) grubu üzerinde request-level feature'lar."""
    if len(group) < 2:
        return None
    iats = group['timestamp'].diff().dt.total_seconds().dropna().values
    return {
        'aggregation_type': key_col,
        'aggregation_key': group.iloc[0][key_col] if pd.notna(group.iloc[0][key_col]) else None,
        'window_start': group['bucket_10s'].iloc[0],
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
        'request_partial_ratio': float(group['partialRequest'].mean()),  # legacy, request-level (NestJS-only, slowloris yakalamaz)
        'login_present_ratio': float(group['loginPresent'].mean()),
        'scenario_id': group.iloc[0]['scenarioId'],
        'majority_label': group['trafficLabel'].mode().iloc[0] if len(group['trafficLabel'].mode()) else 'unlabeled',
    }


results = []
for key_col in ['ip', 'ipSubnet24']:
    print(f'\nAggregating RequestLog by {key_col}...')
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
print(f'\nRequestLog feature rows: {len(feats_df):,}')

# ============================================================
# 2. Connection → connection-level features (yeni)
# ============================================================

print('\nLoading Connection table...')
conn_df = pd.read_sql("""
    SELECT id, "scenarioId", ip, "ipSubnet24",
           "tOpen", "tClose", "requestCount",
           "partialRequestCount", "timeoutRequestCount"
    FROM "Connection"
    WHERE "scenarioId" IS NOT NULL
""", conn)
conn_df['tOpen'] = pd.to_datetime(conn_df['tOpen'], utc=True)
conn_df['bucket_10s'] = conn_df['tOpen'].dt.floor(f'{WINDOW_SEC}s')
print(f'  {len(conn_df):,} connection rows')


def aggregate_connections(connections, key_col):
    """
    Per-(key, bucket_10s, scenarioId) connection aggregation.
    Returns a DataFrame with connection-derived features.
    """
    grouped = connections.groupby([key_col, 'bucket_10s', 'scenarioId']).agg(
        connection_count=('id', 'count'),
        partial_connection_count=('partialRequestCount', 'sum'),
        timeout_connection_count=('timeoutRequestCount', 'sum'),
    ).reset_index()

    grouped['partial_ratio'] = (
        grouped['partial_connection_count'] / grouped['connection_count']
    ).fillna(0)
    grouped['timeout_ratio'] = (
        grouped['timeout_connection_count'] / grouped['connection_count']
    ).fillna(0)

    grouped['aggregation_type'] = key_col
    grouped = grouped.rename(columns={
        key_col: 'aggregation_key',
        'bucket_10s': 'window_start',
        'scenarioId': 'scenario_id',
    })

    return grouped[['aggregation_type', 'aggregation_key', 'window_start',
                    'scenario_id', 'connection_count',
                    'partial_connection_count', 'timeout_connection_count',
                    'partial_ratio', 'timeout_ratio']]


print('\nAggregating Connection by ip...')
conn_ip = aggregate_connections(conn_df, 'ip')
print(f'  {len(conn_ip):,} connection-aggregated rows for ip')

print('Aggregating Connection by ipSubnet24...')
conn_subnet = aggregate_connections(conn_df, 'ipSubnet24')
print(f'  {len(conn_subnet):,} connection-aggregated rows for ipSubnet24')

conn_features = pd.concat([conn_ip, conn_subnet], ignore_index=True)
# aggregation_key string olarak normalize et (RequestLog tarafıyla uyum için)
conn_features['aggregation_key'] = conn_features['aggregation_key'].astype(str)
print(f'\nTotal connection-derived rows: {len(conn_features):,}')

# ============================================================
# 3. Merge — RequestLog feats + Connection feats
# ============================================================

# feats_df'in aggregation_key'ini de string'e normalize et
feats_df['aggregation_key'] = feats_df['aggregation_key'].astype(str)
conn_features['aggregation_key'] = conn_features['aggregation_key'].astype(str)

print('\nMerging RequestLog + Connection features...')
before_count = len(feats_df)

# IMPORTANT:
# how='outer' kullanıyoruz çünkü slowloris/slow_post nginx'te 408 olarak kalıyor.
# Bu nginx-only connection'ların RequestLog tarafında karşılığı yok.
# left merge yapılırsa bu satırlar düşer ve partial_ratio yine 0 kalır.
feats_df = feats_df.merge(
    conn_features,
    on=['aggregation_type', 'aggregation_key', 'window_start', 'scenario_id'],
    how='outer',
)

print(f'  Before merge: {before_count:,} request rows; After outer merge: {len(feats_df):,} rows')

# Connection olmayan window'larda connection feature'larını 0 yap
connection_cols = [
    'connection_count',
    'partial_connection_count',
    'timeout_connection_count',
    'partial_ratio',
    'timeout_ratio',
]
for col in connection_cols:
    if col in feats_df.columns:
        feats_df[col] = feats_df[col].fillna(0)

# RequestLog karşılığı olmayan nginx-only connection window'ları için
# request-level feature'ları default değerlerle doldur.
request_numeric_defaults = {
    'request_count': 0,
    'req_rate': 0,
    'iat_mean': 0,
    'iat_std': 0,
    'iat_cv': 0,
    'iat_skew': 0,
    'iat_p95': 0,
    'endpoint_unique': 0,
    'endpoint_entropy': 0,
    'endpoint_cost_sum': 0,
    'endpoint_cost_mean': 0,
    'ua_unique': 0,
    'ua_entropy': 0,
    'mean_response_time': 0,
    'mean_db_time': 0,
    'mean_cpu_time': 0,
    'sum_db_queries': 0,
    'status_4xx_ratio': 0,
    'status_5xx_ratio': 0,
    'status_404_ratio': 0,
    'status_408_ratio': 0,
    'request_partial_ratio': 0,
    'login_present_ratio': 0,
}

for col, default in request_numeric_defaults.items():
    if col in feats_df.columns:
        feats_df[col] = feats_df[col].fillna(default)

# Connection-only satırlarda window_end boş olabilir.
# 10 saniyelik pencere kabul ederek dolduruyoruz.
if 'window_end' in feats_df.columns:
    feats_df['window_end'] = feats_df['window_end'].fillna(
        feats_df['window_start'] + pd.to_timedelta(WINDOW_SEC - 1, unit='s')
    )

# Connection-only slow HTTP satırları için label ver.
# Böylece WindowLabel tarafında da anlamsız NaN kalmaz.
if 'majority_label' in feats_df.columns:
    feats_df['majority_label'] = feats_df['majority_label'].fillna('unlabeled')

slow_mask = (
    (feats_df['partial_connection_count'] > 0) |
    (feats_df['timeout_connection_count'] > 0)
)
feats_df.loc[slow_mask, 'majority_label'] = 'slow_http'

print(f'  Final feature rows: {len(feats_df):,}')
print(f'  Connection-only / slow_http rows: {int(slow_mask.sum()):,}')

# ============================================================
# 4. WindowLabel (mevcut mantık, korundu)
# ============================================================

print('\nWriting WindowLabel...')
cur = conn.cursor()
cur.execute('TRUNCATE "WindowLabel"')

for r in feats_df.to_dict(orient='records'):
    if not r['aggregation_key']:
        continue

    label = r['majority_label']

    is_attack = (
        'flood' in label or
        'bot' in label or
        'stuffing' in label or
        'slow' in label
    )

    effective_count = int(r['request_count'])

    # Connection-only slow HTTP rows have request_count=0,
    # so use partial_connection_count as the effective attack count.
    if 'slow' in label and effective_count == 0:
        effective_count = int(r.get('partial_connection_count', 0))

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
        effective_count,
        effective_count if is_attack else 0,
        1.0 if is_attack else 0.0,
        label,
    ))

conn.commit()

# ============================================================
# 5. Save parquet
# ============================================================
# Drop invalid scenario rows introduced by non-scenario / legacy connection windows
before_drop = len(feats_df)
feats_df = feats_df[
    feats_df['scenario_id'].notna() &
    (feats_df['scenario_id'].astype(str) != 'NaN')
].copy()
print(f'Dropped {before_drop - len(feats_df):,} invalid scenario rows')
feats_df.to_parquet(OUT / 'tier2_features.parquet', compression='snappy')

print(f'\nSaved features to {OUT / "tier2_features.parquet"}')

# Özet sanity print
print('\n=== Sanity: partial_ratio and timeout_ratio by scenario ===')
sanity = feats_df.groupby('scenario_id').agg(
    n=('aggregation_key', 'count'),
    mean_partial_ratio=('partial_ratio', 'mean'),
    mean_timeout_ratio=('timeout_ratio', 'mean'),
    sum_partial_conns=('partial_connection_count', 'sum'),
    sum_timeout_conns=('timeout_connection_count', 'sum'),
).round(4)
print(sanity.to_string())

cur.close()
conn.close()
