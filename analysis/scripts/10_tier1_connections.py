"""
Tier 1: per-connection feature extraction.
RequestLog → Connection table.
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog with connection info...')
df = pd.read_sql("""
    SELECT id, "connId", "connRequestIndex",
           ip, "ipSubnet24", "scenarioId",
           timestamp, "responseTimeMs", "statusCode", "partialRequest"
    FROM "RequestLog"
    WHERE "connId" IS NOT NULL
""", conn)

print(f'  Loaded {len(df):,} requests with connId')
print(f'  Distinct connections: {df["connId"].nunique():,}')

# Per-connection aggregation
agg = df.groupby('connId').agg(
    scenarioId=('scenarioId', 'first'),
    ip=('ip', 'first'),
    ipSubnet24=('ipSubnet24', 'first'),
    tOpen=('timestamp', 'min'),
    tClose=('timestamp', 'max'),
    request_count=('id', 'count'),
    mean_request_time_ms=('responseTimeMs', 'mean'),
    p95_request_time_ms=('responseTimeMs', lambda x: x.quantile(0.95)),
    max_request_time_ms=('responseTimeMs', 'max'),
    partial_request_count=('partialRequest', 'sum'),
    timeout_request_count=('statusCode', lambda x: (x == 408).sum()),
).reset_index()

agg['durationMs'] = (agg['tClose'] - agg['tOpen']).dt.total_seconds() * 1000
agg['keepaliveUsed'] = agg['request_count'] > 1

print(f'  Aggregated to {len(agg):,} connections')

# Connection table'a yaz
print('Writing to Connection table...')
cur = conn.cursor()
cur.execute('TRUNCATE "Connection"')

records = agg.to_dict(orient='records')
batch_sql = """
INSERT INTO "Connection"
  (id, "scenarioId", ip, "ipSubnet24", "tOpen", "tClose", "durationMs",
   "requestCount", "keepaliveUsed", "meanRequestTimeMs",
   "p95RequestTimeMs", "maxRequestTimeMs", "partialRequestCount",
   "timeoutRequestCount")
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
"""
for r in records:
    cur.execute(batch_sql, (
        r['connId'], r['scenarioId'], r['ip'], r['ipSubnet24'],
        r['tOpen'], r['tClose'], int(r['durationMs']) if pd.notna(r['durationMs']) else None,
        int(r['request_count']),
        bool(r['keepaliveUsed']),
        float(r['mean_request_time_ms']) if pd.notna(r['mean_request_time_ms']) else None,
        float(r['p95_request_time_ms']) if pd.notna(r['p95_request_time_ms']) else None,
        float(r['max_request_time_ms']) if pd.notna(r['max_request_time_ms']) else None,
        int(r['partial_request_count']),
        int(r['timeout_request_count']),
    ))

conn.commit()
cur.close()
conn.close()
print(f'  Inserted {len(records):,} Connection rows')