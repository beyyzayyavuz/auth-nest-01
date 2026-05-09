"""
Tier 1: per-connection feature extraction.
RequestLog → Connection table.
"""

import psycopg2
import json
from datetime import datetime, timezone
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
print(f'  Inserted {len(records):,} Connection rows')

# ============================================================
# NGINX 408 ENRICHMENT — slowloris timeout sinyali için
# Slowloris connection'ları NestJS'e ulaşmıyor (nginx 60s'de timeout),
# bu yüzden RequestLog tabanlı extractor partial/timeout count'larını
# yakalayamıyor. Nginx access log'undan 408 status entries'i parse
# edip Connection table'a UPDATE ediyoruz.
# ============================================================

print('\nEnriching Connection table with nginx 408 timeouts...')

from datetime import datetime

NGINX_LOG = ROOT.parent / 'infra/nginx/logs/ddos_research.log'

# Her scenario'nun time range'ini al
cur.execute('SELECT id, "startedAt", "endedAt" FROM "Scenario"')
scenarios = {row[0]: (row[1], row[2]) for row in cur.fetchall()}

timeout_by_conn_scenario = {}
partial_by_scenario = {}

def find_scenario(entry_dt):
    for sid, (start, end) in scenarios.items():
        if end is None:
            continue
        if start <= entry_dt <= end:
            return sid
    return None

print(f'  Reading nginx log: {NGINX_LOG}')
parsed_408_count = 0

with open(NGINX_LOG) as f:
    for line in f:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(entry.get("status")) != "408":
            continue
        conn_id = entry.get('connection')
        ts_str = entry.get('t_recv_start', '0')
        try:
            ts = float(ts_str)
        except (ValueError, TypeError):
            continue
        if not conn_id or ts == 0:
            continue
        entry_dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
        sid = find_scenario(entry_dt)
        if not sid:
            continue
        key = (conn_id, sid)
        timeout_by_conn_scenario[key] = timeout_by_conn_scenario.get(key, 0) + 1
        partial_by_scenario[sid] = partial_by_scenario.get(sid, 0) + 1
        parsed_408_count += 1

print(f'  Parsed {parsed_408_count} 408 entries from nginx log')
print(f'  Mapped to {len(timeout_by_conn_scenario)} (connId, scenario) pairs')
print(f'  By scenario: {partial_by_scenario}')

# Connection table UPDATE veya INSERT
update_count = 0
not_found = []

for (conn_id, sid), timeout_count in timeout_by_conn_scenario.items():
    cur.execute("""
        UPDATE "Connection"
        SET "timeoutRequestCount" = "timeoutRequestCount" + %s,
            "partialRequestCount" = "partialRequestCount" + %s
        WHERE id = %s
    """, (timeout_count, timeout_count, conn_id))
    if cur.rowcount > 0:
        update_count += cur.rowcount
    else:
        not_found.append((conn_id, sid, timeout_count))

# Nginx'te var ama Connection table'da yok (slowloris connection'ları)
inserted = 0
for conn_id, sid, timeout_count in not_found:
    start, end = scenarios[sid]
    duration_ms = int((end - start).total_seconds() * 1000) if end else 60000
    try:
        cur.execute("""
            INSERT INTO "Connection"
              (id, "scenarioId", ip, "ipSubnet24", "tOpen", "tClose", "durationMs",
               "requestCount", "keepaliveUsed", "meanRequestTimeMs",
               "p95RequestTimeMs", "maxRequestTimeMs", "partialRequestCount",
               "timeoutRequestCount")
            VALUES (%s, %s, '192.168.65.1', '192.168.65.0', %s, %s, %s,
                    0, false, NULL, NULL, NULL, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (conn_id, sid, start, end, duration_ms, timeout_count, timeout_count))
        if cur.rowcount > 0:
            inserted += 1
    except Exception as e:
        print(f'  Insert failed for conn_id={conn_id}: {e}')

conn.commit()
print(f'  Updated {update_count} existing Connection rows')
print(f'  Inserted {inserted} new Connection rows for nginx-only connections')

cur.close()
conn.close()