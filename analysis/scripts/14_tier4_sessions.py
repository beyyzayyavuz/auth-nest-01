"""
Tier 4: Per-session features. sessionIdHash varsa (auth flow), session
düzeyinde metrikler.

[ PostgreSQL: RequestLog ]
               │
               ▼  (Filtreleme: sessionIdHash boş olmayanlar)
   [ Aktif Oturum Kayıtları ]
               │
               ▼  (Gruplama: scenarioId + sessionIdHash)
     ┌─────────┴─────────┐
     ▼                   ▼
[Zaman Bazlı]      [Davranış Bazlı]
  ├─ İstek Sayısı     ├─ Tekil Endpoint (Sayfa) Sayısı
  └─ Oturum Süresi    └─ Login İstek Sayısı
     │                   │
     └─────────┬─────────┘
               ▼
   [ Oransal Türetmeler ] 
     ├─ Oturum Hızı (requests_per_second)
     └─ Çeşitlilik Oranı (endpoints_per_request)
               │
               ▼
   [ tier4_sessions.parquet ]
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog with session info...')
req = pd.read_sql("""
    SELECT timestamp, "sessionIdHash", "scenarioId", "routeTemplate",
           "responseTimeMs", "loginPresent"
    FROM "RequestLog"
    WHERE "scenarioId" IS NOT NULL
      AND "sessionIdHash" IS NOT NULL AND "sessionIdHash" != ''
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
print(f'  {len(req):,} session-tagged requests')

session_df = req.groupby(['scenarioId', 'sessionIdHash']).agg(
    request_count=('timestamp', 'count'),
    duration_sec=('timestamp', lambda x: (x.max() - x.min()).total_seconds()),
    unique_endpoints=('routeTemplate', pd.Series.nunique),
    mean_response_time=('responseTimeMs', 'mean'),
    login_count=('loginPresent', 'sum'),
).reset_index()

session_df['endpoints_per_request'] = (
    session_df['unique_endpoints'] / session_df['request_count']
)
session_df['requests_per_second'] = session_df.apply(
    lambda r: r['request_count'] / r['duration_sec'] if r['duration_sec'] > 0 else 0,
    axis=1,
)

session_df.rename(columns={'scenarioId': 'scenario_id'}, inplace=True)

print(f'  {len(session_df):,} sessions')
session_df.to_parquet(OUT / 'tier4_sessions.parquet', compression='snappy')
print(f'Saved tier4_sessions.parquet')

# Per-window session features (per (scenario, ip, window_10s))
# session_count, session_mean_duration, session_mean_request_count
# Bu kısım Day 16 merge'ine bırakıldı.
conn.close()