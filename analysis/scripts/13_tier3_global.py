"""
Tier 3: Sistem geneli (per-window, all sources aggregated) feature'lar.
Per-window: tüm scenario boyunca o 10s window'da neler oldu sistem genelinde.

[ PostgreSQL: RequestLog ]
           │
           ▼
[ Veri Yükleme & Zaman Kovalama ] -> Zaman damgaları 10'ar saniyelik bloklara yuvarlanır (bucket_10s).
           │
           ▼
[ Gruplama (Group By) ] ----------> (scenarioId, bucket_10s) bazında gruplar oluşturulur.
           │
           ├──> Tekil IP / Subnet Sayımı (nunique)
           └──> Toplam İstek Sayımı (count) & RPS Hesaplama
           │
           ▼
[ State Durum Döngüsü (For) ] ----> Her pencere için: "Bu IP'ler daha önce geldi mi?" kontrolü.
           │                        └─> global_new_src_ratio hesaplanır.
           ▼
[ Çıktı Katmanı ] ────────────────> tier3_global.parquet olarak diske yazılır.
"""

import psycopg2
import pandas as pd
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'data/features'

WINDOW_SEC = 10

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading RequestLog for Tier 3 global aggregation...')
req = pd.read_sql("""
    SELECT timestamp, ip, "ipSubnet24", "scenarioId", "trafficLabel"
    FROM "RequestLog" WHERE "scenarioId" IS NOT NULL
""", conn)
req['timestamp'] = pd.to_datetime(req['timestamp'], utc=True)
req['bucket_10s'] = req['timestamp'].dt.floor(f'{WINDOW_SEC}s')

print(f'  {len(req):,} requests')

# Per-window global aggregates
global_df = req.groupby(['scenarioId', 'bucket_10s']).agg(
    global_unique_ip=('ip', pd.Series.nunique),
    global_unique_subnet=('ipSubnet24', pd.Series.nunique),
    global_request_count=('timestamp', 'count'),
).reset_index()

global_df['global_req_rate'] = global_df['global_request_count'] / WINDOW_SEC
global_df.rename(columns={
    'scenarioId': 'scenario_id',
    'bucket_10s': 'window_start',
}, inplace=True)

# new_src_ratio: window'daki source'ların ne kadarı previously unseen
# (önceki window'a göre yeni IP)
print('Computing new_src_ratio...')
seen_ips = {}  # scenario_id → set of seen IPs
new_src = []
for _, row in global_df.iterrows():
    sid = row['scenario_id']
    ts = row['window_start']
    if sid not in seen_ips:
        seen_ips[sid] = set()
    # Bu window'daki IP'leri al
    window_ips = set(req[
        (req['scenarioId'] == sid) & (req['bucket_10s'] == ts)
    ]['ip'].unique())
    new_count = len(window_ips - seen_ips[sid])
    total_count = len(window_ips)
    new_src.append(new_count / total_count if total_count > 0 else 0)
    seen_ips[sid] |= window_ips

global_df['global_new_src_ratio'] = new_src

print(f'  {len(global_df):,} (scenario, window) global feature rows')
global_df.to_parquet(OUT / 'tier3_global.parquet', compression='snappy')
print(f'Saved tier3_global.parquet')
conn.close()