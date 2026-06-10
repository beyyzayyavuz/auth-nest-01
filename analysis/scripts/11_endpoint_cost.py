"""
S1 (legitimate-only) trafiğinden her route için mean backend cost çıkar.
EndpointCostProfile tablosuna yaz.

1. Connection: Connects to 'ddos_research' database via psycopg2.
2. Extraction: Pulls baseline traffic logs where scenarioId is 'S1_legit_only'.
3. Feature Engineering: Combines DB and CPU times to compute 'totalCost'.
4. Aggregation: Groups by endpoint/method to find means and 95th percentiles.
5. Binning: Segments endpoints into 4 cost quartiles (1=cheapest, 4=most expensive).
6. Persistence: Truncates 'EndpointCostProfile' and populates it with new results.
"""

import psycopg2
import pandas as pd
from pathlib import Path

conn = psycopg2.connect(
    host='localhost', port=5432, user='research', password='research',
    database='ddos_research',
)

print('Loading S1 RequestLog...')
df = pd.read_sql("""
    SELECT "routeTemplate", method,
           "dbTotalTimeMs", "cpuTimeMs", "responseTimeMs"
    FROM "RequestLog"
    WHERE "scenarioId" = 'S1_legit_only'
""", conn)

print(f'  {len(df):,} legit requests')

df['totalCost'] = df['dbTotalTimeMs'] + df['cpuTimeMs']

agg = df.groupby(['routeTemplate', 'method']).agg(
    sample_count=('totalCost', 'count'),
    mean_db_time_ms=('dbTotalTimeMs', 'mean'),
    mean_cpu_time_ms=('cpuTimeMs', 'mean'),
    mean_total_cost_ms=('totalCost', 'mean'),
    p95_total_cost_ms=('totalCost', lambda x: x.quantile(0.95)),
).reset_index()

# Cost quartile (1=cheapest, 4=most expensive)
agg['cost_quartile'] = pd.qcut(agg['mean_total_cost_ms'], 4, labels=[1, 2, 3, 4]).astype(int)

print('\nEndpoint cost profile:')
print(agg.to_string())

cur = conn.cursor()
cur.execute('TRUNCATE "EndpointCostProfile"')
for r in agg.to_dict(orient='records'):
    cur.execute("""
        INSERT INTO "EndpointCostProfile"
          ("routeTemplate", method, "sampleCount", "meanDbTimeMs", "meanCpuTimeMs",
           "meanTotalCostMs", "p95TotalCostMs", "costQuartile", "calibrationScenarioId")
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        r['routeTemplate'], r['method'], int(r['sample_count']),
        float(r['mean_db_time_ms']), float(r['mean_cpu_time_ms']),
        float(r['mean_total_cost_ms']), float(r['p95_total_cost_ms']),
        int(r['cost_quartile']), 'S1_legit_only',
    ))

conn.commit()
cur.close()
conn.close()
print(f'\nSaved {len(agg)} routes to EndpointCostProfile')