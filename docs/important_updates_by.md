# May 9, 2026
S1–S5 verileri sağlam görünüyor; Scenario tablosunda startedAt/endedAt dolu ve RequestLog’da beklenen trafficLabel count’ları var. S6 tarafını temizledik: eski hatalı run S6_slowloris_broken, ilk slowloris-only retry S6_slowloris_slowonly, final temiz run ise tekrar S6_slowloris olarak ayrıldı; zaman aralıkları karışmıyor. Final S6’da slowloris + slow_post çalıştı; loglarda SLOW HEADERS ve SLOW BODY görünüyor, error=0, ama nginx bağlantıları yaklaşık 70 saniyede kapattığı için slowhttptest No open connections left ile erken bitti. Buna rağmen nginx 408 sayısı 3186 → 4186 oldu, yani final S6 sırasında +1000 yeni timeout kaydı oluştu.
# Scenario table sanity
beyzayavuz@Beyza-MacBook-Air auth-nest-01 % docker compose exec -T postgres psql -U research -d ddos_research -c "
SELECT id, \"startedAt\", \"endedAt\",
  EXTRACT(EPOCH FROM (\"endedAt\" - \"startedAt\"))/60 AS minutes,
  (SELECT COUNT(*) FROM \"RequestLog\" WHERE \"scenarioId\" = s.id) AS reqs
FROM \"Scenario\" s
WHERE id LIKE 'S6%'
ORDER BY \"startedAt\";"

          id           |        startedAt        |         endedAt         |       minutes       | reqs  
-----------------------+-------------------------+-------------------------+---------------------+-------
 S6_slowloris_broken   | 2026-05-09 12:29:28     | 2026-05-09 12:59:58     | 30.5000000000000000 | 37565
 S6_slowloris_slowonly | 2026-05-09 14:08:09.579 | 2026-05-09 14:38:40.293 | 30.5119000000000000 | 34427
 S6_slowloris          | 2026-05-09 15:01:35.167 | 2026-05-09 15:32:05.946 | 30.5129833333333333 | 37381
(3 rows)

beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 

# S6 RequestLog separation sanity
beyzayavuz@Beyza-MacBook-Air auth-nest-01 % docker compose exec -T postgres psql -U research -d ddos_research -c "
SELECT \"scenarioId\", \"trafficLabel\", COUNT(*) AS req_count,
       MIN(timestamp) AS first_ts,
       MAX(timestamp) AS last_ts
FROM \"RequestLog\"
WHERE \"scenarioId\" LIKE 'S6%'
GROUP BY \"scenarioId\", \"trafficLabel\"
ORDER BY \"scenarioId\", \"trafficLabel\";"
           scenarioId           | trafficLabel | req_count |        first_ts         |         last_ts         
--------------------------------+--------------+-----------+-------------------------+-------------------------
 S6_slowloris                   | normal_user  |     37381 | 2026-05-09 15:01:59.441 | 2026-05-09 15:31:05.162
 S6_slowloris_broken            | normal_user  |     37565 | 2026-05-08 19:11:07.929 | 2026-05-09 12:59:26.889
 S6_slowloris_broken_recovery   | normal_user  |      6122 | 2026-05-08 19:12:27.722 | 2026-05-09 13:02:57.462
 S6_slowloris_recovery          | normal_user  |      3415 | 2026-05-09 15:32:06.199 | 2026-05-09 15:34:34.893
 S6_slowloris_slowonly          | normal_user  |     34427 | 2026-05-09 14:08:33.867 | 2026-05-09 14:38:04.651
 S6_slowloris_slowonly_recovery | normal_user  |      5078 | 2026-05-09 14:38:40.578 | 2026-05-09 14:41:34.207
(6 rows)

beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 
# Nginx 408 count
beyzayavuz@Beyza-MacBook-Air auth-nest-01 % grep '"status":"408"' infra/nginx/logs/ddos_research.log | wc -l

    4186

# Final slowhttptest logs
eyzayavuz@Beyza-MacBook-Air auth-nest-01 % tail -50 logs/S6_slowloris_slowloris_final.log
tail -50 logs/S6_slowloris_slow_post_final.log
number of connections:            500
URL:                              http://host.docker.internal:8080/
verb:                             GET
cookie:                           
Content-Length header value:      4096
follow up data max size:          52
interval between follow up data:  10 seconds
connections per seconds:          50
probe connection timeout:         3 seconds
test duration:                    1800 seconds
using proxy:                      no proxy 

Sat May  9 15:02:42 2026:
slow HTTP test status on 65th second:

initializing:        0
pending:             0
connected:           275
error:               0
closed:              225
service available:   YES
Sat May  9 15:02:47 2026:
Sat May  9 15:02:47 2026:
        slowhttptest version 1.8.2
 - https://github.com/shekyan/slowhttptest -
test type:                        SLOW HEADERS
number of connections:            500
URL:                              http://host.docker.internal:8080/
verb:                             GET
cookie:                           
Content-Length header value:      4096
follow up data max size:          52
interval between follow up data:  10 seconds
connections per seconds:          50
probe connection timeout:         3 seconds
test duration:                    1800 seconds
using proxy:                      no proxy 

Sat May  9 15:02:47 2026:
slow HTTP test status on 70th second:

initializing:        0
pending:             0
connected:           59
error:               0
closed:              441
service available:   YES
Sat May  9 15:02:48 2026:
Test ended on 71th second
Exit status: No open connections left
number of connections:            500
URL:                              http://host.docker.internal:8080/auth/login
verb:                             POST
cookie:                           
Content-Length header value:      4096
follow up data max size:          122
interval between follow up data:  110 seconds
connections per seconds:          50
probe connection timeout:         3 seconds
test duration:                    1800 seconds
using proxy:                      no proxy 

Sat May  9 15:02:42 2026:
slow HTTP test status on 65th second:

initializing:        0
pending:             0
connected:           281
error:               0
closed:              219
service available:   YES
Sat May  9 15:02:47 2026:
Sat May  9 15:02:47 2026:
        slowhttptest version 1.8.2
 - https://github.com/shekyan/slowhttptest -
test type:                        SLOW BODY
number of connections:            500
URL:                              http://host.docker.internal:8080/auth/login
verb:                             POST
cookie:                           
Content-Length header value:      4096
follow up data max size:          122
interval between follow up data:  110 seconds
connections per seconds:          50
probe connection timeout:         3 seconds
test duration:                    1800 seconds
using proxy:                      no proxy 

Sat May  9 15:02:47 2026:
slow HTTP test status on 70th second:

initializing:        0
pending:             0
connected:           64
error:               0
closed:              436
service available:   YES
Sat May  9 15:02:48 2026:
Test ended on 71th second
Exit status: No open connections left
beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 


Day 12’de Connection tablosu doldu: 547,731 request’ten 14,154 connection row üretildi. Ama S6 connection feature’ları farklı görünmedi; partial_ratio ve timeoutRequestCount tüm senaryolarda 0. Bunun sebebi extractor’ın şu an sadece RequestLog’dan okuması gibi görünüyor; slowloris/slow_post sinyali nginx log’daki 408 kayıtlarında var ama Connection/Tier2 feature’lara henüz taşınmadı.
Day 13 endpoint cost calibration başarılı: S1’den 4 endpoint çıkarıldı; /user/profile Q1, /user/search Q2, /auth/logout Q3, /auth/login Q4 ve en pahalı endpoint çıktı. Tier2 feature script’i de çalıştı; 502,671 request’ten 12,212 feature row üretti. Endpoint entropy beklenen şekilde ayrışıyor: legit yüksek, credential stuffing ve mimicry flood düşük. Ama partial_ratio yine 0 olduğu için S6 slow HTTP sinyali Tier2’de görünmüyor.
Ek not: req_rate metriği beklenen gibi davranmıyor. Flood/mimicry senaryolarında çok yüksek beklerken S2_http_flood ortalaması S1’den düşük, S5_mimicry_flood ise S1’e yakın çıktı. Bu muhtemelen aggregation seviyesinden, IP/subnet window’larının birlikte ortalamaya katılmasından veya req_rate hesaplama formülünden kaynaklanıyor olabilir; kontrol edilmesi gerekiyor.

# Day 12 — Connection extractor
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % python analysis/scripts/10_tier1_connections.py
Loading RequestLog with connection info...
/Users/beyzayavuz/Desktop/auth-nest-01/analysis/scripts/10_tier1_connections.py:18: UserWarning: pandas only supports SQLAlchemy connectable (engine/connection) or database string URI or sqlite3 DBAPI2 connection. Other DBAPI2 objects are not tested. Please consider using SQLAlchemy.
  df = pd.read_sql("""
  Loaded 547,731 requests with connId
  Distinct connections: 14,154
  Aggregated to 14,154 connections
Writing to Connection table...
  Inserted 14,154 Connection rows
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 

# Day 12 connection sanity query
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % >....                                                               
  COUNT(*) AS n,
  AVG(\"durationMs\")::numeric(10,2) AS avg_dur_ms,
  AVG(\"requestCount\")::numeric(8,2) AS avg_req_per_conn,
  AVG(\"meanRequestTimeMs\")::numeric(10,2) AS avg_req_time,
  SUM(\"partialRequestCount\") AS total_partial,
  SUM(\"timeoutRequestCount\") AS total_timeouts
FROM \"Connection\"
WHERE \"scenarioId\" IS NOT NULL
GROUP BY \"scenarioId\"
ORDER BY \"scenarioId\";"
           scenarioId            |  n   | avg_dur_ms | avg_req_per_conn | avg_req_time | total_partial | total_timeouts 
---------------------------------+------+------------+------------------+--------------+---------------+----------------
 NaN                             | 2376 |   14342.84 |            18.96 |         3.52 |             0 |              0
 S1_legit_only                   |  223 |   14643.43 |           182.59 |        85.51 |             0 |              0
 S1_legit_only_recovery          |   28 |   14660.71 |           252.36 |        59.82 |             0 |              0
 S2_http_flood                   | 3771 |   36072.80 |            25.42 |       189.15 |             0 |              0
 S2_http_flood_recovery          |   20 |   36361.60 |           288.15 |        38.34 |             0 |              0
 S3_low_rate_bot                 |  230 |   49591.37 |           154.90 |        44.71 |             0 |              0
 S3_low_rate_bot_recovery        |   27 |   11151.52 |           129.22 |        59.13 |             0 |              0
 S4_credential_stuffing          | 1837 |   42049.87 |            36.34 |         8.80 |             0 |              0
 S4_credential_stuffing_recovery |   22 |   36911.27 |           321.36 |        56.79 |             0 |              0
 S5_mimicry_flood                | 4888 |   15723.56 |            22.64 |         5.91 |             0 |              0
 S5_mimicry_flood_recovery       |   29 |   10602.41 |           195.00 |        52.22 |             0 |              0
 S6_slowloris                    |  212 |   16868.43 |           176.33 |        80.48 |             0 |              0
 S6_slowloris_broken             |  217 |   16241.74 |           173.11 |        79.31 |             0 |              0
 S6_slowloris_broken_recovery    |   19 |   55915.16 |           322.21 |        52.48 |             0 |              0
 S6_slowloris_recovery           |   23 |   12456.39 |           148.48 |        65.24 |             0 |              0
 S6_slowloris_slowonly           |  208 |   18214.70 |           165.51 |        80.13 |             0 |              0
 S6_slowloris_slowonly_recovery  |   24 |   17626.54 |           211.58 |        55.66 |             0 |              0
(17 rows)
         
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 
# Day 13 — Endpoint cost calibration

(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % python analysis/scripts/11_endpoint_cost.py
Loading S1 RequestLog...
/Users/beyzayavuz/Desktop/auth-nest-01/analysis/scripts/11_endpoint_cost.py:16: UserWarning: pandas only supports SQLAlchemy connectable (engine/connection) or database string URI or sqlite3 DBAPI2 connection. Other DBAPI2 objects are not tested. Please consider using SQLAlchemy.
  df = pd.read_sql("""
  40,717 legit requests

Endpoint cost profile:
   routeTemplate method  sample_count  mean_db_time_ms  mean_cpu_time_ms  mean_total_cost_ms  p95_total_cost_ms  cost_quartile
0    /auth/login   POST         12657          1.61302        917.078751          918.691771          1637.2060              4
1   /auth/logout   POST          1038          0.00000          9.297082            9.297082            22.0080              3
2  /user/profile    GET          9188          0.00000          1.542354            1.542354             7.7240              1
3   /user/search    GET         17834          0.00000          5.710487            5.710487            18.4947              2

Saved 4 routes to EndpointCostProfile
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 

# EndpointCostProfile sanity
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % docker compose exec postgres psql -U research -d ddos_research -c "
SELECT * FROM \"EndpointCostProfile\" ORDER BY \"meanTotalCostMs\";"
 routeTemplate | method | sampleCount |    meanDbTimeMs    |   meanCpuTimeMs   |  meanTotalCostMs  |   p95TotalCostMs   | costQuartile | calibrationScenarioId 
---------------+--------+-------------+--------------------+-------------------+-------------------+--------------------+--------------+-----------------------
 /user/profile | GET    |        9188 |                  0 | 1.542353613408794 | 1.542353613408794 |              7.724 |            1 | S1_legit_only
 /user/search  | GET    |       17834 |                  0 | 5.710486878995178 | 5.710486878995178 | 18.494699999999998 |            2 | S1_legit_only
 /auth/logout  | POST   |        1038 |                  0 | 9.297081888246627 | 9.297081888246627 |             22.008 |            3 | S1_legit_only
 /auth/login   | POST   |       12657 | 1.6130204629849096 | 917.0787506518132 | 918.6917711147981 |           1637.206 |            4 | S1_legit_only
(4 rows) 
         
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 
# Day 13 — Tier2 feature extraction
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % python analysis/scripts/12_tier2_features.py
Loading RequestLog + EndpointCostProfile...
/Users/beyzayavuz/Desktop/auth-nest-01/analysis/scripts/12_tier2_features.py:25: UserWarning: pandas only supports SQLAlchemy connectable (engine/connection) or database string URI or sqlite3 DBAPI2 connection. Other DBAPI2 objects are not tested. Please consider using SQLAlchemy.
  req = pd.read_sql("""
  502,671 requests across 16 scenarios
/Users/beyzayavuz/Desktop/auth-nest-01/analysis/scripts/12_tier2_features.py:36: UserWarning: pandas only supports SQLAlchemy connectable (engine/connection) or database string URI or sqlite3 DBAPI2 connection. Other DBAPI2 objects are not tested. Please consider using SQLAlchemy.
  cost_profile = pd.read_sql(

Aggregating by ip...
/Users/beyzayavuz/Desktop/auth-nest-01/analysis/scripts/12_tier2_features.py:67: RuntimeWarning: Precision loss occurred in moment calculation due to catastrophic cancellation. This occurs when the data are nearly identical. Results may be unreliable.
  'iat_skew': float(skew(iats)) if len(iats) > 2 else 0,
  10,000 groups processed

Aggregating by ipSubnet24...

Total feature rows: 12,212

Writing WindowLabel...

Saved features to /Users/beyzayavuz/Desktop/auth-nest-01/analysis/data/features/tier2_features.parquet
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 

# Tier2 feature sanity by scenario
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % python -c "
import pandas as pd
df = pd.read_parquet('analysis/data/features/tier2_features.parquet')
print('--- mean by scenario ---')
print(df.groupby('scenario_id')[['req_rate', 'iat_cv', 'endpoint_entropy', 'endpoint_cost_sum', 'partial_ratio']].mean().round(3))
"
--- mean by scenario ---
                                 req_rate   iat_cv  endpoint_entropy  endpoint_cost_sum  partial_ratio
scenario_id                                                                                           
S1_legit_only                      13.616    6.997             1.620          39297.197            0.0
S1_legit_only_recovery             17.546    3.431             1.636          51848.043            0.0
S2_http_flood                       5.251   37.690             0.812          11511.573            0.0
S2_http_flood_recovery             15.782    2.383             1.569          44255.737            0.0
S3_low_rate_bot                     6.546    2.563             1.121          18116.579            0.0
S3_low_rate_bot_recovery           12.239    3.368             1.643          34708.793            0.0
S4_credential_stuffing              4.503    1.832             0.240          34980.348            0.0
S4_credential_stuffing_recovery    15.193    6.803             1.625          43477.623            0.0
S5_mimicry_flood                   13.703   37.927             0.221           5111.217            0.0
S5_mimicry_flood_recovery          17.342   15.514             1.615          48844.458            0.0
S6_slowloris                       13.161   13.850             1.621          37685.642            0.0
S6_slowloris_broken                12.844  140.505             1.616          37002.565            0.0
S6_slowloris_broken_recovery       13.453    1.690             1.595          38798.847            0.0
S6_slowloris_recovery              12.648    1.839             1.620          37030.646            0.0
S6_slowloris_slowonly              12.229   60.913             1.612          34864.550            0.0
S6_slowloris_slowonly_recovery     14.719    3.216             1.621          42794.745            0.0
(venv) beyzayavuz@Beyza-MacBook-Air auth-nest-01 % 

## Akılda bir şüphe:
Bir şey fark ettim: backend’de /health ve /ping endpointleri varmış ama EndpointCostProfile tablosunda çıkmadılar. Kontrol ettim, k6 senaryolarında gerçek /health veya /ping isteği yok; grep çıktısındaki “ping” sadece ramping kelimesinden geliyor. Bu yüzden S1 legitimate traffic içinde /health ve /ping çağrılmamış, dolayısıyla RequestLog’a ve cost calibration’a girmemişler. Sence bu sorun olur mu, yoksa mevcut 4 endpoint (/auth/login, /auth/logout, /user/profile, /user/search) controlled experimental API için yeterli mi?


Bu açıklamalara cevap verilmesinden sonra duruma göre Day 13.3'e başlayacağım.

## Day 12–13 Fix Note: Nginx 408 → Connection/Tier2 Feature Enrichment
# Problem
S6_slowloris final run sırasında slowloris ve slow_post çalıştı ve nginx tarafında HTTP 408 timeout kayıtları oluştu. Nginx 408 count değeri final S6 sırasında 3186 → 4186 oldu, yani +1000 yeni timeout kaydı üretildi.
Ancak ilk başta Connection ve Tier2 feature çıktılarında partialRequestCount, timeoutRequestCount, partial_ratio ve timeout_ratio değerleri 0 görünüyordu.
Bunun sebebi, slowloris / slow_post bağlantılarının NestJS middleware’e ulaşmadan nginx seviyesinde timeout olmasıydı. Yani bu kayıtlar RequestLog tablosuna düşmüyor, sadece infra/nginx/logs/ddos_research.log içinde status=408 olarak görünüyordu.
Fix 1 — 10_tier1_connections.py içine nginx enrichment eklendi
10_tier1_connections.py başlangıçta sadece RequestLog → Connection akışıyla çalışıyordu. Bu yüzden nginx-only slow HTTP timeout connection’larını göremiyordu.
Düzeltme olarak Connection tablosu doldurulduktan sonra nginx access log parser eklendi. Yeni akış şu hale geldi:
RequestLog → normal Connection rows
nginx access log status=408 → nginx-only timeout Connection rows
Nginx logdan status, connection, t_recv_start, request_time ve remote_addr alanları kullanıldı.
Nginx logda status alanı string olarak geldiği için kontrol şu şekilde yapıldı:
if str(entry.get("status")) != "408":
    continue
İlk denemede datetime.fromtimestamp(ts) local timezone ürettiği için nginx kayıtları scenario time window’larına eşleşmedi. Bu nedenle timezone dönüşümü şu şekilde düzeltildi:
entry_dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
Bu düzeltmeden sonra nginx 408 kayıtları doğru scenario zaman aralıklarına map edildi.
Başarılı çıktı:
Parsed 1500 408 entries from nginx log
Mapped to 1500 (connId, scenario) pairs
By scenario: {'S6_slowloris_slowonly': 500, 'S6_slowloris': 1000}
Updated 0 existing Connection rows
Inserted 1500 new Connection rows for nginx-only connections
Updated 0 normaldir. Çünkü slowloris / slow_post connection’ları NestJS’e ulaşmadığı için RequestLog kaynaklı Connection satırları yoktu. Bu nedenle yeni nginx-only Connection row’ları insert edildi.
Connection sanity sonucu:
S6_slowloris                   conns=1212  total_timeouts=1000  total_partial=1000
S6_slowloris_slowonly          conns=708   total_timeouts=500   total_partial=500
S6_slowloris_broken            total_timeouts=0                 total_partial=0
S6_slowloris_recovery          total_timeouts=0                 total_partial=0
S6_slowloris_slowonly_recovery total_timeouts=0                 total_partial=0
Final S6’da 1000 nginx timeout/partial connection yakalandı. Slowonly retry’de 500 timeout/partial connection yakalandı. Broken ve recovery senaryolarında timeout yok. Bu beklenen ve doğru bir sonuçtur.
Fix 2 — 12_tier2_features.py içine Connection table entegrasyonu eklendi
Önceki 12_tier2_features.py sadece RequestLog + EndpointCostProfile kaynaklarını okuyordu. Bu yüzden nginx kaynaklı slowloris / slow_post 408 timeout kayıtları Tier2 feature’lara yansımıyordu.
Eski scriptte partial_ratio şu şekilde hesaplanıyordu:
'partial_ratio': float(group['partialRequest'].mean())
Bu sadece RequestLog içindeki partialRequest değerini kullanıyordu. Slow HTTP bağlantıları RequestLog içine düşmediği için S6’da bile partial_ratio = 0 çıkıyordu.
Düzeltme olarak script’e üçüncü veri kaynağı olarak Connection tablosu eklendi. Yeni kaynak akışı şu hale geldi:
RequestLog → request-level features
EndpointCostProfile → endpoint cost features
Connection → connection-level partial/timeout features
Connection tablosundan şu alanlar okunmaya başlandı:
SELECT id, "scenarioId", ip, "ipSubnet24",
       "tOpen", "tClose", "requestCount",
       "partialRequestCount", "timeoutRequestCount"
FROM "Connection"
WHERE "scenarioId" IS NOT NULL
Connection kayıtları da aynı 10 saniyelik window mantığına göre bucketlandı:
conn_df['tOpen'] = pd.to_datetime(conn_df['tOpen'], utc=True)
conn_df['bucket_10s'] = conn_df['tOpen'].dt.floor(f'{WINDOW_SEC}s')
Sonra şu connection-level feature’lar üretildi:
connection_count
partial_connection_count
timeout_connection_count
partial_ratio
timeout_ratio
İlk denemede Connection feature’ları RequestLog feature’larına left merge ile eklenmişti:
how='left'
Bu hatalıydı. Çünkü nginx-only slowloris/slow_post connection’larının RequestLog tarafında karşılığı yoktu. Bu nedenle bu satırlar merge sırasında düşüyor ve partial_ratio yine 0 kalıyordu.
Düzeltme olarak merge tipi outer yapıldı:
how='outer'
Böylece RequestLog’da karşılığı olmayan nginx-only connection window’ları da feature tablosuna dahil edildi.
Outer merge sonrası sadece Connection’dan gelen satırlarda request-level feature’lar boş kalıyordu. Bu connection-only satırlarda request_count, req_rate, iat_*, endpoint_*, ua_*, mean_response_time, status_*, login_present_ratio gibi request-level feature’lar 0 ile dolduruldu. Yani nginx-only slow HTTP satırlarında request-level değerler 0, connection-level değerler ise dolu oldu.
Connection-only slow HTTP satırlarının label’ı boş kalmasın diye şu mantık eklendi:
slow_mask = (
    (feats_df['partial_connection_count'] > 0) |
    (feats_df['timeout_connection_count'] > 0)
)

feats_df.loc[slow_mask, 'majority_label'] = 'slow_http'
Ayrıca WindowLabel yazarken slow içeren label’lar attack kabul edildi:
is_attack = (
    'flood' in label or
    'bot' in label or
    'stuffing' in label or
    'slow' in label
)
Tier2 result after fix
12_tier2_features.py tekrar çalıştırıldı.
Başarılı çıktı:
RequestLog feature rows: 12,212
Connection rows: 15,654
Total connection-derived rows: 6,838
Before merge: 12,212 request rows
After outer merge: 12,804 rows
Connection-only / slow_http rows: 4
Saved features to tier2_features.parquet
Sanity sonucu:
S6_slowloris          sum_partial_conns=2000  sum_timeout_conns=2000
S6_slowloris_slowonly sum_partial_conns=1000  sum_timeout_conns=1000
S1-S5                 sum_partial_conns=0     sum_timeout_conns=0
Bu sayıların iki kat görünmesi normaldir. Çünkü Tier2 iki aggregation seviyesi üretmektedir:
ip
ipSubnet24
Bu yüzden final S6’daki 1000 timeout şu şekilde temsil edilir:
S6_slowloris / ip         = 1000
S6_slowloris / ipSubnet24 = 1000
Aynı şekilde slowonly retry’deki 500 timeout şu şekilde temsil edilir:
S6_slowloris_slowonly / ip         = 500
S6_slowloris_slowonly / ipSubnet24 = 500
Bu çift sayım olarak yorumlanmamalıdır. Aynı sinyal iki farklı aggregation seviyesinde temsil edilmektedir.
Final aggregation-type sanity:
S6_slowloris / ip          partial=1000  timeout=1000
S6_slowloris / ipSubnet24  partial=1000  timeout=1000

S6_slowloris_slowonly / ip          partial=500  timeout=500
S6_slowloris_slowonly / ipSubnet24  partial=500  timeout=500

S1-S5 partial/timeout = 0
Daha detaylı çıktı:
S6_slowloris                    ip          partial_connection_count=1000.0  timeout_ratio=0.0020
S6_slowloris                    ipSubnet24  partial_connection_count=1000.0  timeout_ratio=0.0147

S6_slowloris_slowonly           ip          partial_connection_count=500.0   timeout_ratio=0.0020
S6_slowloris_slowonly           ipSubnet24  partial_connection_count=500.0   timeout_ratio=0.0132
Final interpretation
Bu düzeltmelerden sonra slow HTTP sinyali artık pipeline’a taşınmıştır:
nginx 408 logs → Connection table → Tier2 features
Final durum:
S1–S5 senaryolarında partial/timeout feature’ları 0 kaldı. S6_slowloris ve S6_slowloris_slowonly senaryolarında partial/timeout feature’ları 0’dan büyük hale geldi. Bu, slowloris/slow_post sinyalinin artık Tier1 ve Tier2 feature pipeline içinde temsil edildiğini gösterir.
Diğer senaryolarda partial/timeout değerlerinin 0 olması sorun değildir. Çünkü S1–S5 nginx-level incomplete/timeout connection üretmeyen k6 tabanlı senaryolardır. Partial/timeout sinyalinin yalnızca S6’da görünmesi beklenen davranıştır.

Last Update Note: Tier2 WindowLabel ve NaN Scenario Cleanup
Problem 1 — scenario_id içinde string NaN satırları vardı
Son kontrolde 12_tier2_features.py çalıştıktan sonra tier2_features.parquet içinde scenario_id alanında string "NaN" gibi görünen 385 geçersiz satır olduğu fark edildi.
Bu satırlarda:
partial_connection_count = 0
timeout_connection_count = 0
olduğu için S6 slow HTTP sinyalini bozmuyordu. Ancak dataset temizliği için bu satırların kaldırılması gerekiyordu.
Fix 1 — Geçersiz scenario satırları temizlendi
12_tier2_features.py içinde parquet kaydetmeden hemen önce şu temizlik eklendi:
# Drop invalid scenario rows introduced by non-scenario / legacy connection windows
before_drop = len(feats_df)
feats_df = feats_df[
    feats_df['scenario_id'].notna() &
    (feats_df['scenario_id'].astype(str) != 'NaN')
].copy()
print(f'Dropped {before_drop - len(feats_df):,} invalid scenario rows')
Script tekrar çalıştırıldığında şu çıktı alındı:
Dropped 385 invalid scenario rows
Saved features to analysis/data/features/tier2_features.parquet
Sonrasında parquet dosyası kontrol edildi:
Total rows: 12419
String NaN rows: 0
Real NaN rows: 0
Bu sonuçla tier2_features.parquet içindeki geçersiz scenario satırları temizlenmiş oldu.
Problem 2 — slow_http label vardı ama requestCountAttack = 0 görünüyordu
WindowLabel tarafında slow_http label’ı oluşmasına rağmen requestCountAttack değeri ilk başta 0 görünüyordu.
Bunun nedeni, slow_http satırlarının connection-only satırlar olmasıydı. Bu satırlar nginx 408 timeout kayıtlarından geldiği için RequestLog karşılığı yoktu ve bu yüzden:
request_count = 0
kalıyordu.
Fix 2 — slow_http için effective attack count eklendi
WindowLabel yazımında connection-only slow HTTP satırları için partial_connection_count değeri effective attack count olarak kullanılacak şekilde düzenleme yapıldı:
effective_count = int(r['request_count'])

# Connection-only slow HTTP rows have request_count=0,
# so use partial_connection_count as the effective attack count.
if 'slow' in label and effective_count == 0:
    effective_count = int(r.get('partial_connection_count', 0))
Insert sırasında artık requestCountTotal ve requestCountAttack için effective_count kullanıldı:
effective_count,
effective_count if is_attack else 0,
1.0 if is_attack else 0.0,
label
Script tekrar çalıştırıldıktan sonra WindowLabel kontrolünde şu sonuç alındı:
S6_slowloris          | slow_http | n=2 | attack_req_sum=2000 | avg_attack_ratio=1.0000
S6_slowloris_slowonly | slow_http | n=2 | attack_req_sum=1000 | avg_attack_ratio=1.0000
Buradaki 2000 ve 1000 değerleri iki kat görünüyor çünkü Tier2 feature’lar iki aggregation seviyesinde üretiliyor:
1. ip
2. ipSubnet24
Yani final S6’daki 1000 nginx timeout hem ip seviyesinde hem de ipSubnet24 seviyesinde temsil ediliyor. Bu çift sayım hatası değildir; aynı slow HTTP sinyalinin iki farklı aggregation seviyesinde gösterilmesidir.
Final durum
Bu güncellemeden sonra:
NaN / geçersiz scenario satırları temizlendi.
slow_http label’ı WindowLabel tablosuna doğru yazılıyor.
slow_http için attackRatio = 1.0.
slow_http için requestCountAttack artık 0 değil.
S1–S5 tarafında partial/timeout değerleri 0 kalmaya devam ediyor.
S6_slowloris ve S6_slowloris_slowonly tarafında partial/timeout sinyali doğru şekilde görünüyor.
Sonuç olarak WindowLabel ve tier2_features.parquet çıktıları slow HTTP sinyalini doğru şekilde temsil eder hale geldi.