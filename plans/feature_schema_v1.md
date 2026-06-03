# Feature Schema v1 — Application-Layer DDoS Behavioral Detection

**Status:** v1 draft, opinionated. Bu doküman onaylanmış değil — sonunda "Açık kararlar"
listesi var, onlar netleşmeden v2'ye geçilmemeli.

**Scope:** Legitimate vs HTTP flood vs low-slow trafiği davranışsal olarak ayırt etmek için
loglanması ve türetilmesi gereken feature seti.

**Tasarım prensipleri:**
1. Volume yerine *davranışsal şekil*. Rate tek başına feature olarak girer ama belirleyici
   olmamalı.
2. Multi-resolution. Tek pencere (örn. 60s) low-slow'u ezer; tek pencere (örn. 1s) flood'u
   görür ama low-slow'u kaçırır.
3. Multi-aggregation. Tek bir IP key'i evasion'a açıktır.
4. Label leakage'a müsamahasız. Raw UA, raw IP gibi feature'lar input'a *kesinlikle*
   girmez.
5. Calibration-anchored. Entropy, IAT, Markov gibi feature'ların *baseline'ı* gerçek bir
   dataset'ten çıkarılmalı; aksi halde "saldırı vs k6-temiz-trafik"i ayırt eden bir lab
   detector'ı olur, davranışsal detector olmaz.

---

## 0. Mimari ön-koşul (önce bu)

NestJS middleware HTTP request'i Node parse ettikten *sonra* görür. Bu, davranışsal
detection açısından şu sinyalleri **yapısal olarak** kaybetmen demek:

- TLS handshake fingerprint (JA3/JA4)
- TCP-level RTT tahmini
- Header'ın geliş süresi vs body'nin geliş süresi (slowloris/slow-POST'un *tek* gerçek
  imzası)
- Tamamlanmadan timeout olan partial request'ler (slowloris doğası)
- Connection-level metrikler: aynı connection üzerinde kaç istek geldi, idle aralıkları
  ne kadardı

Üç seçenek var:

- **(A) Reverse proxy katmanı:** nginx (veya Envoy/HAProxy) NestJS önüne. nginx
  `log_format` ile `$request_time`, `$upstream_response_time`, `$ssl_protocol`,
  `$ssl_cipher`, `$connection`, `$connection_requests`, `$bytes_received` loglanır.
  JA3 için `ngx_ssl_ja3` veya benzeri modül.
- **(B) Node HTTP server low-level instrumentation:** `http.Server` üzerinde
  `connection`, `data`, `timeout`, `clientError` event'lerini doğrudan dinleyerek
  partial state ve connection-level metrikleri yakalamak. Middleware *değil*, sunucu
  seviyesinde.
- **(C) Out-of-band pcap capture:** tcpdump → offline parse. En zengin sinyal, en yüksek
  effort.

**Tavsiye:** (A) zorunlu, (B) opsiyonel ama low-slow class'ı için faydalı. (C) tezi
gereksiz büyütür.

Eğer (A) yapmadan ilerlersen tezde "low-slow detection yapıyorum" iddiası akademik olarak
zayıftır; çünkü low-slow'un en güçlü iki sinyali (`header_recv_duration`,
`body_recv_duration`) middleware'a hiç ulaşmaz.

---

## 1. Tier 0 — Raw, per-request loglanan alanlar

### Timing (ns hassasiyeti, mümkünse)
- `t_recv_start` — ilk byte alındığı an (nginx)
- `t_headers_complete` — header'lar parse bitti
- `t_body_complete` — request body bitti
- `t_response_start` — TTFB
- `t_response_complete` — total time

### Source identification
- `src_ip`, `src_port`
- `src_subnet_24`, `src_subnet_16` — türetilir
- `asn`, `country` — MaxMind / IP2Location DB ile türetilir
- `is_via_proxy` — XFF zinciri varsa true (middleware/nginx tespit eder)

### TLS / connection (Tier A şartına bağlı)
- `tls_version`, `tls_cipher`
- `ja3_hash`, `ja4_hash`
- `conn_id` — connection unique id (nginx `$connection`)
- `conn_reuse_index` — bu connection üzerinde kaçıncı request (`$connection_requests`)
- `keep_alive_flag`

### HTTP request
- `http_version` (1.1 / 2 / 3)
- `method`
- `path_route` — NestJS matched route template (örn. `/users/:id`). Endpoint
  analizinde **bu** kullanılır, raw path değil.
- `path_raw_hash` — raw path'in hash'i (debug ve cardinality ölçmek için, model input
  *değil*)
- `query_str_len`
- `body_len_declared` (Content-Length header'dan)
- `body_len_received` (gerçekten okunan)
- `header_count`
- `header_order_hash` — header'ların geldiği sıranın hash'i. Browser'lar stable order'a
  sahiptir, bot'lar genelde farklı sıralarda gönderir.
- `ua_raw` — *sadece türetme kaynağı*, model input değil
- `ua_family` — ua-parser-js → Chrome / Firefox / curl / python-requests / k6 / Go-http /
  unknown
- `accept_set_hash`, `accept_lang_present`, `accept_enc_present`
- `referer_present`, `referer_origin_match`
- `cookie_present`, `cookie_count`, `session_cookie_present`

### Response
- `status_code`
- `resp_bytes`
- `cache_hit_flag`

### Backend cost — Tier B, NestJS interceptor + TypeORM hook gerekir
- `db_query_count`
- `db_total_time_ms`
- `cpu_time_ms` — `process.hrtime` veya `perf_hooks`
- `external_call_count` — outbound HTTP/RPC sayısı

### **Modele DOĞRUDAN feature olarak girmemesi gerekenler**
- `ua_raw` — `ua_family` türetilir, ham string atılır. Aksi halde model "k6 = attack"
  öğrenir, gerçekte hiçbir generalization yok.
- `src_ip` raw — lab IP'lerine overfit eder.
- Cookie değerleri — sadece presence/count.
- `path_raw` query string'iyle birlikte — saldırıya özgü token leak eder.

---

## 2. Tier 1 — Connection-level türev (her connection için)

- `conn_duration`
- `conn_request_count`
- `conn_idle_max`, `conn_idle_mean`
- `header_recv_duration` = `t_headers_complete − t_recv_start` — **slowloris key
  signal**
- `body_recv_duration` = `t_body_complete − t_headers_complete` — **slow-POST key
  signal**
- `inbound_byte_rate` = `bytes_received / conn_duration`
- `partial_request_flag` — connection request tamamlanmadan kapandı (slowloris
  hayatını sürdürürken kapanır veya timeout olur)
- `concurrent_conns_at_open` — bu connection açıldığında o source'tan kaç başka
  connection açıktı

---

## 3. Tier 2 — Source-windowed aggregates (modelin esas input'u)

### Aggregation key — *çift anahtar*
- per `src_ip`
- per `src_subnet_24`

İki ayrı feature row üretilir. Botnet evasion'ında /24 daha dayanıklı; NAT'lı meşru
trafikte /24 false positive yaratabilir. İkisini birden tut, model'e ayrı feature seti
ver.

### Windowing — multi-resolution sliding
- 1s slide / 1s window
- 1s slide / 10s window
- 5s slide / 60s window

Her window seviyesi için aşağıdaki tüm feature'lar ayrı suffix ile (`_w1`, `_w10`,
`_w60`).

### 3.1 Volume / rate (kontrol için, belirleyici değil)
- `req_count`
- `req_rate`
- `bytes_in_total`, `bytes_out_total`

### 3.2 Inter-arrival time (IAT)
- `iat_mean`, `iat_std`, `iat_cv` (= std/mean)
- `iat_skew`, `iat_kurt`
- `iat_p50`, `iat_p95`, `iat_p99`, `iat_min`, `iat_max`
- `burstiness_index` B = (σ − μ) / (σ + μ) — Goh & Barabasi tanımı
- `iat_ks_distance_to_baseline` — gerçek legitimate IAT dağılımına KS distance

### 3.3 Endpoint dağılımı
- `endpoint_unique_count`
- `endpoint_entropy_shannon` — **Miller-Madow correction ile** (low-sample bias)
- `endpoint_entropy_renyi_alpha2` — daha robust
- `endpoint_top1_ratio` — en sık endpoint'in oranı
- `endpoint_repeat_ratio` — ardışık aynı endpoint oranı
- `endpoint_kl_divergence_to_baseline` — gerçek legitimate dağılımına KL

### 3.4 Endpoint cost (asymmetry)
**Calibration phase'de:** her route için `mean(cpu_time_ms + db_total_time_ms)` legitimate
trafikte ölçülerek bir cost vector çıkarılır.

- `endpoint_cost_sum` — Σ cost(route) bu pencerede
- `endpoint_cost_mean`
- `endpoint_cost_to_request_ratio`
- `expensive_endpoint_ratio` — top-quartile pahalı route'a giden istek oranı

### 3.5 Behavioral consistency
- `ua_unique_count`
- `ua_entropy`
- `header_order_hash_unique_count`
- `referer_present_ratio`
- `cookie_present_ratio`
- `expected_resource_fan_out_ratio` — HTML response sonrası embedded resource isteği
  oranı (browser ~5–20, bot 0–1)

### 3.6 Status code mix
- `status_2xx_ratio`, `status_3xx_ratio`, `status_4xx_ratio`, `status_5xx_ratio`
- `status_404_ratio` — probing
- `status_429_ratio` — already-throttled

### 3.7 Connection-derived (slow-attack indicators)
- `mean_header_recv_duration`, `p95_header_recv_duration` — slowloris
- `mean_body_recv_duration`, `p95_body_recv_duration` — slow-POST
- `partial_request_ratio` — slowloris
- `mean_inbound_byte_rate` — slowloris/slow-POST düşük
- `conn_reuse_ratio` — bot'lar genelde reuse az
- `concurrent_open_conns` — slowloris yüksek tutar
- `conn_to_request_ratio` — high = aggressive new-conn pattern

### 3.8 Sequential / temporal
- `markov_log_likelihood` — `log P(observed endpoint sequence | baseline transition
  matrix)`. Baseline calibration'da legitimate trafikten çıkarılır.
- `autocorr_iat_lag1`, `autocorr_iat_lag10`
- `hurst_exponent_iat` — long-range dependence; gerçek web trafiği ~0.7–0.9
- `fft_dominant_freq_power` — periyodik low-rate saldırı imzası

---

## 4. Tier 3 — Global / cross-source (per window, sistem genelinde)

Modelin "bu source agresif mi" değil "sistem saldırı altında mı" sinyali görmesi için.

- `global_unique_src_count`
- `global_new_src_ratio` — daha önce hiç görülmemiş source oranı
- `global_top_subnet_share` — en yoğun /24'ün payı
- `global_endpoint_entropy`
- `global_concurrent_conns`
- `global_5xx_ratio` — sunucu zorlanıyor mu

---

## 5. Tier 4 — Session-level (cookie/auth varsa)

- `session_duration`
- `session_request_count`
- `session_endpoint_unique`
- `session_navigation_depth` — Markov chain'de gezilen unique state sayısı
- `session_think_time_p50` — session içi median IAT
- `session_resource_to_page_ratio`
- `session_login_present`

---

## 6. Label granularity — kararım

Per-request label gürültülüdür. Per-source-window önerim:

- Label birim: `(aggregation_key, window)` — yani `(src_ip, 10s_window)` ve
  `(src_subnet_24, 10s_window)` ayrı ayrı.
- Class: `legitimate | http_flood | low_slow`
- Mixed scenario için: tie-breaker = pencerede attacker-controlled source'tan gelen
  request oranı. Eşik %20 (bu eşik tartışmaya açık, deney öncesi sabitlenmeli).

Per-request label de loglansın (debug ve alternatif analiz için), ama ana training/eval
hedefi per-(key, window).

---

## 7. Feature computation locality

| Tier | Nerede | Ne zaman |
|---|---|---|
| 0 raw | nginx access log + NestJS middleware | online, per request |
| 0 backend cost | NestJS interceptor + TypeORM hook | online, per request |
| 1 connection | nginx connection log (`$connection`, `$connection_requests`) + opsiyonel Node low-level | online, conn close'da |
| 2 windowed | Python/Pandas (offline) veya streaming bucket (online detection latency için) | batch + streaming |
| 3 global | Python/Pandas | batch |
| 4 session | Python/Pandas | batch |
| Endpoint cost calibration | ayrı profiling run | deney öncesi |
| Markov / IAT / KL baselines | gerçek calibration dataset'i | deney öncesi |

**Online detection latency çalışacaksa:** Tier 2'nin streaming hesabı zorunlu, tumbling
1s bucket + sliding aggregator. Aksi halde "time-to-detect" metric'i raporlanamaz.

---

## 8. Açık kararlar — bunlar netleşmeden v2 yok

1. **Mimari:** Tier A reverse proxy ekleniyor mu? (Bence evet, low-slow için zorunlu.)
2. **Backend cost instrumentation:** TypeORM hook + perf_hooks kuruluyor mu yoksa endpoint
   cost'u sadece statik route profile mi olacak?
3. **Aggregation key stratejisi:** sadece `src_ip` mi, yoksa benim önerdiğim çift key
   (`src_ip` + `src_subnet_24`) mi? Çift key model boyutunu iki katına çıkarır ama
   robustness kazandırır.
4. **Window resolution:** {1s, 10s, 60s} sabitlemesi kabul mü? Daha aşağıya inmek (200ms)
   flood için faydalı olabilir ama logging overhead'i artırır.
5. **Mixed scenario tie-breaker eşiği:** %20 doğru mu? %50 mi? Bu seçim recall/precision
   trade-off'unu belirler.
6. **Calibration dataset seçimi:** Markov / IAT / endpoint baseline'ları hangi gerçek
   dataset'ten çıkarılacak? Bu karar feature setine *anchor* veriyor; aksi halde
   `*_to_baseline` feature'larının anlamı yok.
7. **Session feature'ları kullanılacak mı?** Sadece cookie/auth'lı endpoint'lerde anlamlı.
   Eğer test app'inde auth flow yoksa Tier 4 atılır.
8. **TLS fingerprint (JA3/JA4):** Tezde kapsamda mı? Eğer Tier A varsa kapsanmalı, çünkü
   k6-tabanlı saldırgan ile Chrome legitimate user'ı arasındaki en güçlü ayrım buradan
   geçer — *fakat dikkat*: bu sinyal o kadar güçlüdür ki davranışsal feature'ların
   katkısını gizleyebilir. Bilinçli olarak ablation'da ayrı tutmak gerekir.

---

## 9. Bilinçli olarak DAHİL ETMEDİĞİM şeyler

- **ML-derived embeddings** (transformer encoder'ları): erken. Önce bu feature seti
  baseline'da ne yapıyor görülmeli.
- **JS-execution / browser fingerprinting**: HTTP-level scope dışında.
- **Geo-clustering features**: source IP geo davranışsal ayırt edici olarak çok gürültülü,
  confound riski yüksek (saldırı tek lab'dan, meşru de tek lab'dan = geo trivial sinyal).
- **Higher-order delta features** (rate of change of features): 1. mertebe yetersiz
  kalırsa eklenir.

---

## 10. Sonraki adımlar

- Yukarıdaki "Açık kararlar"a yanıt al, schema'yı v2'ye çıkar.
- nginx log_format'ı ve NestJS middleware contract'ı bu schema'ya göre yaz.
- PostgreSQL şeması: Tier 0 için `requests` tablosu, Tier 1 için `connections` tablosu,
  Tier 2 hesaplaması için partition key (`src_ip`, `bucket_1s`).
- Calibration plan'ı yaz: hangi dataset, hangi parametreler, hangi distributional
  similarity testleri.
