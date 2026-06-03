# 4-Week Project Plan — Application-Layer DDoS Behavioral Detection

**Revision:** v2 — k6 critique sonrası güncellendi.

**Bant genişliği varsayımı:** 6 gün/hafta × ~10 saat/gün = ~60 saat/hafta brüt,
debugging ve dead-time düşülünce ~45 saat/hafta efektif. 4 hafta = ~180 saat efektif.
**Marj:** sıfır. Her hafta sonunda checkpoint var; bir hafta kayarsa kapsam küçültülür.

---

## Onaylanmış kararlar

1. **Mimari:** nginx + NestJS (middleware-only değil)
2. **Backend cost:** Dynamic instrumentation (Prisma `$on('query')` + `process.cpuUsage`)
3. **Aggregation key:** `src_ip` + `src_subnet_24` (tek model, çift feature seti)
4. **Calibration dataset:** NASA HTTP Logs (primary) + benzer setler destek;
   CIC-DDoS2019 external validation referansı; MAWI opsiyonel
5. **JA3/JA4:** v1 scope dışı, v2 ablation için
6. **Session features:** Tier 4 dahil (JWT subject veya clientHash fallback)
7. **Detection latency:** Offline / post-hoc hesap
8. **Panic mode:** Kabul. Week 3 sonunda detection beklenenden kötüyse "negative
   result + ablation analysis + threat model limitations" tezine pivot edilir.

## v2'de eklenen kararlar (k6 critique sonrası)

9. **Threat class yapısı 4 sınıflı:**
   - `legitimate`
   - `http_flood` (volumetric, 100+ req/s)
   - `low_rate_bot` (eski "low_slow_bot", doğru adlandırma)
   - `real_slowloris` (slowhttptest tabanlı, gerçek L7 slow-loris)
10. **Mimicry attack v1'e dahil:** En az bir "sophisticated_attacker_ua + overlapping
    IP" varyantı dahil. v1'de empirik test edilecek (önceden v2'ye atanmıştı).
11. **Credential stuffing variant:** http_flood'un bir alt tipi olarak random
    credential, %95+ 401 ratio.
12. **k6 ortak modülleri:** `k6-common/` altında legitimate-user-flow,
    ip-pool, ua-pool — tüm script'lerde paylaşılır.
13. **Scenario duration 30 dakika.** Tier 2 windowed analiz için yeterli sample.
14. **trafficLabel data leakage savunması zorunlu:** Random-label permutation
    test'i feature engineering pipeline'ında baseline check.

---

## Scope — kesin liste

### IN SCOPE (v1)
- nginx + NestJS architecture, dynamic backend cost instrumentation (Prisma)
- Tier 0 raw + Tier 1 connection + Tier 2 windowed (single 10s window) + Tier 3 global
- Aggregation: `src_ip` + `src_subnet_24` (tek model, çift feature seti)
- Session features (mevcut JWT auth flow üstünden)
- **4 traffic class:** legitimate (NASA-replay refactored k6), http_flood (k6
  multi-source), low_rate_bot (k6 düşük tempolu), real_slowloris (slowhttptest)
- **3 attack varyantı (mimicry, credential-stuffing, slow-POST):** scenario'larda
  alt sınıf olarak yer alır
- Calibration: NASA HTTP logs (IAT, endpoint Zipf, Markov, session)
- External reference: CIC-DDoS2019 *yalnızca* HTTP-flood + slow-rate subset, model
  transfer testi için
- Detection: anomaly detection on legitimate-only (Isolation Forest) + supervised
  baseline (Random Forest), proposed = layered (anomaly + supervised stacked)
- Baselines: threshold per IP, statistical (EWMA/CUSUM), classical ML (RF)
- Splits: time-based + **mimicry-attack-holdout** (mimicry test-only)
- Metrics: PR-AUC, per-class recall/precision, detection latency (post-hoc), FPR per
  legitimate IP per minute, distributional similarity (KS/MMD)

### OUT OF SCOPE (v2 / future work)
- Multi-resolution windowing {1s, 10s, 60s}
- JA3/JA4 TLS fingerprint
- **İteratif adaptive adversary** (sadece statik mimicry v1'de; iteratif/adaptif
  saldırgan v2)
- MAWI dataset
- Online streaming detection (offline batch + post-hoc latency yeter)
- Deep learning baseline (RF yeter)
- Multi-application generalization
- HTTP/2 Rapid Reset, HTTP/3 attack vectors

### LIMITATIONS bölümünde açıkça yazılacak
- Synthetic-only validation
- Single application
- Iterative adaptive adversary tested olmadı (sadece tek-shot mimicry empirik)
- TLS fingerprinting kullanılmadı
- IP heterogeneity Docker-host single network ile sınırlı (overlap'lı tasarımla
  iyileştirildi ama gerçek botnet'in /16 dağılımı yok)
- slowhttptest tek host'tan çalışıyor; gerçek distributed slowloris değil

---

## Week 1 — Architecture + raw logging + calibration data
*(unchanged from v1)*

### Day 1 (Pazartesi)
- nginx kurulum (Docker container), log_format ile gerekli alanları çıkartma
- nginx → NestJS upstream proxy (`host.docker.internal:3000`)
- Postgres Docker container'da, Prisma migrate deploy ile mevcut schema kuruldu
- Smoke test: nginx üzerinden bir request → access log + RequestLog tablosunda satır

### Day 2
- Prisma `RequestLog` modelini behavioral feature kolonlarıyla genişlet
- Yeni Prisma modelleri: `Connection`, `BehavioralSession`, `WindowLabel`,
  `EndpointCostProfile`, `Scenario`, `CalibrationBaseline`
- `prisma migrate dev` ile uygulama
- Endpoint diversity: `/health`, `/ping` (cheap), `/metrics/users/count` (medium),
  `/metrics/reports/login-stats` (expensive). `/user/search` zaten very expensive

### Day 3
- Prisma `$on('query')` hook + `process.cpuUsage()` ile dynamic cost
  instrumentation
- `AsyncLocalStorage` ile request scope kontekst (Prisma hook ↔ middleware arası)
- Middleware'i extend et: `uaFamily`, `ipSubnet24`, `headerCount`,
  `cookiePresent`, `bodyLenReceived`, `loginPresent`, `sessionIdHash`

### Day 4
- nginx access log → Prisma sync (Python tail script)
- Connection-level alanları (`connId`, `connRequestIndex`) middleware'a nginx
  proxy header'larından oku ve RequestLog'a yaz
- 1000 request smoke test, end-to-end DB'ye düştü mü doğrula

### Day 5
- NASA HTTP log download + parse (Python). 1995 Jul/Aug aylarından bir hafta
- Distributions fit: inter-arrival per session, endpoint popularity (Zipf α),
  session length, session request count
- KS test ile fit kalitesi raporla

### Day 6
- Endpoint Markov transition matrix NASA'dan çıkar
- Test app'in endpoint'lerini bu kategorilere map et
- IAT empirical CDF tablo halinde sakla (inverse-transform sampling için)

### Day 7 — Week 1 checkpoint
- Tüm Tier 0 alanları log'a düşüyor mu, DB'ye geçiyor mu
- NASA distributions ve Markov hazır mı
- **Slip riski:** instrumentation 1 günde bitmezse, Day 8'e taşır ve session
  feature'ları (Tier 4) kes.

---

## Week 2 — k6 refactor + traffic generation + Tier 1-2 features
*(major revision: Days 8-11 reshaped for k6 critique)*

### Day 8 — k6 refactor part 1: common modules
- `k6-common/` dizini oluştur:
  - `legitimate-user-flow.js` — Markov + log-normal think + Zipf search,
    `k6-traffics.js`'den extract edilen
  - `ip-pool.js` — overlap'lı IP havuzu (tüm class'lar için aynı, bot ve insan
    aynı /16'da)
  - `ua-pool.js` — `legit_browsers`, `naive_attacker_uas` (curl, python-requests,
    Go-http-client), `sophisticated_attacker_uas` (= legit pool, mimicry)
  - `cadence.js` — log-normal cadence helpers (bot için bile uniform yerine
    log-normal)
- `k6-traffics.js`'i refactor et: common'dan import etsin
- `k6-mix-http.js`, `k6-mix-slow.js`, `k6-mix-all.js`'in **legitimate kısımlarını**
  common'dan import etsin (mevcut sadeleştirilmiş `chooseLegitJourney` koduyla
  değiştir)
- Sanity: Standalone legit ile mix legit'in IAT KS distance'ı < 0.05 olsun
  (yani aynı dağılımdan)

### Day 9 — k6 refactor part 2: attack variants
- `k6-low-slow.js` → `k6-low-rate-bot.js` rename, threat model dokümanı yaz
- `k6-http-flood.js` rate'ini 100-200 req/s peak'e çıkar
- Yeni: `k6-credential-stuffing.js`
  - Random email + random password, expected %95+ 401
  - Naive UA pool kullanır
- Yeni: `k6-mimicry-flood.js`
  - sophisticated_attacker_uas (= legit UA havuzu)
  - Overlap'lı IP havuzu (legit'e karışan)
  - Token-reuse pattern (her iteration login değil, sticky token)
  - Aksi her şey flood gibi
- `attackerAgents` sabitlerini kaldır (`'FloodBot/1.0'` vb.) — common pool'a geç
- IP pool'lardaki class-deterministik ayrımı kaldır:
  - Legit, flood, low_rate_bot — hepsi aynı 192.168.0.0/16 + 10.0.0.0/8 havuzundan
- Sanity: source IP'ye bakarak class tahmin edilemiyor (random label
  permutation: bir window'un IP'lerini gözle bakıp class tahmini < %50 doğruluk
  vermeli)

### Day 10 — Real slow-loris (slowhttptest)
- `infra/slowhttptest/Dockerfile`: alpine + slowhttptest binary
- `docker-compose.yml`'e `slowhttptest_runner` service'i ekle (manuel başlatılır,
  default down)
- 3 mod yapılandır:
  - slowloris (incomplete header): `slowhttptest -c 200 -H -i 10 -r 50 -t GET -u
    http://nginx/`
  - slow-POST (RUDY): `slowhttptest -c 200 -B -i 110 -r 50 -t POST -u
    http://nginx/auth/login`
  - slow-read: `slowhttptest -c 200 -X -r 50 -u http://nginx/user/search?q=test`
- Sanity:
  - slowloris çalışırken `concurrent_open_conns` >> baseline
  - `header_recv_duration` (nginx `request_time` - `upstream_connect_time`)
    saldırı sırasında p95 > 30s
  - Meşru request'ler aynı sırada hâlâ %95+ başarılı dönüyor mu (nginx
    connection slot tükenmedi mi)
- nginx `client_header_timeout` 60s'de bırak (production-realistic)

### Day 11 — Orchestration + 30dk scenario runs
- `scripts/run-scenario.sh`: scenario adı al, ilgili k6/slowhttptest sırayla
  başlat, scenario_id'yi DB'ye yaz, post-attack 3 dakika legit-only
- 6 scenario tanımla, her biri 30 dakika + 3 dk recovery:
  - **S1 (calibration):** legitimate-only — endpoint cost calibration için
  - **S2:** legitimate + http_flood (naive UA)
  - **S3:** legitimate + low_rate_bot
  - **S4:** legitimate + credential_stuffing
  - **S5:** legitimate + mimicry_flood (HOLDOUT — Week 3 test-only)
  - **S6:** legitimate + real_slowloris + slow_post
- Toplam veri üretimi: 6 × 33 dk ≈ 3.5 saat
  - **Gece çalıştır.** Tek seferde, otomatik. Sabaha hepsi DB'de.
- Sanity (sabah): scenario başına RequestLog count beklenen aralıkta mı
  (legitimate ~10K-50K, flood ~150K+, low_rate ~1-3K, slowloris bağlantı tabanlı
  farklı sayım)

### Day 12 — Tier 1 connection-level pipeline
- Python/Pandas script: nginx access log + RequestLog merge
- Connection bazında MIN/MAX timing'leri toplar, `Connection` tablosuna yazar
- Slow-attack indicators: `mean_request_time_ms`, `partial_request_count`,
  `timeout_request_count` (status=408)
- **CRITICAL sanity:** real_slowloris scenario'sundaki connection feature'ları
  istatistiksel olarak diğer class'lardan FARKLI mı? Eğer aynıysa instrumentation
  bozuk demektir, debug.

### Day 13 — Tier 2 windowed aggregation + endpoint cost calibration
- Tier 2 aggregation (Pandas): 10s sliding, 1s slide
  - Çift aggregation key: `src_ip` ve `src_subnet_24`
  - IAT (mean/std/cv/skew/p95), endpoint entropy (Miller-Madow), endpoint cost
    sum, status mix, conn-derived
- Endpoint cost calibration: S1 (legitimate-only) trafik ile her route'un mean
  backend cost'unu çıkar, `EndpointCostProfile` tablosuna yaz
- **Sanity:** trafficLabel kolonu Tier 2 feature DataFrame'inde
  `aggregation_key` ile birlikte y-target olarak ayrılmış mı, x-feature listesinde
  HİÇ YOK mu? Drop list'i yaz

### Day 14 — Week 2 checkpoint
- 4 traffic class üretebiliyor muyum (legitimate, http_flood, low_rate_bot,
  real_slowloris) + alt varyantlar (mimicry, credential_stuffing)
- Tier 0/1/2 feature'lar baştan sona çalışıyor mu
- Sanity check: low_rate_bot vs real_slowloris connection feature'larında
  istatistiksel anlamlı fark var mı (Mann-Whitney U)
- **Slip riski:** orchestration karmaşıksa, Day 12-13'e taşır ve mimicry/credential
  stuffing varyantlarını sade tut.
- **Slip riski v2:** slowhttptest nginx'e karşı çalışmazsa (timeout drop), Day 10
  configi tekrar dene; bu da olmazsa real_slowloris'i v2'ye at, sadece
  low_rate_bot kalsın (geri adım, ama tezde dürüstçe yaz).

---

## Week 3 — Detection + experiments

### Day 15
- Tier 3 global features + Tier 4 session features (mevcut JWT auth flow
  stabil çalışıyorsa)
- Markov log-likelihood feature: NASA-trained matrix vs gözlemlenen sequence
- IAT KS distance feature: NASA empirical CDF'e karşı

### Day 16 — Label generation
- Per-(`src_ip`, 10s_window) ve per-(`src_subnet_24`, 10s_window) ground truth
- 4-class label: legitimate / http_flood / low_rate_bot / real_slowloris
- Tie-breaker rule (mixed pencereler için): pencerede attacker-controlled
  source request oranı ≥ %20 → dominant attack class. Bu kural sabit, post-hoc
  değiştirilmeyecek
- credential_stuffing label'ı: `http_flood` çatısı altında (alt sınıf metadata'yı
  ayrı tut, ama target = http_flood)
- mimicry_flood label'ı: `http_flood` çatısı altında (önemli — holdout için)

### Day 17 — Splits
- **Time-based split:** ilk %70 train, sonraki %15 val, son %15 test
- **Mimicry-attack-holdout (KEY):** S5 (mimicry_flood) scenario'su tamamen
  test-only. Train'de mimicry yok, sadece naive flood var. Test'te mimicry
  görüyor.
  - Bu, "behavior-based detection statik mimicry'ye dayanıyor mu" sorusunun
    direkt empirik testi
- Class imbalance: pencere bazında muhtemelen %75 legitimate, %18 http_flood,
  %5 low_rate_bot, %2 real_slowloris

### Day 18 — Baselines
- Baseline 1: per-IP rate threshold
- Baseline 2: EWMA + CUSUM her IP için rate üstünden
- Baseline 3: Random Forest tüm Tier 2 feature'ları
- **Random-label permutation sanity:** Train'i random label'la fit et, test
  accuracy %25 (4-class) civarında olmalı. Eğer %50+ alıyorsa data leakage var,
  pipeline'ı debug et

### Day 19 — Proposed model
- Stacked:
  - Layer A: Isolation Forest, sadece legitimate üzerinde train, anomaly score
    üret
  - Layer B: Random Forest, Tier 2 features + anomaly_score → 4-class
    classifier
- Hyperparameter tuning val set'i üzerinde (mimicry test'i kontamine etme)

### Day 20 — External validation
- CIC-DDoS2019 download (HTTP flood + slow-rate scenario'ları subset)
- Feature alignment (eksikleri NaN, ortakları align). 100% map'lenemez, kabul
- Train: NASA+synthetic, Test: CIC subset → external skor

### Day 21 — Week 3 checkpoint
- Modeller eğitiliyor, baseline ve proposed sonuçlar var mı
- Test set + mimicry holdout sonuçları çıktı mı
- **Slip riski:** CIC parse complications çıkarsa, CIC'i at, internal+mimicry
  yeter. Tezde "external benchmark deferred" yaz.
- **Panic mode trigger:** Eğer proposed model in-distribution test'te
  baseline'lardan iyi DEĞİLSE, Week 4'te "negative result + ablation
  + mimicry vulnerability analysis" tezine pivot. Bu meşru bir akademik katkı.

---

## Week 4 — Analysis + writeup

### Day 22 — Metrics
- PR-AUC (per class), ROC-AUC (per class)
- Confusion matrix (4×4)
- Per-class recall/precision
- FPR per legitimate IP per minute (operasyonel metric)
- Detection latency (post-hoc): saldırı T0 ise, ilk doğru pozitif pencere T0+?
- **Mimicry holdout metrics:** mimicry_flood'ta http_flood recall'u in-distribution
  vs out-of-distribution (mimicry) — bu farkın büyüklüğü tezin kalp grafiği

### Day 23 — Ablation
- Feature gruplarını sırayla kapat, her seferinde modeli yeniden train et:
  - Tüm feature'lar (baseline)
  - IAT feature'ları YOK
  - Endpoint dağılımı feature'ları YOK
  - Connection-level feature'ları YOK
  - Endpoint cost feature'ları YOK
  - Sequential/Markov feature'ları YOK
- **UA-only ablation:** sadece `ua_family` ve `ua_entropy` feature'ları → bu ne
  kadar accuracy verir? Eğer %85+ veriyorsa, modelin "behavior" değil "UA"
  öğreniyor demektir, kaygı verici sonuç ama tezde dürüstçe yaz
- **IP-only ablation:** sadece IP/subnet feature'ları → benzer kontrol

### Day 24 — Distributional similarity
- Sentetik legitimate IAT vs NASA IAT → KS distance, MMD, Wasserstein
- Sentetik endpoint dağılımı vs NASA → KL divergence, JS divergence
- Sentetik vs CIC distributional gap raporla
- Bu çıktılar tezin "calibration validity" + "external validity" bölümleri

### Day 25 — Mimicry attack analysis (empirik)
- S5 scenario'sundaki mimicry_flood traffic'in detection performansı vs naive
  flood:
  - In-distribution naive flood'da recall %X
  - Out-of-distribution mimicry flood'da recall %Y
  - Y << X ise: model "behavior'u" değil "UA/IP'yi" öğreniyor
  - Y ≈ X ise: behavior-based detection iddian güçleniyor
- Feature importance (RF) → hangi feature'lar mimicry'de düşüyor?
- Bu Day artık empirik (önceden sadece teorik vulnerability discussion'dı)

### Day 26 — Methodology yazımı
- Architecture, instrumentation, calibration, traffic generation, feature
  engineering, label scheme, splits
- Diagrams: system architecture, data pipeline, feature taxonomy, scenario timeline

### Day 27 — Results yazımı
- Tablolar: baseline vs proposed × metrics, mimicry vs naive
- Figürler: ablation, PR curves, detection latency CDF, distributional similarity,
  feature importance heatmap

### Day 28 — Final
- Discussion + Limitations + Future work (iterative adaptive adversary, JA3,
  multi-app, online streaming, MAWI, multi-resolution)
- Reproducibility: README, requirements.txt, makefile, dataset hashes
- Final read-through

---

## Risk register

| Risk | Olasılık | Etki | Mitigasyon |
|---|---|---|---|
| nginx + Node hooks integration kompleks | orta | orta | Day 12'de Node low-level bırakılabilir, sadece nginx connection log yetebilir |
| NASA log fit kötü | düşük | yüksek | Wikipedia 2007 trace yedek olarak hazırda dursun |
| **slowhttptest nginx default'una çabuk drop yiyor** | **orta** | **yüksek** | nginx config tweak; bu da olmazsa real_slowloris v2'ye atılır |
| **k6 refactor 2 günde bitmez** | orta | orta | Day 9 sonu deadline; mimicry varyantı atılabilir, sadece UA/IP fix kalır |
| Multi-container IP heterojenliği zorluyor | düşük | düşük | Day 8'de overlap'lı IP pool tek host üzerinde simüle edilir, gerçek dağıtımı yok (limitations) |
| CIC-DDoS2019 parse | yüksek | orta | At, internal+mimicry holdout yeter |
| Class imbalance modelleri ezer | yüksek | orta | Class weight, focal loss, veya minority oversampling |
| Prisma `$on('query')` coverage'ı %100 değil | orta | orta | Limitations'ta belirt; raw SQL'lerde direkt `$queryRaw` instrumentation ekle |
| **30dk × 6 scenario veri Pandas in-memory'ye sığmaz** | orta | orta | Chunked processing, partition by scenario; gerekirse `dask` |
| Yazım son haftaya sıkışır | yüksek | yüksek | Week 1'den itibaren methodology bölümünü paralel yaz |

---

## Hard rules

1. **Cuma günleri checkpoint.** Hedefe %80'den az ulaştıysan o haftanın işini takip
   eden hafta yetiştirmeye değil — pazara o hafta için scope cut'a gir.
2. **Day 26-28 yazıma ayrılmıştır, kod yazılmaz.** Aksi halde tez yarım kalır.
3. **Her gün sonunda commit + lab notebook.** "Bugün ne yaptım, ne çalışmadı" — tezdeki
   methodology'nin ham malzemesi bu olur.
4. **k6 refactor 2 gün sınırlı:** Day 8-9. Day 10 başlamadan tamamlanmalı; aksi halde
   mimicry varyantı atılır, sadece naive flood kalır.
5. **slowhttptest çalışmazsa real_slowloris v2'ye atılır.** Day 10 sonu bu kararı ver,
   yarın yarın deme.
6. **Random-label permutation testi her model train'inden önce zorunlu.** Data
   leakage yakalanırsa Day'i durdur, pipeline'ı düzelt, sonra train.
7. **Panic mode aktif:** Week 3 sonunda detection sonuçları kötüyse, tez "negative
   result + ablation + mimicry vulnerability analysis" tezine pivot eder. Bu da
   meşru bir akademik katkı; modelleri büyütmeye çalışma.
