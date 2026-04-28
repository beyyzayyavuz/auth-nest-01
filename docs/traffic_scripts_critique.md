# k6 Traffic Scripts — Critical Review

**Scope:** `k6-traffics.js`, `k6-http-flood.js`, `k6-low-slow.js`, `k6-mix-http.js`,
`k6-mix-slow.js`, `k6-mix-all.js`.

**Tone:** sert, research-grade. Akademik reviewer 2 gözüyle.

---

## 0. Özet

Legitimate user simulator (`k6-traffics.js`) standardın üstünde. Saldırı script'leri
ve mix script'lerde **threat model**, **label leakage** ve **realism** açıkları var.
Tezi bu hâliyle gönderirsen reviewer'ın saldıracağı 5 nokta var; onları aşağıda
priorite sırasına göre yazdım.

**Düzeltilmeden Day 8'e (traffic generation phase) geçilmemesi gerekenler:**

1. "Low-slow" yanlış adlandırma + threat model hatası
2. Saldırgan User-Agent'ı label-leakage seviyesinde belirgin
3. IP space class'a göre deterministik ayrılmış (lab artifact)
4. `trafficLabel` data leakage riski
5. Mix script'lerde "normal user" sadeleştirilmiş — train/test bias

---

## 1. THREAT MODEL HATALARI

### 1.1 "Low-slow bot" yanlış isim — kritik

`k6-low-slow.js` low-slow / slowloris / slow-POST DEĞİL. Low-slow saldırılarının
tanımı:

- **Slowloris:** TCP/HTTP-level partial header. Connection açar, header'ı 1 byte/10s
  hızında gönderir, server connection slot'ı tüketir.
- **Slow-POST (RUDY):** `Content-Length: 9999999` ile başlar, body'yi damla damla
  gönderir.
- **Slow Read:** TCP receive window manipüle ederek server'ı buffer'da bekletir.

Senin `k6-low-slow.js`'in: tam request gönderiyor, 2.2-2.5s aralıklarla. Bu
**low-rate polling bot** veya **stealth scraper**. Tamamen farklı threat model:

| Boyut | Senin script | Gerçek slowloris |
|---|---|---|
| Connection lifecycle | Normal request/response | 100-1000 connection sürekli açık |
| Bytes/second | Normal | <1 byte/s per connection |
| Server resource bottleneck | DB/CPU | Connection slot exhaustion |
| Detection signal | Request rate, timing patterns | `header_recv_duration`, partial requests |

**Sonuç:** `feature_schema_v1.md`'de tanımladığım low-slow detection feature'ları
(`mean_header_recv_duration`, `partial_request_ratio`, `concurrent_open_conns`) bu
script'in trafiğine *sıfır sinyal* verir. Tezde "low-slow attack detection yapıyorum"
iddian havada kalır.

**İki çözüm:**

**A) Yeniden adlandır (kolay, dürüst):** Şu anki "low_slow_bot" → `low_rate_bot` veya
`stealth_scraper`. Threat model: "rate threshold altında uçan, sürdürülebilir
scraping/credential probing bot'u." Bu meşru ve önemli bir threat. Senin script
zaten bunu test ediyor, sadece label yanlış. Tezde thread model bölümünü buna göre
yeniden çerçevele.

**B) Gerçek slow-loris ekle (zor ama tezi güçlendirir):** k6 ile yapılamaz. Ayrı
araç gerek:
- `slowhttptest -c 1000 -H -i 10 -r 200 -t GET -u http://localhost:8080/`
- `slowhttptest -c 1000 -B -i 110 -r 200 -t POST -u http://localhost:8080/auth/login`

Bu araçları Docker container'da çalıştırırsın, k6 ile parallel. Yeni bir scenario:
`real_slowloris`.

**Tavsiyem:** İkisini birden yap. Mevcut `low_slow_bot` adını `low_rate_bot` olarak
değiştir, gerçek slow-loris'i ek bir scenario olarak ekle. Tezde 4 traffic class
olur: legitimate, http_flood, low_rate_bot, real_slowloris.

### 1.2 Tüm flood'lar başarılı login yapıyor

Saldırgan tüm valid kullanıcı şifrelerini biliyor. Threat model: "compromised
credential" — meşru bir threat ama tek başına yetersiz.

Gerçek HTTP flood'un büyük kısmı:
- Auth'sız endpoint'lere vurur
- Credential stuffing yapar (random email + random şifre, %0 başarı)
- Çalınmış token kullanır

**Eksiklik:** Senin script'lerde `4xx/5xx ratio` feature'ı flat olacak çünkü flood
%100 login başarılı oluyor. Gerçekte flood'un en güçlü sinyallerinden biri yüksek
4xx oranıdır.

**Düzeltme:** En az bir flood scenario'su credential-stuffing tarzı yap:
```javascript
const fakeUser = {
  email: `attacker${Math.random().toString(36).slice(2)}@x.com`,
  password: 'wrong',
};
```
Beklenen: 401 oranı %95+. Bu, flood'un karakteristik feature imzasını verir.

### 1.3 Flood'un volumetric yoğunluğu yetersiz

`k6-http-flood.js` peak: 12 req/s (`stages target: 12`). Bu flood değil, **yoğun bir
gün**. Gerçek HTTP flood:
- L7: 100-10,000 req/s, single source ya da botnet
- Mirai-style: tek node'dan 1000+ req/s

Sen 12 req/s ile test edersen "flood detection" iddian zayıflar — modelin "yoğun
trafik vs sakin trafik"i ayırıyor, "saldırı vs yoğun meşru trafik"i değil.

**Düzeltme:** Flood scenario'larını en az 100 req/s'e çıkar. `preAllocatedVUs: 100`,
`stages target: 200`. Backend'inin gerçekten zorlandığı bir noktaya gel — ki feature'lar
(5xx oranı, response time tail, db_total_time spike) anlamlı varyans göstersin.

### 1.4 Real slow-loris'siz tek node attack — IP heterojenliği yok

Tüm saldırı tek host'tan k6 worker'larından geliyor. Gerçek botnet:
- Yüzlerce farklı /24'ten gelir (residential proxy, compromised IoT)
- ASN diversity yüksek
- Geo dağılım coğrafi olarak geniş

Senin script'te flood IP'leri hep `10.10.x.x` aralığında. Bu **lab artifact**;
modelin "10.10.* → flood" diye trivial overfit eder.

---

## 2. LABEL LEAKAGE PROBLEMLERİ

### 2.1 User-Agent saldırgan kimliğini bağırarak söylüyor

```javascript
// flood
'FloodBot/1.0', 'FloodBot/1.1', 'AggressiveClient/2.0'
// slow
'PeriodicStealthBot/1.0', 'LowRateClient/1.2', 'SlowProbe/2.0'
```

Trivial regex `/Bot|Client|Probe/i.test(ua)` → %100 saldırı tespiti. Modelin bu
sinyali öğrenir ve hiçbir şey yapmasa bile yüksek accuracy alır. **Lab içinde
çalışır, gerçek dünyada %0 recall.**

Gerçek attacker UA'ları:
- `curl/7.81.0`, `python-requests/2.31.0`, `Go-http-client/1.1` (naive)
- Headless Chrome / Puppeteer real UA (sophisticated)
- **Real browser UA pool'undan rotation** (mature attacker)

**Düzeltme — iki seviye sun:**

```javascript
// "Naive attacker" pool — orta seviye saldırgan
const naiveAttackerAgents = [
  'curl/7.81.0',
  'python-requests/2.31.0',
  'Go-http-client/1.1',
  'PostmanRuntime/7.36.0',
];

// "Sophisticated attacker" pool — meşru kullanıcılarla aynı UA havuzu
const sophisticatedAttackerAgents = legitAgents; // identical
```

İki ayrı saldırı varyasyonu test et:
- `flood_naive`: kolay attacker pool
- `flood_sophisticated`: legitimate UA pool

İkincisinde detection nasıl düşüyor? Bu **ablation study'nin direkt malzemesi**.

### 2.2 `x-simulation-label` header'ı feature pipeline'a sızabilir

Senin middleware'in `x-simulation-label`'ı okuyup `trafficLabel` kolonuna yazıyor.
Bu **ground truth y-label**. Eğer Tier 2 feature engineering'de `trafficLabel`
kazara feature olarak kullanılırsa modelin %100 accuracy alır — pure data leakage.

**Mutlaka:**
- Feature engineering pipeline'ında `trafficLabel` (ve onun derivative'leri:
  `*_ratio`, `*_count` gibi) **explicit olarak drop** edilsin.
- Sanity check: train öncesi feature listesini print et, `label` kelimesi olan
  hiçbir kolon olmasın.
- Cross-check: random label permutation'da accuracy %33 (3-class) civarında
  olmalı. Eğer hâlâ %80+ alıyorsan leakage var demektir.

### 2.3 IP space class label'ı ele veriyor

| Class | IP space |
|---|---|
| legitimate (k6-traffics) | 192.168.1.x, 10.0.0.x |
| flood standalone | 10.10.1.x |
| low-slow standalone | 10.20.1.x |
| flood mix-http | 10.10.30.x |
| low-slow mix-slow | 10.20.30.x |
| flood mix-all | 10.10.70.x |
| low-slow mix-all | 10.20.70.x |
| normal mix-* | 192.168.20.x / 192.168.50.x / 192.168.70.x |

**`src_subnet_24` feature'ı tek başına %100 ayrım yapar.** Modelin bunu öğrenir,
gerçek dünyaya transfer etmez.

**Düzeltme — iki seçenek:**

**A) Tam overlap (en agresif):**
Tüm class'lar aynı `192.168.*.* + 10.*.*.*` havuzundan rastgele çekilsin. IP
class'tan bağımsız olsun. Bu durumda IP-based feature'ların *katkısı*
ölçülebilir.

**B) Botnet-realistic clustering:**
Saldırganlar daha dar bir IP cluster'ından gelsin (gerçekçi: botnet'ler
clusterlanır), ama meşru IP'lerle önemli overlap olsun. Örnek:
- Legit: 1000 farklı IP, 50 farklı /24'ten
- Flood: 100 farklı IP, 10 farklı /24'ten
- Bunların 5'i overlap

Bu durumda IP gerçek bir signal taşır ama trivial bir leak değildir.

**Tavsiyem:** B. Ama explicit ablation'da A'yı da çalıştır ve raporla:
"IP feature'ları kapatıldığında recall %X düştü."

---

## 3. REALISM TUTARSIZLIKLARI

### 3.1 Mix script'lerde "normal user" sadeleştirilmiş

Standalone `k6-traffics.js`:
- Markov chain (start → profile/search/exit)
- Log-normal think time (3 farklı parametre seti: short/medium/long)
- Zipf search term sampling
- Bad input ratio (%2 garbage)
- Geometric session length, bounce rate
- Weighted UA pool (8 gerçekçi browser)
- IP pool 25 IP

Mix script'lerde "normal user":
- Sabit `chooseLegitJourney` 4 path
- Uniform `think(min, max)` (log-normal değil)
- 2-tier popular/long-tail (Zipf değil)
- 3 UA (8 değil)
- Tek IP per VU formülü

**Sonuç:** Detection en zor olduğu durumda (mix'te) legitimate trafik **daha
basit**. Modelin "basit normal vs flood'u" ayırmayı kolayca öğrenir, "gerçekçi
normal vs flood'u" ayırmayı öğrenmez.

**Bu major bir bias.** Reviewer 2'nin direkt sorusu: "Why is your legitimate
traffic simpler in mixed scenarios than in standalone?" Cevabı yok.

**Düzeltme:** Mix script'lerin "normal" tarafını `k6-traffics.js`'in tam aynısı
yap. Markov, log-normal think, Zipf, weighted UA — hepsi aynı modülden
import edilsin. Ortak bir `legitimate-user-flow.js` yarat ve tüm script'ler import
etsin.

### 3.2 Saldırı süresi çok kısa

| Script | Total duration |
|---|---|
| k6-traffics | ~3 min |
| k6-http-flood | ~3 min |
| k6-low-slow | 4 min |
| mix-http light | ~4 min |
| mix-all heavy | ~3.5 min |

Tier 2'de 10s sliding window kullanacaksın. 3 min × 60 = 180 sample, ama
per-`(src_ip, window)` partition edince çok azalıyor. Ayrıca train/val/test split
sonrası test set'i 30-50 window'a düşebilir. **İstatistiksel olarak yetersiz.**

**Düzeltme:** Her scenario en az 30 dakika çalışsın. 30 dk × 6 senaryo = 3 saat
trafik. Partition başına ~150-300 window, anlamlı.

### 3.3 Endpoint diversity 4 — entropy ceiling düşük

Tüm script'ler sadece bunlara vuruyor:
- `/auth/login`
- `/auth/logout`
- `/user/profile`
- `/user/search`

`endpoint_entropy` Shannon ceiling: log2(4) = 2 bits. Çok dar. Gerçek web 50-500
endpoint hit eder. `endpoint_entropy` feature'ının discriminative gücü artificially
sınırlı.

**Düzeltme:** START_HERE.md'de eklediğin endpoint'leri (/health, /ping,
/metrics/users/count, /metrics/reports/login-stats) k6 script'lerine de ekle.
Legitimate user'lar bunlara da uğrasın. En az 8 endpoint hit edilmeli.

### 3.4 Login → action arası gecikme bot ve insan arasında çok benzer

Bot'lar (`k6-low-slow.js`):
```javascript
function cadenceSleep(profile) {
  const jitter = Math.random() * (MAX_JITTER - MIN_JITTER) + MIN_JITTER;
  sleep(profile.cadenceBase + jitter); // 2.20-2.59s
}
```

İnsanlar (`k6-traffics.js`, `thinkMedium`):
```javascript
function thinkMedium() {
  thinkLogNormal(1.2, 0.8, 0.5, 30); // medyan ~3.3s
}
```

Bot ortalama 2.4s, insan ortalama 3.3s. Distribution shape'ler farklı (uniform vs
log-normal) ama **mean'ler yakın**. Inter-arrival mean tek başına bot/insan
ayırmıyor. Sen `iat_cv`, `iat_skew`, `iat_kurt` feature'larına güveneceksin —
distribution shape feature'ları. Bu doğru, ama: **bot scriptinde uniform jitter
çok dar (60ms varyans).** Bu kadar dar uniform → çok düşük std → bot tespiti çok
kolay.

Gerçek scraping bot'ları davranışsal mimicry için **noisy delays** kullanır
(uniform değil, lognormal-ish). Senin "low-rate bot" çok mekanik kalmış.

**Düzeltme:** Bot cadence'ini de log-normal yap, ama farklı parametrelerle:
```javascript
function botCadence() {
  thinkLogNormal(0.8, 0.3); // medyan ~2.2s, daha dar (insan'a göre)
}
```

Median'lar yakın, distribution shape farkı daha subtle. Detection problemini
**zorlaştırır** — ki tezde "behavior-based detection" iddian güç kazanır. Eğer
detection trivial olursa katkın azalır.

### 3.5 Token persistence farklı script'lerde tutarsız

- `k6-traffics.js`: token session boyunca, sonra `clearToken`
- `k6-http-flood.js`: her iteration'da yeni login (token yenileme)
- `k6-low-slow.js`: 30 step'te bir re-login
- `k6-mix-flood.js`: her iteration'da yeni login

Saldırgan token'larını sürekli yeniliyor → her flood iteration'ı bir login + N
search. Bu **login flood**'u arttırır. Ama gerçek HTTP flood büyük ihtimalle tek
token'la 1000+ request atar (token-reuse). Senin script'lerde flood'un %50'si
login isteği oluyor — gerçek flood profili değil.

**Düzeltme:** Flood'un da k6-traffics gibi token'ı session boyunca tutmasını
düşün. Veya: bilinçli olarak token-spam ve token-reuse iki ayrı senaryo olarak
test et.

---

## 4. EKSIK SCENARIO'LAR

### 4.1 Yetersiz threat coverage

Şu anki traffic class'lar:
- legitimate
- http_flood (volumetric, başarılı login)
- low_slow_bot (yanlış adlandırılmış low-rate bot)

**Eksik gerçekçi senaryolar:**

| Scenario | Açıklama | Önem |
|---|---|---|
| `credential_stuffing` | Random email+password, %95+ 401 | Yüksek — gerçek dünya çok yaygın |
| `real_slowloris` | slowhttptest tabanlı | Yüksek — tezin başlığında "low-slow" var |
| `flood_unauth` | Auth'sız endpoint flood (sadece /search) | Orta — basit ama gerçekçi |
| `pulse_wave_flood` | 60s on / 60s off pattern | Orta — pulse-wave Cloudflare reportlarda yaygın |
| `mimicry_attack` | Saldırgan legit UA + legit IP havuzu kullanıyor | Yüksek — adaptive adversary baseline |
| `gray_traffic` | Search engine bot, monitoring tool, RSS reader | Düşük ama puan getirir |

`mimicry_attack` özellikle önemli. Adaptive adversary önceden v2'de demiştik ama
**en az bir mimicry varyantı v1'de olmalı** — yoksa "behavior-based detection"
iddian temelsiz.

### 4.2 Recovery period yok

Saldırı bitince server'ın toparlanması (DB connection drain, cache cold start)
sırasında 5xx ve latency spike'ları olur. Detection'ın bu period'da neyi yanlış
sınıflandırdığı önemli operasyonel sorudur. Senin script'lerde graceful ramp-down
sonrası boş zaman yok — saldırı bitince hemen kesiyor.

**Düzeltme:** Her scenario sonrası 2-3 dakika "sadece legitimate" kuyruk eklesin.
Bu period'un label'ı `legitimate`, ama feature'ları muhtemelen hâlâ anormal.
Detection nasıl davranıyor? Bu kendi başına bir analiz konusu.

---

## 5. PRIORITY-RANKED FIX LIST

Day 8'e (traffic generation phase) geçmeden:

### P0 (must-fix)
1. **`low_slow_bot` → `low_rate_bot` rename.** Threat model documentation güncelle.
2. **Saldırgan UA'ları gerçekçi yap.** En az iki tier (naive + sophisticated).
3. **IP space overlap'ini sağla.** Class'a göre deterministic ayrım kaldır.
4. **`trafficLabel` data-leakage savunması:** feature engineering pipeline'ında
   explicit drop list. Random-label permutation testi.
5. **Mix script'lerde legitimate user flow'u harmonize et.** `k6-traffics.js`'in
   sophistication'ı mix'lerde de olmalı.

### P1 (should-fix)
6. **Flood rate'ini 100+ req/s'e çıkar.** 12 req/s flood değil.
7. **Scenario duration'ı 30 dakikaya çıkar.** İstatistiksel sample yeterli olsun.
8. **Endpoint diversity'yi 8+'e çıkar.** Yeni endpoint'leri k6'ya da ekle.
9. **Real slow-loris ekle (slowhttptest).** Ayrı scenario olarak.
10. **Credential-stuffing flood ekle.** En az %50 401 oranıyla.

### P2 (nice-to-fix)
11. Bot cadence'ini log-normal yap (mekanik uniform yerine).
12. `mimicry_attack` scenario ekle (legit UA + legit IP'li flood).
13. Recovery period her scenario sonrası.
14. Pulse-wave flood pattern.
15. Token persistence stratejisini standartla (en az iki ayrı varyant test et).

---

## 6. Pratik öneri

Day 8'e geçmeden önce **2-3 günlük "k6 refactor sprint'i"** yap. Çıktı:

1. Ortak modül: `k6-common/legitimate-user.js` — sophisticated flow, tüm
   script'lerde import edilen.
2. Ortak modül: `k6-common/ip-pool.js` — overlap'lı IP havuzu.
3. Ortak modül: `k6-common/ua-pool.js` — legitimate + naive_attacker +
   sophisticated_attacker pool'ları.
4. Yeniden yazılmış: `k6-low-rate-bot.js` (eski adıyla low-slow), durumu net.
5. Yeni: `k6-credential-stuffing.js`.
6. Yeni: `k6-mimicry-flood.js`.
7. Ayrı araç: `slowhttptest` Docker container, separate scenario.
8. Tüm scenario'lar 30 dakika.

Bu refactor'u yapmadan trafik üretirsen, ürettiğin verinin **istatistiksel olarak
geçersiz** olduğunu Day 14 checkpoint'inde göreceksin ve hepsini tekrar yapmak
zorunda kalacaksın. **3 günlük şimdiki yatırım, 7 günlük sonraki kayıptan
ucuz.**

Bu refactor'u proje plan'ında **Day 7.5 — k6 sprint** olarak insert etmek
gerekiyor; planı bu doğrultuda revize edelim.
