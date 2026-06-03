# Calibration Validity & Attack Realism — Pre-Implementation Notes

Bu doküman uygulamaya geçmeden önce iki kritik konunun net olmasını sağlar:

1. **NASA/Calgary'nin eski olması ileride sorun çıkarır mı?**
2. **Saldırı trafiği üretirken nelere dikkat etmeli?**

Tezde "Validity" ve "Methodology Limitations" bölümlerinin de ham malzemesi
budur.

---

## 1. Eski calibration dataset'leri — gerçek riskler ve azaltma stratejisi

NASA (1995) ve Calgary (1994-1995) eski. Bu eskilik **bazı şeyler için kritik
sorun, bazı şeyler için sorun değil**. Ayrımı yapmak tezi savunulur kılar.

### 1.1 ÇIKMASI MUHTEMEL gerçek sorunlar

#### (a) Endpoint diversity ve cardinality farkı
- NASA: ~10K unique path, çoğu statik HTML/image/CGI
- Modern web app: hem daha az (8-50 REST endpoint) hem daha çeşitli
  (parametreli route'lar, GraphQL, SPA)
- Senin test app'in: ~10 endpoint

**Sonuç:** NASA'nın spesifik α=1.0 değeri senin uygulamana **direkt
transfer etmez**. Ama Zipf yasasının *varlığı* transfer eder.

**Azaltma:**
NASA'dan **şekli** al (Zipf yasası geçerli), **parametreyi** kendi uygulamana
özgü tahmin et. İki yol:
- Test app'inde gerçekçi browsing (kendin / arkadaşlar) bir saat çalıştır,
  sonuçtan Zipf α'sını fit et
- Veya **sensitivity analysis** yap: legitimate generator'ı α∈{0.8, 1.0, 1.2}
  parametre aralığında çalıştır, detection performansına etkisini ölç

#### (b) Session yapısı modern web'de farklı
- NASA: Sayfa açar → embedded image'leri çeker → linke tıklar → uzun think
  time → tekrar
- Modern: Login → tek sayfa içinde 5-10 paralel API call → kullanıcı bir
  şey yapar → 5-10 paralel API call → ...

NASA'nın IAT dağılımı **think time**'ı yakalar (insanın okuma süresi). Modern
web'in **API micro-burst**'lerini yakalamaz (paralel XHR fetch'ler).

**Azaltma:**
İki ayrı timing yapısını ayrı modelle:
- **Think time** (kullanıcı eylemleri arası): NASA-lognormal, μ_log ~1-2,
  saniye ölçeği
- **API burst gap** (sayfa içi paralel call'lar arası): farklı dağılım,
  10-200ms ölçeği, NASA'da yok

k6-traffics.js'inde bu ayrım **zaten kısmen var** (`thinkShort`,
`thinkMedium`, `thinkLong`). API burst pattern'i için ayrıca `burstGap`
helper'ı ekleyebilirsin.

#### (c) Markov kategorileri test app'ine cleanly map etmiyor
NASA kategorileri: html, image, static, cgi, video, other.
Senin app endpoint'lerin: /health, /ping, /metrics/*, /user/profile,
/user/search, /auth/login.

**Direkt mapping zorlama:**
- /user/profile → "html" mi, "cgi" mi? Ne ikisi
- /user/search → "cgi" diyebilirsin ama gerçekte modern API endpoint
- /auth/login → "form-submit"? NASA'da bu kategori yok

**Azaltma:**
Markov geçişlerini NASA'dan **literal kopyalama**. Test app'inin endpoint
semantiğine göre **kendi geçiş matrisini tasarla**, NASA'yı sadece "bu
yapı tipinin işe yaradığına dair literatür kanıtı" olarak referans göster.

Tezde:
> "Markov transition matrix is designed to reflect realistic user navigation
> within our test application (login → profile → search → repeat patterns).
> The use of Markov chains for user behavior modeling follows established
> precedent (cf. NASA-1995 calibration baseline, Section X)."

#### (d) Bounce rate ve session length sayıları doğrudan transfer etmez
- NASA bounce rate ~%40 olabilir
- Modern API-driven app: çoğu "session" tek API call (mobile push
  notification → tek endpoint hit)
- Veya tam tersi: SPA'da tek "session" 50+ API call

**Azaltma:**
Spesifik sayıları transfer etme. Sensitivity analysis yap: bounce ∈ {%30,
%50, %70} altında detection nasıl davranıyor?

#### (e) Pre-AJAX dönem dataset'i, modern parallelism yok
NASA'da iki request arasındaki minimum gap büyük (insan tıklaması). Modern
SPA'da paralel XHR'ler aynı millisaniyede gelir. Bu **micro-IAT** yapısı
NASA'da yok.

**Azaltma:**
- Tezde dürüstçe yaz: "NASA reflects pre-AJAX serial request patterns;
  parallel asynchronous request bursts characteristic of modern SPAs are
  modeled separately via burst-gap distributions."
- k6 generator'ında paralel API call'ları manuel olarak kodla

### 1.2 SORUN OLMAYAN şeyler (NASA/Calgary'nin transfer eden yapıları)

#### (a) Heavy-tailed think time
İnsanın okuma/düşünme süresi, dikkat süresi 1995'ten 2026'ya değişmedi.
Lognormal/heavy-tailed shape'i geçerli. Reviewer "modern dataset" derse:
"think time human-cognitive characteristic, distribution family invariant
across decades."

#### (b) Zipf law endpoint popularity
Preferential attachment, statistical mechanics. Sosyal sistemlerde, kelime
frekanslarında, web access pattern'lerinde universal. Spesifik α değişebilir
ama yasanın geçerliliği değişmez.

#### (c) Burst → quiet → burst session yapısı
İnsan dikkat süresi sonlu, attention span dataset bağımsız. Session-quiet-
session yapısı her dönemde geçerli.

#### (d) Long-range dependence (Hurst ~0.7-0.9)
Web traffic self-similar, fractal yapıda. Bu yapı network-level değil,
**kullanıcı davranışı** kaynaklı. NASA'dan literatüre 30 yıllık devamlılık
gösterilmiş özellik.

#### (e) Bot vs insan ayrımı için temel sinyaller
NASA'da bot trafiği zaten az ama bot davranışı (constant cadence, narrow
endpoint set, no think time, no embedded resource fetch) 1995'te de
2026'da da aynı yapısal imzaya sahip.

### 1.3 Tez metodolojisinin doğru çerçevelenmesi

**Yanlış formülasyon:**
> "We use NASA logs as our calibration dataset"

Bu söylenirse reviewer 2 hemen "outdated dataset" diye saldırır.

**Doğru formülasyon:**
> "We use classical web traffic logs (NASA, Calgary; 1994-1995) as
> *structural priors* for legitimate user behavior modeling. These traces
> establish the *distributional families* (heavy-tailed think time, Zipf
> endpoint popularity, geometric session length) that characterize human
> web browsing — properties grounded in cognitive limits and statistical
> mechanics that have not fundamentally changed since 1995. Specific
> magnitudes (mean values, exact α) are not transferred; instead, they
> are re-parameterized to our test application context, with sensitivity
> analysis across a range of plausible values (Section X)."

Bu cümle tezin kalbinde olmalı. Reviewer'ın ilk eleştirisini çürütüyor.

### 1.4 Modern context bridge — Wikipedia 2007 (opsiyonel ama güçlü)

Eğer Week 4'te zaman varsa: Wikipedia 2007 hourly pageview dump'ı ile
endpoint popularity Zipf'ini modern dönemde de validate et. Sadece α
karşılaştırması (per-request data yok, sadece hourly aggregate). 2-3 saatlik
iş, tezde "modern Zipf consistency" olarak yer alır.

İndirme: `https://dumps.wikimedia.org/other/pageviews/2007/`

Bu **opsiyonel**, must-have değil. Calgary cross-validation Day 6'da zaten
yapılıyor, bu üst tabaka.

### 1.5 İleride çıkabilecek somut sorunlar ve şimdiden hazırlık

| Soru/sorun | Ne zaman çıkar | Şimdiden cevabın |
|---|---|---|
| "NASA çok eski" | Tez savunması | Section 1.3'teki çerçeveleme |
| "Bounce rate modern web'i yansıtmıyor" | Sensitivity analiz isteyen reviewer | Day 6'da fit edilen sayıyı sabit kullanma; Week 3'te ±20% sensitivity test et |
| "Markov matrisi senin app'le uyumsuz" | Methodology incelemesi | Day 6'da NASA matrisini "literatür referansı"; Week 2'de test app'e özgü matris tasarla |
| "Modern API patterns yok" | DDoS/security uzman reviewer | Limitations'ta açıkça yaz; future work: real production trace |
| "Tek dataset'e güven duyulmaz" | Akademik standart | Calgary cross-validation Day 6'da var |

---

## 2. Saldırı trafiği — gerçekçilik için kritik boyutlar

Saldırı trafiği gerçekçiliği, legitimate trafik gerçekçiliğinden **daha
zor**. Çünkü:
- Saldırı türleri çok çeşitli (volumetric, slow, mimicry, application-logic
  abuse, credential stuffing, scraping)
- Her birinin kendi imzaları var
- Saldırgan **adaptif** olabilir (defense'i izler, evade eder)
- Gerçek saldırı verisi nadir ve genelde anonimleştirilmiş

Senin tez kapsamında 4 traffic class olacak:
- legitimate
- http_flood (volumetric, high rate)
- low_rate_bot (eski "low_slow", scraping/credential probing)
- real_slowloris (TCP-level partial frame, slowhttptest)

Her birinin gerçekçilik kriterleri ayrı.

### 2.1 Volume / rate gerçekçiliği

#### (a) HTTP flood ne kadar olmalı?
- **Senin önceki k6 script'in:** 12 req/s peak. Bu **flood değil**.
- **Gerçek volumetric flood:** 100-10,000 req/s tek source'tan, botnet'te
  toplam 100K+ req/s
- **Lab'da makul hedef:** 100-500 req/s peak. Backend'inin gerçekten
  zorlandığını görmen lazım.
- **Çıktı dolayısıyla nasıl olmalı:** flood sırasında DB connection pool
  doluyor, response time artıyor, 5xx oranı %5+'a çıkıyor. Bu olmazsa
  flood gerçek değil.

#### (b) Low-rate bot ne kadar olmalı?
- **Senin önceki k6 script'in:** 3 VU × 2.4s cadence ≈ 1.25 req/s — OK
- Real low-rate scraping: 0.5-5 req/s sürekli
- Tezde "stealth" iddian güçlüyse: rate'i legitimate user mean rate'inin
  ALTINDA tut. Yani threshold ile fark edilmesin.

#### (c) Slowloris ne kadar olmalı?
- nginx default'unda: `worker_connections 16384`. Senin slowloris bunu
  zorlamalı: 1000+ paralel açık connection.
- slowhttptest default ayarı `-c 1000` zaten gerçekçi
- Sanity: slowloris çalışırken legitimate request başarı oranı düşmeli
  (connection slot tükenmeli)

### 2.2 Source diversity (botnet realism)

Bu **en sık atlanan** realism boyutu, ve detection iddialarını en çok
etkileyen.

#### (a) Tek host'tan saldırı = lab artifact
Senin tüm k6 trafiği **tek makineden** çıkıyor. Tek source IP (veya
sahte X-Test-Client-IP'lerle çoklu görünen tek source). Gerçek botnet:
- 100-10,000 farklı IP'den
- 50+ farklı /24 subnet'inden
- 10+ farklı ASN'den
- Coğrafi olarak dağılmış

#### (b) IP simülasyonu nasıl yapılmalı (Week 2 k6 refactor'unun core'u)
Üç seçenek:
1. **Single host + sahte X-Forwarded-For headers** — senin mevcut yöntem.
   Avantaj: basit. Dezavantaj: nginx tarafında gerçek IP tek (Docker
   bridge); src_ip feature'ı sahte. Eğer middleware `x-test-client-ip`
   header'ı *priority* olarak okuyorsa (`ALLOW_TEST_IP_HEADER=true`
   ile), bu pratik olarak işe yarar — middleware'in **gerçek**
   `req.ip`'i değil, header'daki sahte IP'yi alır. Lab içinde geçerli.
2. **Docker network namespace + macvlan** — her container farklı IP.
   Daha gerçekçi ama setup karmaşık.
3. **Linux netns + iptables MASQUERADE** — opsiyon 2'nin alternatifi,
   benzer karmaşıklık.

**Tavsiyem:** Seçenek 1 + thesis'te limitations'a yaz: "IP heterogeneity
simulated via header-injected addresses; physical network-level diversity
deferred to future work with multi-host deployment."

#### (c) IP pool'unun overlap'lı olması zorunlu (k6 critique'inden)
- Legitimate IP'ler: `192.168.1.1-15, 10.0.0.1-10`
- Flood IP'ler: `192.168.1.50-100, 10.0.0.30-80` (legit ile **overlap**!)
- Low-rate IP'ler: `192.168.1.20-30`

Hepsi aynı /16 pool'undan. `src_subnet_24` feature'ı tek başına class'ı
ayırmamalı.

### 2.3 Request fingerprint gerçekçiliği

#### (a) User-Agent: ÜÇLÜ tier sun
1. **Naive attacker** (script kiddie): `curl/8.x`, `python-requests/2.x`,
   `Go-http-client/1.x`, `PostmanRuntime/7.x`
2. **Sophisticated attacker** (mature toolkit): legit browser UA pool'undan
   rotation. **Aynı pool legitimate'in kullandığı**. Bu mimicry attack.
3. **Real-browser attacker** (Puppeteer/Playwright): tam Chrome UA, JS
   execution capability. Senin scope dışı (HTTP-level değil) ama
   thesis'te mention.

İki farklı flood scenario yap: `flood_naive_ua` ve `flood_sophisticated_ua`.
Detection performansını karşılaştır. Bu Day 25 mimicry analysis'in çekirdeği.

#### (b) Header completeness
Real browsers always send: User-Agent, Accept, Accept-Language,
Accept-Encoding, sometimes Referer. Naive attacker tools genellikle:
- curl: User-Agent + minimal headers (Accept, Host)
- python-requests: User-Agent + Accept + Accept-Encoding (default)
- Go-http-client: minimal

Header completeness'i feature olarak kullanabilirsin (`headerCount`,
`acceptLangPresent`, `refererPresent` zaten var). Naive attacker'lar daha
düşük completeness gösterir.

#### (c) Header order
Real browsers stable order'a sahip (Chrome/Firefox/Safari her biri kendi
sırası). Bot'lar genelde farklı sıra veya rastgele. `headerOrderHash`
feature'ı (zaten schema'da yok ama eklenebilir) discriminative olabilir.

V1 scope'u için **çok ileri**. v2'ye not düş.

### 2.4 Endpoint targeting (saldırgan strateji)

Saldırgan *neden* hangi endpoint'i seçer?

#### (a) Resource exhaustion strategy
Pahalı endpoint'leri hedef alır:
- `/user/search?q=expensive_query` — DB LIKE'lı, yavaş
- `/auth/login` — bcrypt compare expensive
- `/metrics/reports/login-stats` — multi-table aggregate

Senin flood script'in zaten ağırlıklı `/user/search`'e vuruyor. **Doğru.**

Bunu thesis'te şöyle çerçevele:
> "Attackers target asymmetric resource consumption endpoints (high
> backend cost relative to request size). Our flood scenarios concentrate
> traffic on /user/search, which exhibits ~5-100x backend cost relative
> to /health (cf. endpoint cost calibration, Section X.Y)."

#### (b) Probing strategy
Attacker önce sitenin yapısını keşfeder:
- 404 oranı yüksek (random path probing)
- HEAD method kullanımı yüksek
- Robots.txt, sitemap.xml gibi reconnaissance endpoint'leri

Senin scenario'ların **bu boyutu eksik**. v1'de scope dışı, v2'de
"reconnaissance phase" scenario'su olarak eklenebilir.

#### (c) Application logic abuse
Valid input ile expensive code path tetikleme:
- GraphQL deep nested query (uygulanabilir değil senin app'inde)
- Search regex patterns: `^.*(.*).*$` (catastrophic backtracking)
- Pagination abuse: `?limit=10000&offset=0`
- Sort parameter abuse

Senin `/user/search` endpoint'i pagination kabul ediyor. Saldırgan
`?limit=10000` veya çok büyük sayfalama ile DB'yi zorlayabilir.
**Test edilebilir bir saldırı.**

### 2.5 Authentication patterns

#### (a) Credential stuffing — k6 critique'inde önerildi, **must-have**
Random email + random şifre. Beklenen: %95+ 401 cevap. Bu, 4xx_ratio
feature'ının discriminative gücünü ortaya çıkarır. Senin schema'da
`statusCode`, `loginPresent` zaten var, Tier 2 aggregation'da
`status_4xx_ratio` türetilecek.

#### (b) Pre-auth flood
Auth gerektiren endpoint'leri auth'sız vurmak:
- `/user/profile` direkt → 401
- `/user/search?q=x` direkt → 401

Volume sağlanır ama backend cost düşük (auth check'te kesilir). Saldırgan
açısından inefficient ama detection açısından "yüksek 401 oranı +
yüksek volume" imzası verir.

#### (c) Post-auth flood (compromised account)
Login başarılı + token al + bombarduman. Senin mevcut k6-http-flood.js bunu
yapıyor. Bu **sophistication** seviyesinde flood.

#### (d) Session fixation, hijack
Çok daha sofistike, scope dışı.

### 2.6 Temporal patterns

#### (a) Sustained constant rate
En basit, senin mevcut script'lerin bunu yapıyor (ramping-arrival-rate
ile peak'e çıkıp sürdürüyor).

#### (b) Pulse-wave (Cloudflare reportlarda yaygın)
30-60s burst, 30-60s quiet, tekrarla. Window-averaged metric'leri kandırır
çünkü ortalama düşük görünür ama burst'ler sırasında server zorlanır.

V1 scope dışı (Plan'da v2). Tezde mention et.

#### (c) Gradual ramp-up (threshold testi)
Saldırgan defense'in eşiğini bulmaya çalışır. Yavaş yavaş artırır.
Threshold-based detector'lar bunu kaçırır (her zaman threshold altında).

V1'de basit gradual ramp ile demonstrate edilebilir.

#### (d) Recovery period
Saldırı bittikten sonra server toparlanır (DB connection drain, cache cold).
5xx/latency kalıntıları bir süre devam eder. Detection bu period'da neyi
yanlış sınıflandırıyor? Önemli analytical question.

Senin scenario'larında recovery period eklendi (Day 11 plan'ında).

### 2.7 Adaptive adversary (mimicry)

Mimicry = saldırgan defense'in feature setini biliyor ve *taklit ediyor*.

Senin v1'de **statik mimicry** var: `mimicry_flood` scenario'su,
sophisticated UA + overlap IP. Bu, "saldırgan UA ve IP'yi gizliyor" senaryosu.
Detection'ın UA/IP'ye değil, davranışa dayandığını test eder.

**İteratif/dinamik adaptive adversary** (ML-based attacker, evolving
strategy) v2 scope. Tezde "future work" olarak mention.

### 2.8 Saldırı gerçekçilik check-list (k6 refactor'da)

| Boyut | v1 hedefi | Şu an mevcut mu | Kapatılması gereken |
|---|---|---|---|
| Volume (flood) | 100+ req/s peak | 12 req/s (yetersiz) | k6 stages'i ölçekle |
| Source IP heterogeneity | Overlap'lı pool | Class-deterministik | k6-common/ip-pool.js |
| UA tier | Naive + Sophisticated | Tek tier (`FloodBot/1.0`) | k6-common/ua-pool.js |
| Endpoint targeting | Expensive odaklı | Çoğunlukla `/user/search` | OK |
| Credential stuffing | Var olmalı | Yok | k6-credential-stuffing.js |
| Mimicry attack | Var olmalı | Yok | k6-mimicry-flood.js |
| Real slowloris | Var olmalı | k6 ile yapılan yanlış | slowhttptest container |
| Pulse-wave | v2 | Yok | v2 |
| Recovery period | 3dk post-attack | Plan'da var | Day 11'de uygulanacak |
| Temporal ramp | ramping-arrival-rate ✓ | Var | OK |
| 4xx pattern | Credential stuffing'le | Yok | scenario eklenince gelir |

### 2.9 Saldırı dataset ground-truth ambiguity

**Önemli felsefi mesele:**

"Attack" nedir, "legitimate automated user" nedir? Sınır net değil.
- Bir araştırmacı API'ni programatik kullanıyor → automation. Saldırı mı?
- SEO crawler robots.txt'i ihlal ediyor → bot. Saldırı mı?
- Mobile app exponential backoff bug'ı yüzünden retry storm yapıyor →
  legitimate user, ama trafiği saldırıya benziyor

Senin synthetic ground-truth'unda bu **muğlaklık yok** (k6 script'i ya
attacker'dır ya legit). Ama gerçek production'da var.

**Tezde şöyle açıkla:**
> "Synthetic traffic provides binary ground-truth labels. Real-world
> deployment introduces label ambiguity (gray traffic: crawlers, automation
> tools, retry storms from misbehaving clients). Detection threshold
> calibration in production must accommodate this gray zone, typically via
> probabilistic scoring rather than binary classification. Future work
> directions: semi-supervised learning, anomaly score interpretation."

### 2.10 Eksik kalacak şeyler (v1'de yapılamayan, dürüstçe)

Bu listeyi tezin Limitations bölümüne yaz:
- **Real botnet diversity** (IP/ASN/geo): tek host'tan synthetic
- **Encrypted traffic / TLS fingerprinting**: HTTP only v1
- **HTTP/2 specific attacks** (Rapid Reset CVE-2023-44487): scope dışı
- **CDN-fronted attacks** (origin tek IP'lik gibi görünür): scope dışı
- **Distributed slowloris** (botnet'ten 100K+ slow connection): tek host
- **Iterative adaptive adversary** (ML-based evolving): future work
- **Real production gray traffic** (crawlers, monitoring): synthetic'te yok

---

## 3. Uygulamaya geçmeden önce somut zihinsel kontrol

Day 5-6'ya başlamadan önce kendine sor:

1. NASA fits'ini **şekil olarak mı, parametre olarak mı** kullanacağım?
   → Şekil olarak. Parametreler sensitivity analiz'le.

2. Markov matrisini test app'e **literal kopyalayacak mıyım**?
   → Hayır. Test app'in semantik mapping'iyle kendi geçişlerimi tasarlayacağım,
     NASA/Calgary'i literatür referansı olarak kullanacağım.

3. k6 attack scripts'i Day 8-9'da refactor edeceğim, **bu refactor'da hangi
   gerçekçilik boyutlarını kapatacağım**?
   → P0 listesi (k6 critique dosyası): UA tier, IP overlap, label leakage,
     credential stuffing, mimicry, real slowloris, 30dk duration.

4. Tezde NASA/Calgary kullanımını nasıl çerçeveleyeceğim?
   → Section 1.3'teki formülasyon. "Structural priors, not direct parameters."

5. Hangi limitations'ı baştan kabul ediyorum?
   → Section 2.10'daki liste. Future work olarak yazılı.

Bu beş soruya net cevabın varsa, Day 5'e güvenle başlayabilirsin. Belirsizlik
varsa önce onu netleştir.

---

## 4. Bir cümlede özet

NASA/Calgary'i **distribution shape** ve **literatür referansı** olarak
kullan, **parametre** olarak değil. Saldırı trafiğinde **source diversity,
UA realism, label leakage savunması, credential stuffing, mimicry, real
slowloris** boyutları kapatılmadan threat model eksiktir — bunlar Week 2
k6 refactor sprint'inin amacı.
