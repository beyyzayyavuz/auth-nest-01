# Citation Verification Roadmap

Bu doküman, `attack_calibration_sources.md`'daki tüm kaynakları sırayla
nasıl doğrulayacağını adım adım anlatır. Her kaynak için:
- Direkt URL
- Ne aramak lazım
- Hangi cümle / sayı / bölüm önemli
- Bulduğunu nasıl cite edeceğin
- Bulamazsan ne yapacağın

> **Önemli uyarı:** Sayfa numaralarını ve spesifik istatistikleri **ben
> garanti edemem**. Mirai disaster'ı gösterdi — LLM'ler bu detayları
> uydurabilir. Sen kaynağı açıp **kendi gözünle bulmalısın**. Bu doküman
> sadece "nereye bakacağına" yol gösterir, "ne bulacağını" garanti etmez.

---

## Genel sıralama (öncelik düzeni)

Sıralama **kolaydan zora** + **risk düşükten yükseğe**:

1. **Kategori A: Tool documentation** (en kolay, en güvenilir) — 1-2 saat
2. **Kategori C: OWASP / RFC** (kolay, public, çok güvenilir) — 1 saat
3. **Kategori B: Industry reports** (PDF okumak lazım, orta süre) — 2-3 saat
4. **Kategori D: Academic papers** (en zor, en yüksek hallucination riski) — 3-4 saat

Toplam: ~7-10 saat. Day 9.0'a 4 saat ayrılmıştı; geri kalan Day 9.1'e
yayılır veya yazım haftasında (Day 26-28) bitirilir.

**Tavsiye edilen iş düzeni:**

```
Bugün (Day 8 öncesi):
  - Bu roadmap'ı oku, anla
  - Kategori A (tool docs) tamamen yap (~1-2 saat)

Day 9.0:
  - Kategori C (OWASP) yap (~1 saat)
  - Kategori B (Akamai SOTI + Cloudflare) yap (~2 saat)

Day 26 yazım:
  - Kategori D (akademik) yap (~3-4 saat)
  - Doğrulanamayanlar için fallback: tool/industry citation'a geç
```

---

# KATEGORİ A — TOOL DOCUMENTATION

## A.1 — slowhttptest GitHub

**Neye yarıyor:** Slowloris/slow-POST/slow-read parametrelerinin
gerekçesini veriyor. **K6 scenario S6** için anchor.

**URL:** https://github.com/shekyan/slowhttptest

**Ne yapacaksın (10 dk):**

1. Linki aç
2. README.md'yi yukarıdan aşağı göz gez
3. **"Usage" bölümünü** bul (genelde README'nin ortasında)
4. Default parametreleri bul:
   - `-c` → connection count default (50 veya 1000 olabilir)
   - `-i` → header drip interval (5-10 saniye)
   - `-r` → connection rate
   - `-x` → maximum bytes
5. **Slow attack kategorilerini** bul: slowloris, slow-POST, slow-read
   (genelde `-H`, `-B`, `-X` flag'ları altında)

**Kaydet (`citation_verification_log.md`'a):**

```markdown
## slowhttptest (Shekyan)
- URL: https://github.com/shekyan/slowhttptest
- Verified: YYYY-MM-DD
- Defaults observed:
  - -c default: __ (oradan kopyala)
  - -i default: __ saniye
  - -r default: __
- Attack categories documented:
  - -H: slowloris (incomplete header)
  - -B: slow-POST (slow body)
  - -X: slow-read (TCP receive window)
- Status: ✓ Verified
```

**Tezde nasıl cite et:**

```
Slowloris and slow-POST attack parameters follow slowhttptest tool
documentation defaults [Shekyan, slowhttptest GitHub repository,
https://github.com/shekyan/slowhttptest]:
- 500 concurrent connections (within range -c 50 to -c 1000 documented)
- 10s header drip interval (matches -i 10 default)
- 110s body drip interval (slow-POST RUDY mode -B)
```

**Eğer bulamazsan:** README değişmiş olabilir. Wayback Machine'de eski
versiyonu bul: https://web.archive.org/web/*/github.com/shekyan/slowhttptest

---

## A.2 — Cloudflare Rate Limiting Documentation

**Neye yarıyor:** "Per-source rate limit threshold" iddiamızın anchor'ı.
**S2, S3, S4, S5** için "rate-limit-evading attacker" justification.

**URL:** https://developers.cloudflare.com/waf/rate-limiting-rules/

**Ne yapacaksın (15 dk):**

1. Linki aç
2. Sayfada Cmd+F ile ara: `default`, `threshold`, `requests per minute`
3. Cloudflare'in default rate limit önerilerini bul
   (genelde "100 requests per minute per IP" gibi)
4. **"Rate-based rules"** veya **"WAF rate limiting"** sayfasına git
   (link yan menüde)
5. Recommended rate limit ranges'i kaydet

**Alternatif sayfa (genel rate limit bilgisi):**
https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/

**Kaydet:**

```markdown
## Cloudflare Rate Limiting
- URL: https://developers.cloudflare.com/waf/rate-limiting-rules/
- Verified: YYYY-MM-DD
- Default/recommended rate limit observed:
  - __ requests per __ time unit per IP
- Best practices section says: __ (paraphrase)
- Status: ✓ Verified
```

**Tezde:**
> "Per-source attack rate (1 req/s) is set below typical CDN rate limit
> defaults; Cloudflare WAF rate limiting documentation
> [https://developers.cloudflare.com/waf/rate-limiting-rules/]
> recommends thresholds of approximately X requests/minute per IP for
> bot mitigation."

---

## A.3 — AWS WAF Rate Limit Defaults

**Neye yarıyor:** İkinci bir industry vendor reference. Defansif.

**URL:** https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html

**Ne yapacaksın (10 dk):**

1. Linki aç
2. **"Rate limit"** veya **"rate-based rule"** açıklamasını bul
3. Default time window (5 minutes) ve default limit'i not et
4. Aggregation key types (IP, header, custom) bilgisini al

**Kaydet:**
```markdown
## AWS WAF Rate-Based Rules
- URL: yukarıdaki
- Default rate limit: __ requests per 5-minute window per IP
- Status: ✓ Verified
```

**Tezde:** Cloudflare ile birlikte cite et (iki vendor doğrulaması).

---

## A.4 — k6 Documentation

**Neye yarıyor:** Load testing methodology'sini gerekçelendiriyor.
Lab-scale parametre seçimi için.

**URL:** https://k6.io/docs/

**Ne yapacaksın (10 dk):**

1. **"Test types"** sayfasına git
2. **"Load test"** vs **"Stress test"** vs **"Spike test"** ayrımını oku
3. Bizim flood scenario'larımız "stress test" kategorisinde — bunu cite et

**Spesifik link:** https://k6.io/docs/test-types/load-test-types/

**Tezde:**
> "Traffic generation employs k6 with stress-test executor patterns
> [k6 Documentation, https://k6.io/docs/test-types/], using
> ramping-arrival-rate executor to model sustained attack intensity
> with controlled per-second request rate."

**Status:** ✓ Verifiable, ekstra çaba gerekmiyor.

---

## A.5 — nginx Default Configuration

**Neye yarıyor:** Slowloris attack'in nginx'i nasıl etkilediğini açıklamak.
Server tarafı parametre context'i.

**URL:** https://nginx.org/en/docs/http/ngx_http_core_module.html

**Ne yapacaksın (15 dk):**

1. Linki aç (uzun bir doc, sabırlı ol)
2. Cmd+F: `client_header_timeout` → default değerini bul (60s genelde)
3. Cmd+F: `client_body_timeout` → default
4. Cmd+F: `keepalive_timeout` → default
5. Cmd+F: `worker_connections` → ngx_core module'da

**worker_connections için:** https://nginx.org/en/docs/ngx_core_module.html
   (Bu farklı bir module sayfası)

**Kaydet:**
```markdown
## nginx defaults
- client_header_timeout: 60s
- client_body_timeout: 60s
- keepalive_timeout: 75s
- worker_connections: 512 (default)
- Source: https://nginx.org/en/docs/...
- Status: ✓ Verified
```

**Tezde:**
> "nginx is configured with production-realistic default timeouts
> (client_header_timeout=60s, client_body_timeout=60s) per nginx core
> module documentation [nginx docs, http_core_module]. These defaults
> intentionally retained to allow slow attacks to develop their
> characteristic signatures rather than triggering early timeouts."

---

# KATEGORİ C — OWASP / RFC

## C.1 — OWASP Automated Threats to Web Applications

**Neye yarıyor:** **HTTP-layer bot threat taxonomy.** Mimicry, credential
stuffing, scraping için en güçlü HTTP-specific reference. **Kritik.**

**URL:** https://owasp.org/www-project-automated-threats-to-web-applications/

**Ne yapacaksın (45 dk — bu önemli, vakit ayır):**

1. Linki aç
2. **"OAT Threats"** veya **"Threat Events"** bölümüne git
3. Şu OAT kodlarına bak:
   - **OAT-008 Credential Stuffing** — S4 scenario için
   - **OAT-014 Vulnerability Scanning** — bot probing için
   - **OAT-019 Account Aggregation** — scraping için
   - **OAT-002 Token Cracking** — credential abuse alternatives
   - **OAT-005 Scalping** — mimicry context
   - **OAT-021 Denial of Inventory** — application-level DoS

4. Her OAT için PDF veya web sayfasını oku:
   - **Description**
   - **Threat agents**
   - **Affected industries**
   - **Mitigation**

5. PDF version (en güvenilir): genelde proje sayfasında "Handbook" veya
   "Document" başlığı altında
   - Tam başlık: **"OWASP Automated Threats to Web Applications - Handbook"**
   - Document ID genelde versiyonlu (v1.2 vs.)

**Kaydet:**

```markdown
## OWASP Automated Threats Handbook
- URL: https://owasp.org/www-project-automated-threats-to-web-applications/
- Document version: __ (handbook'tan kopyala)
- Verified: YYYY-MM-DD
- Relevant threats for thesis:
  - OAT-008 Credential Stuffing — page __
    Description summary: __ (1-2 cümle paraphrase)
  - OAT-014 Vulnerability Scanning — page __
  - OAT-019 Account Aggregation — page __
  - OAT-021 Denial of Inventory — page __
- Status: ✓ Verified
```

**Tezde nasıl cite et:**

```
Credential stuffing scenario operationalizes OWASP OAT-008
[OWASP Automated Threats Handbook, OAT-008 Credential Stuffing].
Bot scraping scenario aligns with OAT-019 Account Aggregation.
Volumetric flood scenario reflects OAT-021 Denial of Inventory at
application layer. The mimicry-flood scenario incorporates surface
feature techniques characterized in OAT-005 (UA rotation, IP
rotation via residential proxies) typical of mature attack tooling.
```

**Bu kaynak senin tezinde en güçlü HTTP-specific anchor olacak.**

---

## C.2 — RFC 7235 (HTTP Authentication) — opsiyonel

**Neye yarıyor:** HTTP auth flow'u standart referansı. Credential stuffing
context için.

**URL:** https://datatracker.ietf.org/doc/html/rfc7235

Sadece eğer methodology'de "HTTP authentication mechanisms" diye
detay veriyorsan cite et. Çoğu tezde gerekmez.

**Status:** Opsiyonel, atlanabilir.

---

# KATEGORİ B — INDUSTRY REPORTS

## B.1 — Akamai State of the Internet (SOTI) Security Report

**Neye yarıyor:** Credential stuffing rate ve industry-scale attack
istatistikleri. **S4 scenario** için kritik.

**URL ana sayfa:** https://www.akamai.com/resources/state-of-the-internet

**Ne yapacaksın (60 dk — uzun PDF):**

1. Ana sayfada en güncel "Defenders' Guide" veya "Bot Protection" raporunu
   bul (2024 olmalı, en kötü 2023)
2. PDF'i indir (genelde free, email isteyebilir)
3. PDF'te Cmd+F:
   - `credential stuffing` — bu konunun bölümünü bul
   - `attempts per second` — rate istatistikleri
   - `bot` — bot taxonomy
4. Spesifik istatistikleri kaydet:
   - Toplam credential stuffing attempts (yıllık)
   - Peak rate (ne kadar/saniye)
   - Per-source rate dağılımı
   - Industry distribution

**Hangi yıl raporu?** En güncel olan (2024 Q4 veya 2025 Q1 olabilir).
Tezde rapor yılını kesinlikle yaz: "Akamai SOTI Security 2024"

**Kaydet:**

```markdown
## Akamai SOTI Security Report
- URL: __ (specific PDF link)
- Year: __ (kesin)
- Page reference: page __
- Verified: YYYY-MM-DD
- Statistics extracted:
  - Annual credential stuffing volume: __
  - Peak per-target rate: __ attempts/sec
  - Per-source typical rate range: __
  - Industries most targeted: __
- Status: ✓ Verified
```

**Tezde:**
> "Credential stuffing scenario rate parameters reflect industry
> measurements: aggregate peak rates of approximately X attempts/second
> against monitored targets, per-source distributed rates of Y attempts/
> second documented in Akamai State of the Internet Security 2024
> Report [Akamai, 2024, page Z]."

---

## B.2 — Cloudflare DDoS Threat Report (Quarterly)

**Neye yarıyor:** L7 HTTP attack rate aggregate observations. **S2, S5**
için scaled-lab-analog argument.

**URL ana sayfa:** https://blog.cloudflare.com/?tag=ddos

Veya direkt: https://blog.cloudflare.com/ddos-threat-report-2024-q1/
(2024 Q1 spesifik)

En güncel: https://blog.cloudflare.com/ddos-threat-report-2025-q1/
(eğer mevcutsa, varsa kullan)

**Ne yapacaksın (45 dk):**

1. En güncel quarterly raporu aç
2. Cmd+F: `HTTP DDoS`, `application layer`, `L7`
3. Şu istatistikleri bul:
   - Q1 toplam HTTP DDoS attack sayısı
   - Peak rate (en büyük tek attack)
   - Average / median rate
   - Industry distribution
   - Source country distribution
4. Tablo veya grafiği screen capture al (tezdeki figür için)

**Kaydet:**

```markdown
## Cloudflare DDoS Threat Report
- URL: __
- Year/Quarter: __ (kesin)
- Verified: YYYY-MM-DD
- Statistics extracted:
  - HTTP DDoS attacks in quarter: __
  - Largest L7 attack rate: __ Mreq/s
  - Median L7 attack rate: __ req/s
  - Top targeted industries: __
- Status: ✓ Verified
```

**Tezde:**
> "Lab-scale flood parameters (peak 200 req/s aggregate) represent a
> scaled analog of mid-tier production HTTP DDoS attacks; Cloudflare
> DDoS Threat Report [year Q] documents L7 attacks ranging from X to
> Y req/s with median of Z req/s [Cloudflare, year Q, page W]."

---

## B.3 — Imperva Bad Bot Report — opsiyonel

**Neye yarıyor:** Bot mimicry industry observation, 3rd vendor data point.

**URL:** https://www.imperva.com/resources/resource-library/reports/

Bad Bot Report'u bul (yıllık çıkıyor).

**Ne yapacaksın (30 dk):**

1. En güncel Bad Bot Report PDF'i indir
2. Cmd+F: `evasion`, `User-Agent`, `mimic`, `sophisticated`
3. Bot sophistication levels taxonomy bul (genelde "Simple", "Moderate",
   "Advanced/Evasive" gibi)
4. UA rotation, IP rotation, residential proxy istatistiklerini al

**Status:** Opsiyonel ama mimicry argümanını güçlendirir. Day 9.0'da zaman
varsa ekle.

---

# KATEGORİ D — ACADEMIC PAPERS

> **En riskli kategori.** Hallucination geçmişi var (Mirai). Her birini
> dikkatli verify et veya **çıkar**.

## D.1 — Antonakakis et al. 2017 Mirai (PARTIALLY VERIFIED)

**Status:** Sen verify ettin, partially correct, düzeltmeler uygulandı.
Daha fazla iş yok.

**Citation:**
> Antonakakis, M., et al. (2017). "Understanding the Mirai Botnet."
> *USENIX Security*. p.1: 600K device peak, 7-month analysis.

**URL:** https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis

**Use case:** Sadece "Mirai botnet'in ölçeği ve varlığı" anchor'ı. Per-bot
HTTP rate iddiası YOK.

---

## D.2 — Wagner & Soto 2002 (VERIFIED)

**Status:** Sen verify ettin, "static" terim düzeltmesi gerekiyor (yapıldı).

**Citation:**
> Wagner, D., & Soto, P. (2002). "Mimicry Attacks on Host-based
> Intrusion Detection Systems." *CCS '02*, 255-264.

**URL:** https://dl.acm.org/doi/10.1145/586110.586145
(ACM DL — paywall, ama abstract free)
Veya yazarın sitesinde free preprint olabilir: https://people.eecs.berkeley.edu/~daw/

**Use case:** Mimicry attack kavramının orijinal akademik tanımı. Host IDS
context, HTTP'ye konceptual transfer.

---

## D.3 — Fogla et al. 2006 (VERIFIED)

**Status:** Sen verify ettin, "payload byte frequency" detayı not edildi.

**Citation:**
> Fogla, P., et al. (2006). "Polymorphic Blending Attacks." *USENIX
> Security '06*, 241-256.

**URL:** https://www.usenix.org/legacy/event/sec06/tech/full_papers/fogla/fogla.pdf
(USENIX legacy archive — free)

**Use case:** Statistical traffic blending kavramı. PAYL IDS context, HTTP
metadata'ya konceptual transfer.

---

## D.4 — Doran & Gokhale 2011 (UNVERIFIED — verify et)

**Citation:**
> Doran, D., & Gokhale, S. S. (2011). "Web Robot Detection Techniques:
> Overview and Limitations." *Data Mining and Knowledge Discovery*,
> 22(1-2), 183-210.

**URL:** https://link.springer.com/article/10.1007/s10618-010-0180-z
(Springer — paywall, üniversite proxy lazım)

**Free alternative search:** Yazar Derek Doran'ın akademik sayfasını ara,
preprint olabilir. ResearchGate: https://www.researchgate.net/profile/Derek-Doran

**Ne yapacaksın (30 dk):**

1. Paper'a eriş (üniversite proxy, ResearchGate, veya yazar sitesi)
2. Erişim varsa:
   - Paper'ı aç
   - Cmd+F: `request rate`, `bot rate`, `requests per second`
   - 0.5-5 req/s claim paper'da var mı doğrula
3. Erişim yoksa:
   - Bu citation'ı **çıkar**, alternatif kullan

**Alternatif kaynaklar (eğer Doran'a erişilemez):**
- **Bursztein et al.** Google reCAPTCHA papers — bot detection at scale
  https://ai.google/research/people/author35876/
- **PerimeterX/HUMAN whitepapers** — bot characterization
- **Imperva Bad Bot Report** — already in B.3

**Tezde fallback:**
> "Stealth scraping rate ranges (per-source <5 req/s) are consistent
> with industry bot characterization reports; specific academic survey
> [Doran & Gokhale 2011] could not be independently verified due to
> access restrictions, hence parameter justification anchors to
> verifiable Imperva Bad Bot Report [URL] and Cloudflare bot
> documentation [URL]."

---

## D.5 — Thomas et al. 2017 CCS (UNVERIFIED — verify et)

**Citation:**
> Thomas, K., et al. (2017). "Data Breaches, Phishing, or Malware?
> Understanding the Risks of Stolen Credentials." *CCS '17*, 1421-1434.

**URL:** https://dl.acm.org/doi/10.1145/3133956.3134067
(ACM DL — paywall, ama büyük ihtimalle Google'dan free preprint var)

**Free preprint search:** "Thomas Bursztein stolen credentials" Google'da
ara. Genelde Google Research yazarları paper'ı kendi sitesinde free
yayınlar. Kurt Thomas: https://research.google/people/KurtThomas/

**Ne yapacaksın (30 dk):**

1. Paper'a eriş
2. Cmd+F: `success rate`, `valid credentials`, `account takeover`
3. Stolen credential reuse rate (5%, 10% gibi) iddiasını bul
4. Tablo veya grafik bul, sayfa numarası kaydet

**Eğer iddia paper'da yok:**
- Bu citation'ı çıkar
- Alternatif: **Onaolapo 2016 IMC** (D.6) veya **Akamai SOTI** istatistiği

---

## D.6 — Onaolapo et al. 2016 IMC (UNVERIFIED — verify et)

**Citation:**
> Onaolapo, J., Mariconti, E., & Stringhini, G. (2016). "What Happens
> After You Are Pwnd: Understanding the Use of Leaked Webmail
> Credentials in the Wild." *IMC '16*, 65-79.

**URL:** https://dl.acm.org/doi/10.1145/2987443.2987475

**Free preprint:** UCL'de Stringhini'nin sitesinde olabilir
https://www0.cs.ucl.ac.uk/staff/g.stringhini/

**Ne yapacaksın (30 dk):**

1. Paper'a eriş
2. Cmd+F: `success rate`, `compromise rate`, `account access`
3. Leaked credential successful login oranı iddialarını bul
4. <5% reuse rate iddiası paper'da var mı doğrula

---

## D.7 — Cambiaso et al. 2013 (PAYWALLED — ÇIKAR)

**Status:** Erişim yok. **Citation chain'den çıkar.**

**Replacement:** slowhttptest tool documentation (A.1) tek başına yeterli.
Slow-DoS taxonomy zaten tool README'sinde.

**Action:** `attack_calibration_sources.md`'dan Cambiaso referanslarını sil.
Slowloris/slow-POST/slow-read taxonomy için sadece slowhttptest'e cite et.

---

# KARAR MATRİSİ

Doğrulama sonrası her kaynak için bu matrise bak:

| Sonuç | Aksiyon |
|---|---|
| ✓ Tam doğrulandı, claim paper'la uyuşuyor | Cite et + sayfa numarası ekle |
| ⚠️ Kısmen doğrulandı, bazı claim'ler hatalı | Hatalı claim'leri çıkar, doğru olanları cite et |
| ❌ Doğrulanamadı (paywall, paper yok, claim uyuşmuyor) | **Citation'ı çıkar**, alternatif tool/industry kaynak kullan |
| 🔄 Belirsiz | Default davranış: çıkar. Sonra zaman varsa eklersin |

**Genel kural:** Şüphede kalan citation'ı **çıkar**. Az ama doğru citation,
çok ama yanlış citation'dan iyidir.

---

# VERIFICATION LOG TEMPLATE

`docs/citation_verification_log.md` dosyasını oluştur (yoksa). Her kaynak
için şu format'ta kayıt:

```markdown
## [Kaynak adı]
- URL: [direkt link]
- Verified: YYYY-MM-DD
- Verifier: self
- Pages/sections checked: __
- Specific claims verified:
  - ✓ Claim X (page Y)
  - ✗ Claim Z — NOT in paper, removed from thesis
- Action: __ (kept / partially kept / removed)
- Replacement (if removed): __
```

**Bu log'u tezin appendix'ine koy.** Reviewer'a "verification protocol"
gösterir. Methodology rigor evidence.

---

# FINAL CITATION SHORTLIST (post-verification)

Doğrulama bittikten sonra tezde şu çekirdek citation chain kalmalı:

**Tool documentation (highest verification):**
- slowhttptest (Shekyan, GitHub)
- Cloudflare WAF rate limiting docs
- AWS WAF rate-based rules docs
- nginx core module docs
- k6 load testing docs

**Industry reports (verifiable PDFs):**
- Akamai SOTI Security [year]
- Cloudflare DDoS Threat Report [year Q]
- Imperva Bad Bot Report [year] (opsiyonel)

**Standards (highest verification):**
- OWASP Automated Threats Handbook (specifically OAT-008, OAT-014, OAT-019, OAT-021)

**Academic (sparingly, conceptual framework only):**
- Antonakakis et al. 2017 — Mirai (verified scope: botnet existence/scale)
- Wagner & Soto 2002 — mimicry concept (verified)
- Fogla et al. 2006 — statistical blending (verified)
- + Doran & Gokhale 2011 / Thomas 2017 / Onaolapo 2016 if you can verify

**Removed:**
- Cambiaso 2013 (paywalled, unverifiable)
- Stevanovic 2014 (low confidence on what we attributed)

---

# OZET — EN KISA YOL

Eğer sadece **2 saat** ayırabilirsen:

1. **slowhttptest GitHub** (15 dk) — slow attack params anchor
2. **OWASP OAT Handbook** (45 dk) — HTTP threat taxonomy
3. **Cloudflare DDoS Q4 2024 report** (45 dk) — L7 attack aggregate
4. **Cambiaso 2013'ü calibration doc'tan çıkar** (15 dk)

Bu dört iş, citation rigor'unun çekirdek %80'ini kapsar. Geri kalan
referansları (Doran, Thomas, Onaolapo) Day 26 yazımda doğrularsın veya
çıkarırsın.

Eğer **4 saat** ayırabilirsen: yukarıdakiler + Akamai SOTI + AWS WAF
docs + nginx defaults.

Eğer **8 saat** ayırabilirsen: hepsi + akademik 3 paper verification.
